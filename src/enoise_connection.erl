%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module implementing a gen_server for holding a handshaked
%%% Noise connection over gen_tcp.
%%%
%%% Some care is needed since the underlying transmission is broken up
%%% into Noise packets, so we need some buffering.
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_connection).

%% API
-export([
    start_link/5,
    controlling_process/2,
    close/1,
    send/2,
    set_active/2
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-export_type([
    t/0,
    active/0
]).

-record(enoise, {
    pid :: pid()
}).

-record(state, {
    rx :: cipher_state(),
    tx :: cipher_state(),
    owner :: pid(),
    owner_ref :: reference() | undefined,
    tcp_sock :: gen_tcp:socket() | closed,
    active :: true | {once, boolean()},
    msgbuf = [] :: list(binary()),
    rawbuf = <<>> :: binary()
}).

-type t() :: #enoise{}.
-type active() :: true | once.
-type state() :: #state{}.
-type cipher_state() :: enoise_cipher_state:state().

%% -- API ---------------------------------------------------------------------

-spec start_link(gen_tcp:socket(), cipher_state(), cipher_state(), pid(), {active(), binary()}) ->
    {ok, t()} | {error, term()}.
start_link(TcpSock, Rx, Tx, Owner, {Active0, Buf}) ->
    Active = case Active0 of
        true -> true;
        once -> {once, false}
    end,
    State = #state{
        rx = Rx, tx = Tx,
        owner = Owner,
        tcp_sock = TcpSock,
        active = Active
    },

    case gen_server:start_link(?MODULE, State, []) of
        {ok, Pid} ->
            Conn = #enoise{pid = Pid},
            case gen_tcp:controlling_process(TcpSock, Pid) of
                ok ->
                    %% Changing controlling process require a bit of
                    %% fiddling with already received and delivered content...
                    Buf /= <<>> andalso (Pid ! {tcp, TcpSock, Buf}),
                    flush_tcp(Pid, TcpSock),
                    {ok, Conn};
                {error, _} = Err ->
                    close(Conn),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-spec send(t(), Data :: binary()) -> ok | {error, term()}.
send(#enoise{pid = Pid}, Data) ->
    gen_server:call(Pid, {send, Data}).

-spec set_active(t(), active()) -> ok | {error, term()}.
set_active(#enoise{pid = Pid}, Active) ->
    gen_server:call(Pid, {active, self(), Active}).

-spec close(t()) -> ok.
close(#enoise{pid = Pid}) ->
    gen_server:call(Pid, close).

-spec controlling_process(t(), NewPid :: pid()) -> ok | {error, term()}.
controlling_process(#enoise{pid = Pid}, NewPid) ->
    gen_server:call(Pid, {controlling_process, self(), NewPid}, 100).

%% -- gen_server callbacks ----------------------------------------------------

-spec init(state()) -> {ok, state()}.
init(#state{owner = Owner} = S) ->
    {ok, S#state{
        owner_ref = erlang:monitor(process, Owner)
    }}.

-spec handle_call(any(), gen_server:from(), state()) ->
    {reply, any(), state()} | {stop, normal, any(), state()}.
handle_call(close, _From, S) ->
    {stop, normal, ok, S};
handle_call(_Call, _From, S = #state{tcp_sock = closed}) ->
    {reply, {error, closed}, S};
handle_call({send, Data}, _From, S) ->
    {Res, S1} = handle_send(S, Data),
    {reply, Res, S1};
handle_call({controlling_process, OldPid, NewPid}, _From, S) ->
    {Res, S1} = handle_control_change(S, OldPid, NewPid),
    {reply, Res, S1};
handle_call({active, Pid, NewActive}, _From, S) ->
    {Res, S1} = handle_active(S, Pid, NewActive),
    {reply, Res, S1}.

-spec handle_cast(any(), state()) -> {noreply, state()}.
handle_cast(_Msg, S) ->
    {noreply, S}.

-spec handle_info(any(), state()) -> {noreply, state()} | {stop, any(), state()}.
handle_info({tcp, TS, Data}, S = #state{tcp_sock = TS, owner = O}) ->
    try
        {S1, Msgs} = handle_data(S, Data),
        S2 = handle_msgs(S1#state{msgbuf = S1#state.msgbuf ++ Msgs}),
        ok = set_active(S2),
        {noreply, S2}
    catch error:{enoise_error, _} ->
        %% We are not likely to recover, but leave the decision to upstream
        O ! {enoise_error, TS, decrypt_error},
        {noreply, S}
    end;
handle_info({tcp_closed, TS}, S = #state{tcp_sock = TS, owner = O}) ->
    O ! {tcp_closed, TS},
    {noreply, S#state{tcp_sock = closed}};
handle_info({'DOWN', Ref, process, _, normal}, S = #state{tcp_sock = TS, owner_ref = Ref}) ->
    close_tcp(TS),
    {stop, normal, S#state{tcp_sock = closed, owner_ref = undefined}};
handle_info({'DOWN', _, _, _, _}, S) ->
    %% Ignore non-normal monitor messages - we are linked.
    {noreply, S};
handle_info(_Msg, S) ->
    {noreply, S}.

-spec terminate(any(), state()) -> ok.
terminate(_Reason, #state{tcp_sock = TcpSock, owner_ref = ORef}) ->
    TcpSock /= closed andalso gen_tcp:close(TcpSock),
    ORef /= undefined andalso erlang:demonitor(ORef, [flush]),
    ok.

%% -- Local functions --------------------------------------------------------

-spec handle_control_change(state(), pid(), pid()) ->
    {ok | {error, not_owner}, state()}.
handle_control_change(S = #state{owner = Pid, owner_ref = OldRef}, Pid, NewPid) ->
    NewRef = erlang:monitor(process, NewPid),
    erlang:demonitor(OldRef, [flush]),
    {ok, S#state{owner = NewPid, owner_ref = NewRef}};
handle_control_change(S, _OldPid, _NewPid) ->
    {{error, not_owner}, S}.

-spec handle_active(state(), pid(), active()) -> {ok | {error, term()}, state()}.
handle_active(S = #state{owner = Pid, tcp_sock = TcpSock}, Pid, Active) ->
    case Active of
        true ->
            ok = inet:setopts(TcpSock, [{active, true}]),
            {ok, handle_msgs(S#state{active = true})};
        once ->
            S1 = handle_msgs(S#state{active = {once, false}}),
            {set_active(S1), S1}
    end;
handle_active(S, _Pid, _NewActive) ->
    {{error, not_owner}, S}.

-spec handle_data(state(), binary()) -> {state(), [binary()]} | no_return().
handle_data(S = #state{rawbuf = Buf}, Data) ->
    case <<Buf/binary, Data/binary>> of
        B = <<Len:16, Payload/binary>> when Len > byte_size(Payload) ->
            {S#state{rawbuf = B}, []}; %% Not a full Noise message - save it
        <<Len:16, Payload/binary>> ->
            <<MsgEnc:Len/binary, Rest/binary>> = Payload,
            Rx = S#state.rx,
            case enoise_cipher_state:decrypt_with_ad(Rx, <<>>, MsgEnc) of
                {ok, Rx1, Msg} ->
                    {S1, Msgs} = handle_data(S#state{rawbuf = Rest, rx = Rx1}, <<>>),
                    {S1, [Msg | Msgs]};
                {error, _} ->
                    error({enoise_error, decrypt_input_failed})
            end;
        EmptyOrSingleByte ->
            {S#state{rawbuf = EmptyOrSingleByte}, []}
    end.

-spec handle_msgs(state()) -> state().
handle_msgs(S = #state{msgbuf = []}) ->
    S;
handle_msgs(S = #state{msgbuf = Msgs, active = true, owner = Owner}) ->
    _ = [reply(Owner, Msg) || Msg <- Msgs],
    S#state{msgbuf = []};
handle_msgs(S = #state{active = {once, true}}) ->
    S;
handle_msgs(S = #state{msgbuf = [Msg | Msgs], active = {once, false}, owner = Owner}) ->
    ok = reply(Owner, Msg),
    S#state{msgbuf = Msgs, active = {once, true}}.

reply(Pid, Msg) ->
    Pid ! {reply, #enoise{pid = self()}, Msg},
    ok.

-spec handle_send(state(), binary()) -> {ok | {error, term()}, state()}.
handle_send(S = #state{tcp_sock = TcpSock, tx = Tx}, Data) ->
    {ok, Tx1, Msg} = enoise_cipher_state:encrypt_with_ad(Tx, <<>>, Data),
    case gen_tcp:send(TcpSock, <<(byte_size(Msg)):16, Msg/binary>>) of
        ok ->
            {ok, S#state{tx = Tx1}};
        {error, _} = Err ->
            {Err, S}
    end.

-spec set_active(state()) -> ok | {error, term()}.
set_active(#state{msgbuf = [], active = {once, _}, tcp_sock = TcpSock}) ->
    inet:setopts(TcpSock, [{active, once}]);
set_active(_) ->
    ok.

flush_tcp(Pid, TcpSock) ->
    receive {tcp, TcpSock, Data} ->
        Pid ! {tcp, TcpSock, Data},
        flush_tcp(Pid, TcpSock)
    after 1 ->
        ok
    end.

close_tcp(closed) ->
    ok;
close_tcp(Sock) ->
    gen_tcp:close(Sock).
