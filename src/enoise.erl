%% ----------------------------------------------------------------------------
%% @doc Module is an interface to the Noise protocol
%% [https://noiseprotocol.org]
%%
%% For convenience there is also an API to use Noise over TCP (i.e. `gen_tcp')
%% and after "upgrading" a `gen_tcp'-socket into a `enoise'-socket it has a
%% similar API as `gen_tcp'.
%%
%% @end -----------------------------------------------------------------------

-module(enoise).

%% API
-export([
    init/2,
    close/1,
    controlling_process/2,
    send/2,
    set_active/2,
    handshake/2,
    create_hstate/1,
    step_handshake/2,
    encrypt/2,
    decrypt/2
]).

-type noise_key() :: enoise_crypto:noise_key().
-type noise_keypair() :: enoise_keypair:keypair().

-type noise_options() :: [noise_option()].
%% A list of Noise options is a proplist, it *must* contain a value `noise'
%% that describes which Noise configuration to use. It is possible to give a
%% `prologue' to the protocol. And for the protocol to work, the correct
%% configuration of pre-defined keys (`s', `e', `rs', `re') should also be
%% provided.

-type noise_option() :: {noise, noise_protocol()} %% Required
                      | {role, enoise_hs_state:noise_role()} %% Required
                      | {e, noise_keypair()} %% Mandatary depending on `noise'
                      | {s, noise_keypair()}
                      | {re, noise_key()}
                      | {rs, noise_key()}
                      | {prologue, binary()} %% Optional
                      | {timeout, timeout()}.%% Optional

-type noise_protocol() :: enoise_protocol:protocol() | string() | binary().
%% Either an instantiated Noise protocol configuration or the name of a Noise
%% configuration (either as a string or a binary string).

-type com_state() :: {gen_tcp:socket(), socket_mode(), binary()}.
%% The communiction state of a handshake context

-type recv_msg_fun() :: fun((com_state(), timeout()) ->
                            result({ok, binary(), com_state()})).
%% Function that receive a message

-type send_msg_fun() :: fun((com_state(), binary()) -> ok).
%% Function that sends a message

-type noise_com_context() :: #{recv_msg := recv_msg_fun(),
                               send_msg := send_msg_fun(),
                               state    := com_state()}.
%% Noise handshake communication context. Consists of a
%% send, receive functions, and an internal state.

-type noise_split_state() :: enoise_hs_state:noise_split_state().
%% Return value from the final `split' operation. Provides a CipherState for
%% receiving and a CipherState transmission. Also includes the final handshake
%% hash for channel binding.

-type handshake_state() :: enoise_hs_state:state().
-type cipher_state()    :: enoise_cipher_state:state().

-type result(Expected) :: Expected | {error, term()}.

-type socket_mode() :: enoise_connection:active().

-type conn() :: enoise_connection:t().
%% An abstract Noise socket - holds a reference to a socket that has completed
%% a Noise handshake.

-export_type([
    noise_options/0
]).

%% -- API ---------------------------------------------------------------------

%% @doc Initialize a Noise connection and perform handshake
%%
%% Upgrades a gen_tcp, or equivalent, connected socket to a Noise socket.
%%
%% Note: The TCP socket has to be in mode `{active, true}' or `{active, once}',
%% passive receive is not supported.
%%
%% {@link noise_options()} is a proplist.
%% @end
-spec init(gen_tcp:socket(), noise_options()) ->
    result({ok, conn(), handshake_state()}).
init(TcpSock, Options) ->
    case check_socket(TcpSock) of
        ok ->
            case handshake(Options, build_tcp_com_context(TcpSock)) of
                {ok, #{rx := Rx, tx := Tx, final_state := FState}, #{state := ComState}} ->
                    case enoise_connection:start_link(ComState, Rx, Tx, self()) of
                        {ok, Conn} -> {ok, Conn, FState};
                        {error, _} = Err -> Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Perform a Noise handshake
%% {@link noise_options()} is a proplist.
%% @end
-spec handshake(noise_options(), noise_com_context()) ->
    result({ok, noise_split_state(), noise_com_context()}).
handshake(Options, ComCtx) ->
    HState = create_hstate(Options),
    Timeout = proplists:get_value(timeout, Options, infinity),
    do_handshake(HState, ComCtx, Timeout).

%% @doc Writes `Data' to `Socket'
-spec send(conn(), binary()) -> result(ok).
send(Conn, Data) ->
    enoise_connection:send(Conn, Data).

%% @doc Closes a Noise connection.
-spec close(conn()) -> result(ok).
close(Conn) ->
    enoise_connection:close(Conn).

%% @doc Assigns a new controlling process to the Noise socket. A controlling
%% process is the owner of an Noise socket, and receives all messages from the
%% socket.
%% @end
-spec controlling_process(conn(), pid()) -> result(ok).
controlling_process(Conn, NewPid) ->
    enoise_connection:controlling_process(Conn, NewPid).

%% @doc Set the active option `true | once'. Note that `N' and `false' are
%% not valid options for a Noise socket.
%% @end
-spec set_active(conn(), socket_mode()) -> result(ok).
set_active(Conn, Mode) ->
    enoise_connection:set_active(Conn, Mode).

%% @doc Create a handshake state
%% {@link noise_options()} is a proplist.
%% @end
-spec create_hstate(noise_options()) -> handshake_state().
create_hstate(Options) ->
    Prologue = proplists:get_value(prologue, Options, <<>>),
    Proto    = proplists:get_value(noise, Options),
    Role     = proplists:get_value(role, Options),

    Protocol = case Proto of
        X when is_binary(X); is_list(X) ->
            enoise_protocol:from_name(X);
        _ ->
            Proto
    end,

    S  = proplists:get_value(s, Options, undefined),
    E  = proplists:get_value(e, Options, undefined),
    RS = proplists:get_value(rs, Options, undefined),
    RE = proplists:get_value(re, Options, undefined),

    enoise_hs_state:init(Protocol, Role, Prologue, {S, E, RS, RE}).

%% @doc Perform a handshake step.
%% Data possible values:
%% <ul>
%%   <li>{send, Payload}</li>
%%   <li>{rcvd, EncryptedData}</li>
%%   <li>done</li>
%% </ul>
%% @end
-spec step_handshake(handshake_state(), {rcvd, binary()} | {send, binary()} | done) ->
          {ok, send, binary(), handshake_state()}
        | {ok, rcvd, binary(), handshake_state()}
        | {ok, done, noise_split_state()}
        | {error, term()}.
step_handshake(HState, Data) ->
    case {enoise_hs_state:next_message(HState), Data} of
        {in, {rcvd, Encrypted}} ->
            case enoise_hs_state:read_message(HState, Encrypted) of
                {ok, HState1, Msg} ->
                    {ok, rcvd, Msg, HState1};
                {error, _} = Err ->
                    Err
            end;
        {out, {send, Payload}} ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, Payload),
            {ok, send, Msg, HState1};
        {done, done} ->
            {ok, Res} = enoise_hs_state:finalize(HState),
            {ok, done, Res};
        {Next, _} ->
            {error, {invalid_step, expected, Next, got, Data}}
    end.

%% @doc Encrypt message for further transmitting.
%% Cipher state is received as a result of handshake.
%% @end
-spec encrypt(cipher_state(), binary()) -> {ok, cipher_state(), binary()}.
encrypt(CState, Msg) ->
    enoise_cipher_state:encrypt_with_ad(CState, <<>>, Msg).

%% @doc Decrypt received message.
%% Cipher state is received as a result of handshake.
%% @end
-spec decrypt(cipher_state(), binary()) -> result({ok, cipher_state(), binary()}).
decrypt(CState, Encrypted) ->
    enoise_cipher_state:decrypt_with_ad(CState, <<>>, Encrypted).

%%-- internals ----------------------------------------------------------------

-spec do_handshake(handshake_state(), noise_com_context(), timeout()) ->
    result({ok, noise_split_state(), noise_com_context()}).
do_handshake(HState, ComCtx, Timeout) ->
    case enoise_hs_state:next_message(HState) of
        in ->
            case hs_recv_msg(ComCtx, Timeout) of
                {ok, Data, ComCtx1} ->
                    case enoise_hs_state:read_message(HState, Data) of
                        {ok, HState1, _Msg} ->
                            do_handshake(HState1, ComCtx1, Timeout);
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        out ->
            {ok, HState1, Msg} = enoise_hs_state:write_message(HState, <<>>),
            case hs_send_msg(ComCtx, Msg) of
                {ok, ComCtx1} ->
                    do_handshake(HState1, ComCtx1, Timeout);
                {error, _} = Err ->
                    Err
            end;
        done ->
            {ok, Res} = enoise_hs_state:finalize(HState),
            {ok, Res, ComCtx}
    end.

-spec hs_recv_msg(noise_com_context(), timeout()) ->
    result({ok, binary(), noise_com_context()}).
hs_recv_msg(CS = #{recv_msg := Recv, state := S}, Timeout) ->
    case Recv(S, Timeout) of
        {ok, Data, S1}   -> {ok, Data, CS#{state := S1}};
        {error, _} = Err -> Err
    end.

-spec hs_send_msg(noise_com_context(), binary()) ->
    result({ok, noise_com_context()}).
hs_send_msg(CS = #{send_msg := Send, state := S}, Data) ->
    case Send(S, Data) of
        {ok, S1}         -> {ok, CS#{state := S1}};
        {error, _} = Err -> Err
    end.

%% -- gen_tcp specific functions ----------------------------------------------

-spec build_tcp_com_context(gen_tcp:socket()) -> noise_com_context().
build_tcp_com_context(TcpSock) ->
    {ok, [{active, Active}]} = inet:getopts(TcpSock, [active]),
    ok = gen_tcp:controlling_process(TcpSock, self()),
    #{
        recv_msg => fun gen_tcp_rcv_msg/2,
        send_msg => fun gen_tcp_snd_msg/2,
        state    => {TcpSock, Active, <<>>}
    }.

-spec check_socket(gen_tcp:socket()) -> result(ok).
check_socket(TcpSock) ->
    case inet:getopts(TcpSock, [mode, packet, active, header, packet_size]) of
        {ok, TcpOpts} ->
            Packet = proplists:get_value(packet, TcpOpts, 0),
            Active = proplists:get_value(active, TcpOpts, 0),
            Header = proplists:get_value(header, TcpOpts, 0),
            PSize  = proplists:get_value(packet_size, TcpOpts, undefined),
            Mode   = proplists:get_value(mode, TcpOpts, binary),
            case (Packet == 0 orelse Packet == raw)
                    andalso (Active == true orelse Active == once)
                    andalso Header == 0 andalso PSize == 0 andalso Mode == binary of
                true ->
                    ok;
                false ->
                    {error, {invalid_tcp_options, TcpOpts}}
            end;
        {error, _} = Err ->
            Err
    end.

-spec gen_tcp_snd_msg(com_state(), binary()) ->
    result({ok, com_state()}).
gen_tcp_snd_msg(S = {TcpSock, _, _}, Msg) ->
    Len = byte_size(Msg),
    case gen_tcp:send(TcpSock, <<Len:16, Msg/binary>>) of
        ok               -> {ok, S};
        {error, _} = Err -> Err
    end.

-spec gen_tcp_rcv_msg(com_state(), timeout()) ->
    result({ok, binary(), com_state()}).
gen_tcp_rcv_msg({TcpSock, Active, Buf}, Timeout) ->
    receive {tcp, TcpSock, Data} ->
        %% Immediately re-set {active, once}
        Active == once andalso inet:setopts(TcpSock, [{active, once}]),
        case <<Buf/binary, Data/binary>> of
            Buf1 = <<Len:16, Rest/binary>> when byte_size(Rest) < Len ->
                gen_tcp_rcv_msg({TcpSock, true, Buf1}, Timeout);
            <<Len:16, Rest/binary>> ->
                <<Data1:Len/binary, Buf1/binary>> = Rest,
                {ok, Data1, {TcpSock, true, Buf1}}
        end
    after Timeout ->
        {error, timeout}
    end.
