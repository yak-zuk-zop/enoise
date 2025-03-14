-module(echo_srv).

-export([
    start/4,
    stop/1,
    build_enoise_options/4,
    wait_server_result/1,
    expected_reply/1
]).

-type keypair() :: enoise_keypair:keypair().
-type role() :: enoise_hs_state:noise_role().
-type server_opts() :: [
    {echos, pos_integer()} |
    {recipient, pid()} |
    {mode,  active | passive} |
    {cpub, enoise_keypair:keypair()}
].

-type protocol() :: enoise_protocol:protocol() | binary().

%%-- API ----------------------------------------------------------------------

-spec start(inet:port_number(), protocol(), keypair(), server_opts()) -> pid().
start(Port, Protocol, SrvKP, Opts) ->
    spawn(fun() -> echo_srv(Port, Protocol, SrvKP, Opts) end).

-spec stop(pid()) -> true.
stop(Pid) ->
    erlang:exit(Pid, kill).

-spec build_enoise_options(protocol(), role(), keypair(), keypair()) -> enoise:noise_options().
build_enoise_options(Protocol, Role, KP, RemotePubKey) ->
    [{noise, Protocol}, {role, Role}, {s, KP} | [{rs, RemotePubKey} || need_rs(Role, Protocol)]].

-spec wait_server_result(pid()) -> {ok, any()} | {error, timeout}.
wait_server_result(SrvPid) ->
    receive {server_result, SrvPid, Res} ->
        {ok, Res}
    after 500 ->
        {error, timeout}
    end.

-spec expected_reply(enoise_connection:t()) -> {ok, binary()} | {error, timeout}.
expected_reply(EConn) ->
    receive {reply, EConn, Msg} ->
        {ok, Msg}
    after 100 ->
        {error, timeout}
    end.

%%-- internals ----------------------------------------------------------------

echo_srv(Port, Protocol, SrvKP, SrvOpts) ->
    TcpOpts  = [{active, true}, binary, {reuseaddr, true}],

    {ok, LSock} = gen_tcp:listen(Port, TcpOpts),
    {ok, TcpSock} = gen_tcp:accept(LSock, 500),

    CliPubKey = proplists:get_value(cpub, SrvOpts),
    Opts = build_enoise_options(Protocol, responder, SrvKP, CliPubKey),

    Res = case enoise:init(TcpSock, Opts) of
        {ok, EConn, _}   ->
            Res0 = echo_srv_loop(EConn, SrvOpts),
            ok = enoise:close(EConn),
            Res0;
        {error, _} = Err ->
            Err
    end,

    ok = maybe_srv_reply(Res, SrvOpts),

    gen_tcp:close(TcpSock),
    gen_tcp:close(LSock).

-spec echo_srv_loop(enoise_connection:t(), server_opts()) -> ok | {error, term()}.
echo_srv_loop(EConn, SrvOpts) ->
    Echos = proplists:get_value(echos, SrvOpts, 2),
    try
        RecvFun = build_recv_fun(SrvOpts),
        [ok = enoise:send(EConn, RecvFun(EConn)) || _ <- lists:seq(1, Echos)],
        ok
    catch _:R ->
        {error, R}
    end.

-spec maybe_srv_reply(ok | {error, term()}, server_opts()) -> ok.
maybe_srv_reply(Reply, SrvOpts) ->
    case proplists:get_value(recipient, SrvOpts, undefined) of
        undefined -> ok;
        Pid       -> Pid ! {server_result, self(), Reply}, ok
    end.

-spec build_recv_fun(server_opts()) -> fun((enoise_connection:t()) -> binary()).
build_recv_fun(SrvOpts) ->
    case proplists:get_value(mode, SrvOpts, passive) of
        passive ->
            fun(EConn) ->
                {ok, Data} = expected_reply(EConn),
                Data
            end;
        active  ->
            error({not_supported, active})
            %fun(EConn) ->
            %    {ok, Data} = enoise:recv(EConn, 0, 200),
            %    Data
            %end
    end.

-spec need_rs(role(), protocol()) -> boolean().
need_rs(Role, Name) when is_binary(Name) ->
    need_rs(Role, enoise_protocol:from_name(Name));
need_rs(Role, Protocol) ->
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    lists:member({in, [s]}, PreMsgs).
