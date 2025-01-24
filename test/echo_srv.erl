%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(echo_srv).

-export([
    start/4,
    stop/1,
    need_rs/2,
    wait_server_result/1
]).

-type server_opts() :: [
    {echos, pos_integer()} |
    {reply, pid()} |
    {mode,  active | passive} |
    {cpub, enoise_keypair:keypair()}
].

-type protocol() :: enoise_protocol:protocol() | binary().

%%-- API ----------------------------------------------------------------------

-spec start(inet:port_number(), protocol(), enoise_keypair:keypair(), server_opts()) -> pid().
start(Port, Protocol, SrvKP, Opts) ->
    spawn(fun() -> echo_srv(Port, Protocol, SrvKP, Opts) end).

-spec stop(pid()) -> true.
stop(Pid) ->
    erlang:exit(Pid, kill).

-spec need_rs(enoise_hs_state:noise_role(), protocol()) -> boolean().
need_rs(Role, Name) when is_binary(Name) ->
    need_rs(Role, enoise_protocol:from_name(Name));
need_rs(Role, Protocol) ->
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    lists:member({in, [s]}, PreMsgs).

-spec wait_server_result(pid()) -> {ok, any()} | {error, timeout}.
wait_server_result(SrvPid) ->
    receive {SrvPid, server_result, Res} ->
        {ok, Res}
    after 500 ->
        {error, timeout}
    end.

%%-- internals ----------------------------------------------------------------

echo_srv(Port, Protocol, SrvKP, SrvOpts) ->
    TcpOpts  = [{active, true}, binary, {reuseaddr, true}],

    {ok, LSock} = gen_tcp:listen(Port, TcpOpts),
    {ok, TcpSock} = gen_tcp:accept(LSock, 500),

    Opts = [{noise, Protocol}, {s, SrvKP} |
           [{rs, proplists:get_value(cpub, SrvOpts)} || need_rs(responder, Protocol)]],

    Res = case enoise:accept(TcpSock, Opts) of
        {ok, EConn, _}   ->
            Res0 = echo_srv_loop(EConn, SrvOpts),
            ok = enoise:close(EConn),
            Res0;
        {error, _} = Err ->
            Err
    end,

    ok = srv_reply(Res, SrvOpts),

    gen_tcp:close(TcpSock),
    gen_tcp:close(LSock).

-spec echo_srv_loop(enoise_connection:t(), server_opts()) -> ok | {error, term()}.
echo_srv_loop(EConn, SrvOpts) ->
    Echos = proplists:get_value(echos, SrvOpts, 2),
    try
        RecvFun = build_recv_fun(EConn, SrvOpts),
        [ok = enoise:send(EConn, RecvFun()) || _ <- lists:seq(1, Echos)],
        ok
    catch _:R ->
        {error, R}
    end.

-spec srv_reply(ok | {error, term()}, server_opts()) -> ok.
srv_reply(Reply, SrvOpts) ->
    case proplists:get_value(reply, SrvOpts, undefined) of
        undefined -> ok;
        Pid       -> Pid ! {self(), server_result, Reply}, ok
    end.

build_recv_fun(EConn, SrvOpts) ->
    case proplists:get_value(mode, SrvOpts, passive) of
        passive ->
            fun() ->
                receive {reply, EConn, Data} -> Data
                after 200 -> error(timeout) end
            end;
        active  ->
            error({not_supported, active})
            %fun() ->
            %    {ok, Data} = enoise:recv(EConn, 0, 200),
            %    Data
            %end
    end.
