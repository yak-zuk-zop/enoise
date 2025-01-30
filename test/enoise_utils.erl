%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_utils).

-export([
    echo_srv_start/4,
    echo_srv_stop/1,
    need_rs/2
]).

-type server_opts() :: [
    {echos, pos_integer()} |
    {reply, pid()} |
    {cpub, any()} %% TODO: ???
].

-type protocol() :: enoise_protocol:protocol() | binary().

%%-- API ----------------------------------------------------------------------

-spec echo_srv_start(
    inet:port_number(),
    protocol(),
    enoise_keypair:keypair(),
    server_opts()
) -> pid().
echo_srv_start(Port, Protocol, SKP, Opts) ->
    Pid = spawn(fun() -> echo_srv(Port, Protocol, SKP, Opts) end),
    timer:sleep(10),
    Pid.

-spec echo_srv_stop(pid()) -> true.
echo_srv_stop(Pid) ->
    erlang:exit(Pid, kill).

-spec need_rs(enoise_hs_state:noise_role(), protocol()) -> boolean().
need_rs(Role, Name) when is_binary(Name) ->
    need_rs(Role, enoise_protocol:from_name(Name));
need_rs(Role, Protocol) ->
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    lists:member({in, [s]}, PreMsgs).

%%-- internals ----------------------------------------------------------------

echo_srv(Port, Protocol, SKP, SrvOpts) ->
    TcpOpts  = [{active, true}, binary, {reuseaddr, true}],

    {ok, LSock} = gen_tcp:listen(Port, TcpOpts),
    {ok, TcpSock} = gen_tcp:accept(LSock, 500),

    Opts = [{noise, Protocol}, {s, SKP} |
           [{rs, proplists:get_value(cpub, SrvOpts)} || need_rs(responder, Protocol)]],

    AcceptRes =
        try
            enoise:accept(TcpSock, Opts)
        catch _:R:Stacktrace ->
            gen_tcp:close(TcpSock),
            {error, {R, Stacktrace}}
        end,

    gen_tcp:close(LSock),

    case AcceptRes of
        {ok, EConn, _}   -> echo_srv_loop(EConn, SrvOpts);
        Err = {error, _} -> srv_reply(Err, SrvOpts)
    end.

echo_srv_loop(EConn, SrvOpts) ->
    Recv =
        case proplists:get_value(mode, SrvOpts, passive) of
            passive ->
                fun() ->
                    receive {reply, EConn, Data} -> Data
                    after 200 -> error(timeout) end
                end;
            active  ->
                error({not_supported, active})
                %fun() ->
                %    {ok, Msg} = enoise:recv(EConn, 0, 100),
                %    Msg
                %end
        end,

    Echos = proplists:get_value(echos, SrvOpts, 2),
    Res = try
        [ok = enoise:send(EConn, Recv()) || _ <- lists:seq(1, Echos)],
        ok
    catch _:R ->
        {error, R}
    end,

    ok = srv_reply(Res, SrvOpts),
    ok = enoise:close(EConn),

    Res.

-spec srv_reply(ok | {error, term()}, server_opts()) -> ok.
srv_reply(Reply, SrvOpts) ->
    case proplists:get_value(reply, SrvOpts, undefined) of
        undefined -> ok;
        Pid       -> Pid ! {self(), server_result, Reply}, ok
    end.
