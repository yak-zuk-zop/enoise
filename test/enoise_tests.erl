%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- fixtures -----------------------------------------------------------------

-spec noise_interactive_test_() -> _.
noise_interactive_test_() ->
    {setup,
        fun() -> test_utils:noise_test_vectors(fun test_utils:protocol_filter_interactive/1) end,
        fun(Tests) ->
            [{
                maps:get(protocol_name, T),
                fun() -> test_utils:init_hs_test(T, fun noise_interactive/5) end
            } || T <- Tests]
        end
    }.

-spec noise_dh25519_test_() -> _.
noise_dh25519_test_() ->
    {setup,
        fun() -> setup_dh(dh25519) end,
        fun({Tests, SrvKP, CliKP}) ->
            [{T, fun() -> noise_test_simple(T, SrvKP, CliKP) end} || T <- Tests]
        end
    }.

-spec noise_dh448_test_() -> _.
noise_dh448_test_() ->
    {setup,
        fun() -> setup_dh(dh448) end,
        fun({Tests, SrvKP, CliKP}) ->
            [{T, fun() -> noise_test_simple(T, SrvKP, CliKP) end} || T <- Tests]
        end
    }.

-spec noise_monitor_test_() -> _.
noise_monitor_test_() ->
    {setup,
        fun() -> setup_dh(dh25519) end,
        fun({Tests, SrvKP, CliKP}) ->
            [{T, fun() -> noise_test_monitor(T, SrvKP, CliKP) end} || T <- Tests]
        end
    }.

%%

-spec setup_dh(enoise_crypto:noise_dh()) -> {[Protocol], SrvKP, CliKP} when
    Protocol :: binary(),
    SrvKP :: enoise_keypair:keypair(),
    CliKP :: enoise_keypair:keypair().
setup_dh(DH) ->
    %% Generate a static key-pair for Client and Server
    SrvKeyPair = enoise_keypair:new(DH),
    CliKeyPair = enoise_keypair:new(DH),

    #{hs_pattern := Ps, hash := Hs, cipher := Cs} = enoise_protocol:supported(),
    Protocols = [enoise_protocol:to_name(P, DH, C, H) || P <- Ps, C <- Cs, H <- Hs],
    {Protocols, SrvKeyPair, CliKeyPair}.

%%-- tests --------------------------------------------------------------------

noise_interactive(Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    SecK = fun(undefined) -> undefined; (Sec) -> enoise_keypair:new(DH, Sec, undefined) end,
    PubK = fun(undefined) -> undefined; (Pub) -> enoise_keypair:new(DH, Pub) end,
    HSInit = fun(#{e := E, s := S, rs := RS, prologue := PL}, R) ->
        Opts = [
            {noise, Protocol},
            {s, SecK(S)},
            {e, SecK(E)},
            {rs, PubK(RS)},
            {prologue, PL}
        ],
        enoise:handshake(Opts, R)
    end,
    {ok, InitHS} = HSInit(Init, initiator),
    {ok, RespHS} = HSInit(Resp, responder),

    noise_interactive(Messages, InitHS, RespHS, HSHash).

noise_interactive([#{payload := PL0, ciphertext := CT0} | Msgs], SendHS, RecvHS, HSHash) ->
    PL = test_utils:hex2bin("0x" ++ binary_to_list(PL0)),
    CT = test_utils:hex2bin("0x" ++ binary_to_list(CT0)),
    case enoise_hs_state:next_message(SendHS) of
        out ->
            {ok, send, Message, SendHS1} = enoise:step_handshake(SendHS, {send, PL}),
            ?assertEqual(CT, Message),
            {ok, rcvd, PL1, RecvHS1} = enoise:step_handshake(RecvHS, {rcvd, Message}),
            ?assertEqual(PL, PL1),
            noise_interactive(Msgs, RecvHS1, SendHS1, HSHash);
        done ->
            {ok, done, #{rx := RX1, tx := TX1, hs_hash := HSHash1}} = enoise:step_handshake(SendHS, done),
            {ok, done, #{rx := RX2, tx := TX2, hs_hash := HSHash2}} = enoise:step_handshake(RecvHS, done),
            ?assertEqual(RX1, TX2),
            ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1),
            ?assertEqual(HSHash, HSHash2)
    end.

%%

noise_test_simple(Conf, SrvKP, CliKP) ->
    #{econn := EConn, echo_srv := EchoSrv} = noise_test_run(Conf, SrvKP, CliKP),
    enoise:close(EConn),
    echo_srv:stop(EchoSrv),
    ok.

noise_test_monitor(Conf, SrvKP, CliKP) ->
    #{econn := EConn, proxy := Proxy} = noise_test_run(Conf, SrvKP, CliKP),
    try
        proxy_exec(Proxy, fun() -> exit(normal) end)
    catch
        error:normal ->
            receive after 20 ->
                ?assertNot(enoise_connection:is_alive(EConn))
            end
    end.

%%-- internals ----------------------------------------------------------------

noise_test_run(Conf, SrvKP, CliKP) ->
    {Pid, MRef} = spawn_monitor_proxy(
        fun() -> noise_test_run_(Conf, SrvKP, CliKP) end
    ),
    receive
        {Pid, #{} = Info} ->
            Info#{proxy => Pid, proxy_mref => MRef}
    after 5000 ->
        erlang:error(timeout)
    end.

noise_test_run_(Conf, SrvKP, CliKP) ->
    Protocol = enoise_protocol:from_name(Conf),
    TcpOpts  = [{active, once}, binary],
    Port     = 4556,

    SrvOpts = [{echos, 2}, {cpub, CliKP}],
    EchoSrv = echo_srv:start(Port, Protocol, SrvKP, SrvOpts),

    {ok, TcpSock} = gen_tcp:connect("localhost", Port, TcpOpts, 100),

    Opts = [{noise, Protocol}, {s, CliKP} | [{rs, SrvKP} || echo_srv:need_rs(initiator, Conf)]],
    {ok, EConn, _} = enoise:connect(TcpSock, Opts),

    Msg1 = <<"Hello World!">>,
    ok = enoise:send(EConn, Msg1),
    ?assertEqual({ok, Msg1}, expected_reply(EConn)),

    ok = enoise:set_active(EConn, once),
    Msg2 = <<"Goodbye!">>,
    ok = enoise:send(EConn, Msg2),
    ?assertEqual({ok, Msg2}, expected_reply(EConn)),
    #{econn => EConn, tcp_sock => TcpSock, echo_srv => EchoSrv}.

-spec expected_reply(enoise_connection:t()) -> {ok, any()} | {error, timeout()}.
expected_reply(EConn) ->
    receive {reply, EConn, Msg} ->
        {ok, Msg}
    after 100 ->
        {error, timeout}
    end.

%%

spawn_monitor_proxy(F) ->
    Me = self(),
    spawn_monitor(fun() ->
        MRef = erlang:monitor(process, Me),
        Me ! {self(), F()},
        proxy_loop(Me, MRef)
    end).

proxy_loop(Parent, MRef) ->
    receive
        {exec, Parent, Ref, F} when is_function(F, 0) ->
            Parent ! {exec_result, Ref, F()},
            proxy_loop(Parent, MRef);
        {'DOWN', MRef, process, Parent, _} ->
            done
    end.

proxy_exec(P, F) when is_function(F, 0) ->
    R = erlang:monitor(process, P),
    P ! {exec, self(), R, F},
    receive
        {exec_result, R, Res} ->
            Res;
        {'DOWN', R, _, _, Reason} ->
            erlang:error(Reason)
    after 5000 ->
        erlang:error(timeout)
    end.

%% Talks to local echo-server (noise-c)
%% client_test() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),
%%     ClientPrivKey = <<64,168,119,119,151,194,94,141,86,245,144,220,78,53,243,231,
%%           168,216,66,199,49,148,202,117,98,40,61,109,170,37,133,122>>,
%%     ClientPubKey = <<115,39,86,77,44,85,192,176,202,11,4,6,194,144,127,123,
%%          34,67,62,180,190,232,251,5,216,168,192,190,134,65,13,64>>,
%%     ServerPubKey = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,
%%          163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     TcpOpts = [{active, once}, binary],
%%     {ok, TcpSock} = gen_tcp:connect("localhost", 7890, TcpOpts, 1000),
%%     gen_tcp:send(TcpSock, <<0,8,0,0,3>>),

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, ClientPrivKey, ClientPubKey)}
%%            , {rs, enoise_keypair:new(dh25519, ServerPubKey)}
%%            , {prologue, <<0,8,0,0,3>>}],

%%     {ok, EConn} = enoise:connect(TcpSock, Opts),
%%     Msg = <<"ok\n">>,
%%     ok = enoise:send(EConn, Msg),
%%     expected_reply(Msg),
%%     %% {ok, Msg} = enoise:recv(EConn, 3, 1000),
%%     enoise:close(EConn).


%% Expects a call-in from a local echo-client (noise-c)
%% server_test_() ->
%%     {timeout, 20, fun() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),

%%     ServerPrivKey = <<200,81,196,192,228,196,182,200,181,83,169,255,242,54,99,113,
%%          8,49,129,92,225,220,99,50,93,96,253,250,116,196,137,103>>,
%%     ServerPubKey = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,
%%          163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, ServerPrivKey, ServerPubKey)}
%%            , {prologue, <<0,8,0,0,3>>}],

%%     {ok, LSock} = gen_tcp:listen(7891, [{reuseaddr, true}, binary]),

%%     {ok, TcpSock} = gen_tcp:accept(LSock, 10000),

%%     receive {tcp, TcpSock, <<0,8,0,0,3>>} -> ok
%%     after 1000 -> error(timeout) end,

%%     {ok, EConn} = enoise:accept(TcpSock, Opts),

%%     {EConn1, Msg} = enoise:recv(EConn),
%%     EConn2 = enoise:send(EConn1, Msg),

%%     enoise:close(EConn2)
%%     end}.
