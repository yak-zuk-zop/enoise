-module(enoise_handshake_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-dialyzer({nowarn_function, [
    noise_monitor_test/0
]}).

%%-- fixtures -----------------------------------------------------------------

-spec vectors_test_() -> _.
vectors_test_() ->
    {setup,
        fun() -> test_utils:load_test_vectors("test_vectors.txt") end,
        fun(Tests) ->
            TestCaseFun = fun(T) -> test_utils:init_hs_test(T, fun test_handshake/5) end,
            [{maps:get(protocol_name, T), {with, T, [TestCaseFun]}} || T <- Tests]
        end
    }.

-spec noise_dh25519_test_() -> _.
noise_dh25519_test_() ->
    setup_dh_test(dh25519).

-spec noise_dh448_test_() -> _.
noise_dh448_test_() ->
    setup_dh_test(dh448).

%%

setup_dh_test(DH) ->
    {setup,
        fun() -> setup_dh(DH) end,
        fun({Tests, SrvKP, CliKP}) ->
            [{T, fun() -> noise_test_simple(T, SrvKP, CliKP) end} || T <- Tests]
        end
    }.

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

-spec noise_monitor_test() -> _.
noise_monitor_test() ->
    DH    = dh25519,
    Name  = enoise_protocol:to_name(xk, DH, 'ChaChaPoly', blake2b),
    SrvKP = enoise_keypair:new(DH),
    CliKP = enoise_keypair:new(DH),
    Proto = enoise_protocol:from_name(Name),

    Port    = 4556,
    SrvOpts = [{echos, 3}, {cpub, CliKP}],
    EchoSrv = echo_srv:start(Port, Proto, SrvKP, SrvOpts),

    ClientFun = fun() ->
        {ok, TcpSock} = gen_tcp:connect("localhost", Port, [{active, true}, binary], 100),
        Opts = echo_srv:build_enoise_options(Proto, initiator, CliKP, SrvKP),
        {ok, EConn, _} = enoise:init(TcpSock, Opts),

        Msg1 = <<"Hello World!">>,
        ok = enoise:send(EConn, Msg1),
        ?assertEqual({ok, Msg1}, echo_srv:expected_reply(EConn)),

        {econn, EConn}
    end,

    Proxy = proxy_srv:start(),
    {ok, {econn, EConn}} = proxy_srv:exec(Proxy, ClientFun),
    {error, {'DOWN', normal}} = proxy_srv:exec(Proxy, fun() -> exit(normal) end),

    ?assertNot(enoise_connection:is_alive(EConn)),

    echo_srv:stop(EchoSrv),
    ok.

-spec bad_handshake_test() -> _.
bad_handshake_test() ->
    DH     = dh25519,
    SrvKP  = enoise_keypair:new(DH),
    Name   = enoise_protocol:to_name(xk, DH, 'ChaChaPoly', blake2b),
    Opts   = [{echos, 1}, {recipient, self()}],
    Port   = 4567,
    SrvPid = echo_srv:start(Port, Name, SrvKP, Opts),

    %% start client
    {ok, Sock} = gen_tcp:connect("localhost", Port, [binary], 100),
    ok = gen_tcp:send(Sock, <<0:256/unit:8>>),
    {ok, SrvRes} = echo_srv:wait_server_result(SrvPid),

    gen_tcp:close(Sock),

    ?assertMatch({error, {bad_data, _}}, SrvRes).

%%

test_handshake(Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    HSInit = fun(#{e := E, s := S, rs := RS, prologue := PL, psk := PSK}, R) ->
        Opts = [
            {noise, Protocol},
            {role, R},
            {s, test_utils:maybe_new_keypair(DH, {secret, S})},
            {e, test_utils:maybe_new_keypair(DH, {secret, E})},
            {rs, test_utils:maybe_new_keypair(DH, {public, RS})},
            {prologue, PL},
            {psk, PSK}
        ],
        enoise:create_hstate(Opts)
    end,
    InitHS = HSInit(Init, initiator),
    RespHS = HSInit(Resp, responder),

    test_handshake(Messages, InitHS, RespHS, HSHash).

test_handshake([#{payload := PL0, ciphertext := CT0} | Msgs], SendHS, RecvHS, HSHash) ->
    PL = test_utils:hex2bin(<<$0, $x, PL0/binary>>),
    CT = test_utils:hex2bin(<<$0, $x, CT0/binary>>),
    case enoise_hs_state:next_message(SendHS) of
        out ->
            {ok, send, Message, SendHS1} = enoise:step_handshake(SendHS, {send, PL}),
            ?assertEqual(CT, Message),
            {ok, rcvd, PL1, RecvHS1} = enoise:step_handshake(RecvHS, {rcvd, Message}),
            ?assertEqual(PL, PL1),
            test_handshake(Msgs, RecvHS1, SendHS1, HSHash);
        done ->
            {ok, done, SenderSplitState} = enoise:step_handshake(SendHS, done),
            {ok, done, RecipientSplitState} = enoise:step_handshake(RecvHS, done),

            #{rx := RX1, tx := TX1, hs_hash := HSHash1} = SenderSplitState,
            #{rx := RX2, tx := TX2, hs_hash := HSHash2} = RecipientSplitState,
            ?assertEqual(RX1, TX2),
            ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1),
            ?assertEqual(HSHash, HSHash2)
    end.

%%

-spec noise_test_simple(binary(), enoise_keypair:keypair(), enoise_keypair:keypair()) -> ok.
noise_test_simple(Name, SrvKP, CliKP) ->
    Msgs    = [<<"Hello World!">>, <<"Thank you all">>, <<"Goodbye!">>],
    Proto   = enoise_protocol:from_name(Name),
    TcpOpts = [{active, true}, binary],
    Port    = 4556,
    SrvOpts = [{echos, length(Msgs)}, {cpub, CliKP}],
    EchoSrv = echo_srv:start(Port, Proto, SrvKP, SrvOpts),

    {ok, TcpSock} = gen_tcp:connect("localhost", Port, TcpOpts, 100),

    Opts = echo_srv:build_enoise_options(Proto, initiator, CliKP, SrvKP),
    {ok, EConn, _} = enoise:init(TcpSock, Opts),

    TestFun = fun(Msg) ->
        ok = enoise:send(EConn, Msg),
        ?assertEqual({ok, Msg}, echo_srv:expected_reply(EConn))
    end,
    lists:foreach(TestFun, Msgs),

    enoise:close(EConn),
    echo_srv:stop(EchoSrv),
    ok.
