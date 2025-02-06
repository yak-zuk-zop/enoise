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
    Proto = enoise_protocol:to_name(xk, DH, 'ChaChaPoly', blake2b),
    SrvKP = enoise_keypair:new(DH),
    CliKP = enoise_keypair:new(DH),

    Proxy = proxy_srv:start(),

    TestFun = fun() -> noise_test_run(Proto, SrvKP, CliKP) end,
    {ok, #{econn := EConn}} = proxy_srv:exec(Proxy, TestFun),

    {error, {'DOWN', normal}} = proxy_srv:exec(Proxy, fun() -> exit(normal) end),

    timer:sleep(20),

    ?assertNot(enoise_connection:is_alive(EConn)).

-spec bad_handshake_test() -> _.
bad_handshake_test() ->
    DH     = dh25519,
    SrvKP  = enoise_keypair:new(DH),
    Proto  = enoise_protocol:to_name(xk, DH, 'ChaChaPoly', blake2b),
    Opts   = [{echos, 1}, {recipient, self()}],
    Port   = 4567,
    SrvPid = echo_srv:start(Port, Proto, SrvKP, Opts),

    %% start client
    {ok, Sock} = gen_tcp:connect("localhost", Port, [binary], 100),
    ok = gen_tcp:send(Sock, <<0:256/unit:8>>),
    {ok, SrvRes} = echo_srv:wait_server_result(SrvPid),

    gen_tcp:close(Sock),

    ?assertMatch({error, {bad_data, _}}, SrvRes).

%%

noise_interactive(Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    HSInit = fun(#{e := E, s := S, rs := RS, prologue := PL}, R) ->
        Opts = [
            {noise, Protocol},
            {s, test_utils:maybe_new_keypare(DH, {secret, S})},
            {e, test_utils:maybe_new_keypare(DH, {secret, E})},
            {rs, test_utils:maybe_new_keypare(DH, {public, RS})},
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

noise_test_simple(Proto, SrvKP, CliKP) ->
    #{econn := EConn, echo_srv := EchoSrv} = noise_test_run(Proto, SrvKP, CliKP),
    enoise:close(EConn),
    echo_srv:stop(EchoSrv),
    ok.

%%-- internals ----------------------------------------------------------------

-spec noise_test_run(binary(), enoise_keypair:keypair(), enoise_keypair:keypair()) -> Result when
    Result :: #{econn := enoise_connection:t(), echo_srv := pid()}.
noise_test_run(Proto, SrvKP, CliKP) ->
    Protocol = enoise_protocol:from_name(Proto),
    TcpOpts  = [{active, true}, binary],
    Port     = 4556,

    SrvOpts = [{echos, 2}, {cpub, CliKP}],
    EchoSrv = echo_srv:start(Port, Protocol, SrvKP, SrvOpts),

    {ok, TcpSock} = gen_tcp:connect("localhost", Port, TcpOpts, 100),

    Opts = [{noise, Protocol}, {s, CliKP} | [{rs, SrvKP} || echo_srv:need_rs(initiator, Protocol)]],
    {ok, EConn, _} = enoise:connect(TcpSock, Opts),

    Msg1 = <<"Hello World!">>,
    ok = enoise:send(EConn, Msg1),
    ?assertEqual({ok, Msg1}, echo_srv:expected_reply(EConn)),

    Msg2 = <<"Goodbye!">>,
    ok = enoise:send(EConn, Msg2),
    ?assertEqual({ok, Msg2}, echo_srv:expected_reply(EConn)),
    #{econn => EConn, echo_srv => EchoSrv}.

%% Talks to local echo-server (noise-c)
%% client_test() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),
%%     CliPrivKey = <<64,168,119,119,151,194,94,141,86,245,144,220,78,53,243,231,
%%           168,216,66,199,49,148,202,117,98,40,61,109,170,37,133,122>>,
%%     CliPupKey = <<115,39,86,77,44,85,192,176,202,11,4,6,194,144,127,123,
%%          34,67,62,180,190,232,251,5,216,168,192,190,134,65,13,64>>,
%%     SrvPubKey = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,
%%          163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     TcpOpts = [{active, once}, binary],
%%     {ok, TcpSock} = gen_tcp:connect("localhost", 7890, TcpOpts, 1000),
%%     gen_tcp:send(TcpSock, <<0,8,0,0,3>>),

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, CliPrivKey, CliPupKey)}
%%            , {rs, enoise_keypair:new(dh25519, SrvPubKey)}
%%            , {prologue, <<0,8,0,0,3>>}],

%%     {ok, EConn} = enoise:connect(TcpSock, Opts),
%%     Msg = <<"ok\n">>,
%%     ok = enoise:send(EConn, Msg),
%%     {ok, Msg} = echo_srv:expected_reply(EConn),
%%     %% {ok, Msg} = enoise:recv(EConn, 3, 1000),
%%     enoise:close(EConn).


%% Expects a call-in from a local echo-client (noise-c)
%% server_test_() ->
%%     {timeout, 20, fun() ->
%%     TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),

%%     SrvPrivKey = <<200,81,196,192,228,196,182,200,181,83,169,255,242,54,99,113,
%%          8,49,129,92,225,220,99,50,93,96,253,250,116,196,137,103>>,
%%     SrvPubKey = <<112,91,141,253,183,66,217,102,211,40,13,249,238,51,77,114,
%%          163,159,32,1,162,219,76,106,89,164,34,71,149,2,103,59>>,

%%     Opts = [ {noise, TestProtocol}
%%            , {s, enoise_keypair:new(dh25519, SrvPrivKey, SrvPubKey)}
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
