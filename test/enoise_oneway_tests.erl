-module(enoise_oneway_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- fixtures -----------------------------------------------------------------

-spec oneway_handshake_test_() -> _.
oneway_handshake_test_() ->
    {setup,
        fun() -> test_utils:noise_test_vectors(fun test_utils:protocol_filter_oneway/1) end,
        fun(Tests) ->
            TestCaseFun = fun(T) -> test_utils:init_hs_test(T, fun test_handshake/5) end,
            [{maps:get(protocol_name, T), {with, T, [TestCaseFun]}} || T <- Tests]
        end
    }.

%%-- tests --------------------------------------------------------------------

test_handshake(Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    HSInit = fun(#{e := E, s := S, rs := RS, prologue := PL}, R) ->
        Opts = [
            {noise, Protocol},
            {role, R},
            {s, test_utils:maybe_new_keypair(DH, {secret, S})},
            {e, test_utils:maybe_new_keypair(DH, {secret, E})},
            {rs, test_utils:maybe_new_keypair(DH, {public, RS})},
            {prologue, PL}
        ],
        enoise:create_hstate(Opts)
    end,
    InitHS = HSInit(Init, responder),
    RespHS = HSInit(Resp, initiator),

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
