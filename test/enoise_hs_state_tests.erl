-module(enoise_hs_state_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- fixtures -----------------------------------------------------------------

-spec noise_hs_test_() -> _.
noise_hs_test_() ->
    {setup,
        fun() -> test_utils:noise_test_vectors(fun test_utils:protocol_filter_interactive/1) end,
        fun(Tests) ->
            [{
                maps:get(protocol_name, T),
                fun() -> test_utils:init_hs_test(T, fun noise_test/5) end
            } || T <- Tests]
        end
    }.

%%-- tests --------------------------------------------------------------------

noise_test(Protocol, Init, Resp, Messages, HSHash) ->
    DH = enoise_protocol:dh(Protocol),
    NewK = fun(Key) -> test_utils:maybe_new_keypare(DH, Key) end,
    HSInit = fun(#{e := E, s := S, rs := RS, prologue := PL}, R) ->
        Keys = {NewK({secret, S}), NewK({secret, E}), NewK({public, RS}), undefined},
        enoise_hs_state:init(Protocol, R, PL, Keys)
    end,
    InitHS = HSInit(Init, initiator),
    RespHS = HSInit(Resp, responder),

    noise_test(Messages, InitHS, RespHS, HSHash).

%%-- internals ----------------------------------------------------------------

noise_test([M = #{payload := PL0, ciphertext := CT0} | Msgs], SendHS, RecvHS, HSHash) ->
    case {enoise_hs_state:next_message(SendHS), enoise_hs_state:next_message(RecvHS)} of
        {out, in} ->
            PL = test_utils:hex2bin(<<$0, $x, PL0/binary>>),
            CT = test_utils:hex2bin(<<$0, $x, CT0/binary>>),

            {ok, SendHS1, Message} = enoise_hs_state:write_message(SendHS, PL),
            ?assertEqual(CT, Message),
            {ok, RecvHS1, PL1} = enoise_hs_state:read_message(RecvHS, Message),
            ?assertEqual(PL, PL1),
            noise_test(Msgs, RecvHS1, SendHS1, HSHash);
        {done, done} ->
            {ok, #{rx := RX1, tx := TX1, hs_hash := HSHash1}} = enoise_hs_state:finalize(SendHS),
            {ok, #{rx := RX2, tx := TX2, hs_hash := HSHash2}} = enoise_hs_state:finalize(RecvHS),
            ?assertEqual(RX1, TX2), ?assertEqual(RX2, TX1),
            ?assertEqual(HSHash, HSHash1), ?assertEqual(HSHash, HSHash2),
            message_test([M | Msgs], TX1, RX1);
        {Out, In} ->
            ?assertMatch({out, in}, {Out, In})
    end.

message_test([], _, _) -> ok;
message_test([#{payload := PL0, ciphertext := CT0} | Msgs], CA, CB) ->
    PL = test_utils:hex2bin(<<$0, $x, PL0/binary>>),
    CT = test_utils:hex2bin(<<$0, $x, CT0/binary>>),
    {ok, CA1, CT1} = enoise_cipher_state:encrypt_with_ad(CA, <<>>, PL),
    ?assertEqual(CT, CT1),
    {ok, CA2, PL1} = enoise_cipher_state:decrypt_with_ad(CA, <<>>, CT1),
    ?assertEqual(CA1, CA2),
    ?assertEqual(PL, PL1),
    message_test(Msgs, CB, CA1).
