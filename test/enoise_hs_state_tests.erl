-module(enoise_hs_state_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- tests --------------------------------------------------------------------

-spec prologue_test_() -> _.
prologue_test_() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_ChaChaPoly_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},
    [
        {"empty", fun() -> prologue_test_int(Protocol, <<>>, InitialKeypairs) end},
        {"non empty", fun() -> prologue_test_int(Protocol, <<"Pr010gUe">>, InitialKeypairs) end},
        {"substituted", fun() ->
            AliceHS0 = enoise_hs_state:init(Protocol, initiator, <<"Pr010gUe">>, InitialKeypairs),
            %% Mallory replaced prologue
            BobHS0 = enoise_hs_state:init(Protocol, responder, <<"Pr010g">>, InitialKeypairs),

            {ok, AliceHS1, EncMsg1} = enoise_hs_state:write_message(AliceHS0, <<>>),
            {ok, BobHS1, <<>>} = enoise_hs_state:read_message(BobHS0, EncMsg1),

            {ok, BobHS2, EncMsg2} = enoise_hs_state:write_message(BobHS1, <<>>),
            {ok, _BobSplitState} = enoise_hs_state:finalize(BobHS2),

            ?assertMatch({error, _}, enoise_hs_state:read_message(AliceHS1, EncMsg2))
        end}
    ].

-spec unexpected_step_test_() -> _.
unexpected_step_test_() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_AESGCM_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},
    [
        {"finalize", fun() ->
            HS = enoise_hs_state:init(Protocol, initiator, <<>>, InitialKeypairs),
            ?assertError({expected, out}, enoise_hs_state:finalize(HS))
        end},
        {"read", fun() ->
            HS = enoise_hs_state:init(Protocol, initiator, <<>>, InitialKeypairs),
            ?assertEqual({error, {expected, out}}, enoise_hs_state:read_message(HS, <<>>))
        end},
        {"write", fun() ->
            HS = enoise_hs_state:init(Protocol, responder, <<>>, InitialKeypairs),
            ?assertEqual({error, {expected, in}}, enoise_hs_state:write_message(HS, <<>>))
        end}
    ].

%%-- internals ----------------------------------------------------------------

-spec prologue_test_int(enoise_protocol:protocol(), Prologue :: binary(), InitialKeypairs :: tuple()) -> _.
prologue_test_int(Protocol, Prologue, InitialKeypairs) ->
    AliceHS0 = enoise_hs_state:init(Protocol, initiator, Prologue, InitialKeypairs),
    BobHS0 = enoise_hs_state:init(Protocol, responder, Prologue, InitialKeypairs),

    ?assertEqual(out, enoise_hs_state:next_message(AliceHS0)),
    {ok, AliceHS1, EncMsg1} = enoise_hs_state:write_message(AliceHS0, <<>>),
    ?assertEqual(in, enoise_hs_state:next_message(BobHS0)),
    {ok, BobHS1, <<>>} = enoise_hs_state:read_message(BobHS0, EncMsg1),

    ?assertEqual(out, enoise_hs_state:next_message(BobHS1)),
    {ok, BobHS2, EncMsg2} = enoise_hs_state:write_message(BobHS1, <<>>),
    {ok, BobSplitState} = enoise_hs_state:finalize(BobHS2),

    ?assertEqual(in, enoise_hs_state:next_message(AliceHS1)),
    {ok, AliceHS2, <<>>} = enoise_hs_state:read_message(AliceHS1, EncMsg2),
    {ok, AliceSplitState} = enoise_hs_state:finalize(AliceHS2),

    #{rx := AliceRx, tx := AliceTx, hs_hash := AliceHSHash} = AliceSplitState,
    #{rx := BobRx, tx := BobTx, hs_hash := BobHSHash} = BobSplitState,
    ?assertEqual(AliceRx, BobTx),
    ?assertEqual(BobRx, AliceTx),
    ?assertEqual(AliceHSHash, BobHSHash).
