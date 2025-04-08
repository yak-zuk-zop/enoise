-module(enoise_hs_state_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- tests --------------------------------------------------------------------

-spec empty_prologue_test() -> _.
empty_prologue_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_ChaChaPoly_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},

    AliceHS0 = enoise_hs_state:init(Protocol, initiator, <<>>, InitialKeypairs),
    BobHS0 = enoise_hs_state:init(Protocol, responder, <<>>, InitialKeypairs),

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

-spec prologue_test() -> _.
prologue_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_ChaChaPoly_SHA256">>),
    Prologue = <<"Pr010gUe">>,
    InitialKeypairs = {undefined, undefined, undefined, undefined},

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

-spec substituted_prologue_test() -> _.
substituted_prologue_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_AESGCM_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},

    AliceHS0 = enoise_hs_state:init(Protocol, initiator, <<"Pr010gUe">>, InitialKeypairs),
    %% Mallory replaced prologue
    BobHS0 = enoise_hs_state:init(Protocol, responder, <<"Pr010g">>, InitialKeypairs),

    {ok, AliceHS1, EncMsg1} = enoise_hs_state:write_message(AliceHS0, <<>>),
    {ok, BobHS1, <<>>} = enoise_hs_state:read_message(BobHS0, EncMsg1),

    {ok, BobHS2, EncMsg2} = enoise_hs_state:write_message(BobHS1, <<>>),
    {ok, _BobSplitState} = enoise_hs_state:finalize(BobHS2),

    ?assertMatch({error, _}, enoise_hs_state:read_message(AliceHS1, EncMsg2)).

-spec unexpected_finalize_step_test() -> _.
unexpected_finalize_step_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_AESGCM_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},

    HS = enoise_hs_state:init(Protocol, initiator, <<>>, InitialKeypairs),

    ?assertError({expected, out}, enoise_hs_state:finalize(HS)).

-spec unexpected_read_test() -> _.
unexpected_read_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_AESGCM_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},

    HS = enoise_hs_state:init(Protocol, initiator, <<>>, InitialKeypairs),

    ?assertEqual({error, {expected, out}}, enoise_hs_state:read_message(HS, <<>>)).

-spec unexpected_write_test() -> _.
unexpected_write_test() ->
    Protocol = enoise_protocol:from_name(<<"Noise_NN_25519_AESGCM_SHA256">>),
    InitialKeypairs = {undefined, undefined, undefined, undefined},

    HS = enoise_hs_state:init(Protocol, responder, <<>>, InitialKeypairs),

    ?assertEqual({error, {expected, in}}, enoise_hs_state:write_message(HS, <<>>)).
