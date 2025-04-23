-module(enoise_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-type protocol_name() :: string().

%%-- fixtures -----------------------------------------------------------------

-spec protocol_test_() -> _.
protocol_test_() ->
    {setup,
        fun protocol_setup/0,
        fun (Tests) ->
            TestCases = [fun protocol_test/1],
            [{T, {with, T, TestCases}} || T <- Tests]
        end
    }.

-spec protocol_setup() -> [protocol_name()].
protocol_setup() ->
    [
        %% oneway
        "Noise_N_25519_ChaChaPoly_SHA512",
        %% basic
        "Noise_XK_25519_ChaChaPoly_SHA512",
        %% deferred
        "Noise_X1K_448_ChaChaPoly_SHA512",
        "Noise_XK1_448_AESGCM_SHA256",
        "Noise_K1K1_448_AESGCM_SHA512",
        %% psk
        "Noise_NNpsk0_25519_AESGCM_BLAKE2b"
    ].

%%-- tests --------------------------------------------------------------------

-spec protocol_test(protocol_name()) -> _.
protocol_test(Name) ->
    NameConv = enoise_protocol:to_name(enoise_protocol:from_name(Name)),
    ?assertMatch(Name, binary_to_list(NameConv)).
