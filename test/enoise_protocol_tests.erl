-module(enoise_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- tests --------------------------------------------------------------------

-spec protocol_test_() -> _.
protocol_test_() ->
    [
        {"unknown_protocol", fun() ->
            Name = "UnknownNoise_OO_HAHA128",
            ?assertError({unsupported, {name, Name}}, enoise_protocol:from_name(Name))
        end} | [
        {Name, fun() ->
            NameConv = enoise_protocol:to_name(enoise_protocol:from_name(Name)),
            ?assertMatch(Name, binary_to_list(NameConv))
        end} || Name <- protocol_setup()
    ]].

%%-- fixtures -----------------------------------------------------------------

-spec protocol_setup() -> [ProtocolName :: string()].
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
