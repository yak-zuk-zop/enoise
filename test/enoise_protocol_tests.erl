%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

-define(NAME, "Noise_XK_25519_ChaChaPoly_SHA512").

-spec test() -> _.

-spec name_test() -> _.
name_test() ->
    ?assertMatch(<<?NAME>>, enoise_protocol:to_name(enoise_protocol:from_name(?NAME))).
