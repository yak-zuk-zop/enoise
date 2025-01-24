%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------
-module(enoise_bad_data_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec bad_data_hs1_test() -> _.
bad_data_hs1_test() ->
    DH     = dh25519,
    SrvKP  = enoise_keypair:new(DH),
    Proto  = enoise_protocol:to_name(xk, DH, 'ChaChaPoly', blake2b),
    Opts   = [{echos, 1}, {reply, self()}],
    Port   = 4567,
    SrvPid = echo_srv:start(Port, Proto, SrvKP, Opts),

    %% start client
    {ok, Sock} = gen_tcp:connect("localhost", Port, [binary], 100),
    ok = gen_tcp:send(Sock, <<0:256/unit:8>>),
    {ok, SrvRes} = echo_srv:wait_server_result(SrvPid),

    gen_tcp:close(Sock),

    ?assertMatch({error, {bad_data, _}}, SrvRes).
