-module(enoise_oneway_tests).

-include_lib("eunit/include/eunit.hrl").

-export([fixtures_init/0]).

-spec test() -> _.

%%-- setup --------------------------------------------------------------------

-spec oneway_handshake_test_() -> _.
oneway_handshake_test_() ->
    {setup,
        %fun fixtures_init/0,
        fun() -> test_utils:noise_test_vectors(fun test_utils:protocol_filter_oneway/1) end,
        fun(Tests) ->
            [{maps:get(protocol_name, T), {with, T, [fun oneway_handshake/1]}} || T <- Tests]
        end
    }.

%%-- tests --------------------------------------------------------------------

-spec oneway_handshake(Fixture :: map()) -> _.
oneway_handshake(Fixture) ->
    Protocol = enoise_protocol:from_name(maps:get(protocol_name, Fixture)),

    FixK = fun
        (undefined) -> undefined;
        (Bin) -> hex2bin(Bin)
    end,

    Init = #{ prologue => FixK(maps:get(init_prologue, Fixture, <<>>))
            , e        => FixK(maps:get(init_ephemeral, Fixture, undefined))
            , s        => FixK(maps:get(init_static, Fixture, undefined))
            , rs       => FixK(maps:get(init_remote_static, Fixture, undefined))},
    Resp = #{ prologue => FixK(maps:get(resp_prologue, Fixture, <<>>))
            , e        => FixK(maps:get(resp_ephemeral, Fixture, undefined))
            , s        => FixK(maps:get(resp_static, Fixture, undefined))
            , rs       => FixK(maps:get(resp_remote_static, Fixture, undefined))},
    Messages = maps:get(messages, Fixture),
    HandshakeHash = maps:get(handshake_hash, Fixture),

    test_handshake(Protocol, Init, Resp, Messages, FixK(HandshakeHash)).

%%-- internals --------------------------------------------------------------------

test_handshake(Protocol, Init, Resp, Messages, HSHash) ->
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
    {ok, InitHS} = HSInit(Init, responder),
    {ok, RespHS} = HSInit(Resp, initiator),

    test_handshake(Messages, InitHS, RespHS, HSHash).

test_handshake([#{payload := PL0, ciphertext := CT0} | Msgs], SendHS, RecvHS, HSHash) ->
    PL = hex2bin(PL0),
    CT = hex2bin(CT0),
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

hex2bin(Data) ->
    Hex = case Data of
        Bin when is_binary(Bin) ->
            binary_to_list(Bin);
        Str ->
            Str
    end,
    test_utils:hex2bin([$0, $x | Hex]).

%%-- fixtures -----------------------------------------------------------------

-spec fixtures_init() -> [map()].
fixtures_init() ->
    %_ = dbg:tracer(),
    %_ = dbg:p(all, c),
    %_ = dbg:tpl({'enoise', '_', '_'}, x),
    [
        #{
            protocol_name => "Noise_K_25519_AESGCM_BLAKE2b",
            init_prologue => "4a6f686e2047616c74",
            init_static => "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
            init_ephemeral => "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
            init_remote_static => "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62",
            resp_prologue => "4a6f686e2047616c74",
            resp_static => "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
            resp_remote_static => "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a",
            handshake_hash => "9c9a2396c05fbca86b66c555e9497b46c6a867c3b7732a10d6becbbf5396be88"
                "35c3760882f3351f2f5e94391e8d0163d4b0f2249facabecc0b58d1c09061fb0",
            messages => [
                #{
                    payload => "4c756477696720766f6e204d69736573",
                    ciphertext => "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
                        "5732b72e5473d5bc15e86a5caa0a1c78de9bef0254d0658a259aec25520d1eff"
                },
                #{
                    payload => "4d757272617920526f746862617264",
                    ciphertext => "e0d1d43cd8d5a15c2b15a07524d67fdc31557708ad71a0660bfc5d9a590b7d"
                },
                #{
                    payload => "462e20412e20486179656b",
                    ciphertext => "d44dcea01d1d25fb3036d151d9794412bc7b5469e272896ad01bf9"
                },
                #{
                    payload => "4361726c204d656e676572",
                    ciphertext => "5729d9253400806eefa496b6ab7d6b0b0e677954a1a7fee2424fd0"
                },
                #{
                    payload => "4a65616e2d426170746973746520536179",
                    ciphertext => "da4291f09c9c54a009dc5d9cbc3ff1534aadc92d3e79582bbcd56b47b6ac606178"
                },
                #{
                    payload => "457567656e2042f6686d20766f6e2042617765726b",
                    ciphertext => "926bb761946433c1902659867cac3f9fd6868597fe05bb6b4a6a550ed494e6618028db6b09"
                }
            ]
        }
    ].
