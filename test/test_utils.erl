-module(test_utils).
-include_lib("eunit/include/eunit.hrl").

%% utils
-export([
    hex2bin/1,
    maybe_new_keypair/2
]).

%% test data
-export([
    cipher_data/1,

    noise_test_vectors/1,
    protocol_filter_all/1,
    protocol_filter_interactive/1,
    protocol_filter_oneway/1,

    init_hs_test/2
]).

-spec test() -> _.

-type protocol() :: enoise_protocol:protocol().
-type keypair() :: enoise_keypair:keypair().
-type test_vector_fun() :: fun((protocol(), init_data(), init_data(), [message()], binary()) -> ok).
-type init_data() :: #{e := keypair(), s := keypair(), rs := keypair(), prologue := binary()}.
-type message() :: #{payload := binary(), ciphertext := binary()}.
-type protocol_filter() :: fun((protocol()) -> boolean()).

%% -- utils -------------------------------------------------------------------

-spec hex2bin(string() | binary()) -> binary().
hex2bin([$0, $x | Rest]) ->
    << <<(list_to_integer([C], 16)):4>> || C <- Rest >>;
hex2bin(<<$0, $x, Rest/binary>>) ->
    << <<(list_to_integer([C], 16)):4>> || <<C:8>> <= Rest >>.

%%

-spec protocol_filter_all(protocol()) -> boolean().
protocol_filter_all(_) ->
    true.

-spec protocol_filter_interactive(protocol()) -> boolean().
protocol_filter_interactive(Protocol) ->
    not protocol_filter_oneway(Protocol).

-spec protocol_filter_oneway(protocol()) -> boolean().
protocol_filter_oneway(Protocol) ->
    Pattern = enoise_protocol:pattern(Protocol),
    Pattern == n orelse Pattern == k orelse Pattern == x.

%%

-spec init_hs_test(map(), test_vector_fun()) -> ok.
init_hs_test(V = #{protocol_name := Name}, TestFun) ->
    Protocol = enoise_protocol:from_name(Name),

    FixK = fun
        (undefined) -> undefined;
        (Bin) -> hex2bin(<<$0, $x, Bin/binary>>)
    end,

    Init = #{ prologue => FixK(maps:get(init_prologue, V, <<>>))
            , e        => FixK(maps:get(init_ephemeral, V, undefined))
            , s        => FixK(maps:get(init_static, V, undefined))
            , rs       => FixK(maps:get(init_remote_static, V, undefined))},
    Resp = #{ prologue => FixK(maps:get(resp_prologue, V, <<>>))
            , e        => FixK(maps:get(resp_ephemeral, V, undefined))
            , s        => FixK(maps:get(resp_static, V, undefined))
            , rs       => FixK(maps:get(resp_remote_static, V, undefined))},
    Messages = maps:get(messages, V),
    HandshakeHash = maps:get(handshake_hash, V),

    TestFun(Protocol, Init, Resp, Messages, FixK(HandshakeHash)).

-spec maybe_new_keypair(DH, KnownKey) -> Result when
    DH :: enoise_crypto:noise_dh(),
    KnownKey :: {secret | public, binary() | undefined},
    Result :: enoise_keypair:keypair().
maybe_new_keypair(_, {_, undefined}) ->
    undefined;
maybe_new_keypair(DH, {secret, Sec}) ->
    enoise_keypair:new(DH, Sec, undefined);
maybe_new_keypair(DH, {public, Pub}) ->
    enoise_keypair:new(DH, undefined, Pub).

%% -- test data ---------------------------------------------------------------

-spec cipher_data(enoise_crypto:noise_cipher()) -> map().
cipher_data('ChaChaPoly') ->
    #{ key   => hex2bin("0x1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
     , nonce => 16#0807060504030201
     , ad    => hex2bin("0xf33388860000000000004e91")
     , pt    => hex2bin(
            "0x496e7465726e65742d4472616674732061726520647261667420646f63756d65"
            "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
            "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
            "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
            "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
            "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
            "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
            "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
            "726573732e2fe2809d")
     , ct    => hex2bin(
            "0x64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
            "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
            "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
            "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
            "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
            "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
            "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
            "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
            "a6ad5cb4022b02709b")
     , mac   => hex2bin("0xeead9d67890cbb22392336fea1851f38")
    };
cipher_data('AESGCM') ->
    #{ key   => <<0:256>>
     , nonce => 16#00
     , ad    => <<>>
     , pt    => <<>>
     , ct    => <<>>
     , mac   => hex2bin("0x530f8afbc74536b9a963b4f1c4cb738b")
    }.

% apply l8r
%cipher_data('AESGCM') ->
%    #{ key   => <<0:256>>
%     , nonce => 0,
%     , ad    => <<>>,
%     , pt    => <<0:128>>
%     , ct    => hex2bin("0xcea7403d4d606b6e074ec5d3baf39d18")
%     , mac   => hex2bin("0xd0d1c8a799996bf0265b98b5d48ab919")
%    }.

%%

%% Test vectors from
%% https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt
-spec noise_test_vectors(protocol_filter()) -> [map()].
noise_test_vectors(FilterFun) ->
    noise_test_filter(parse_test_vectors("test/test_vectors.txt"), FilterFun).

%% -- internals ---------------------------------------------------------------

parse_test_vectors(File) ->
    {ok, Bin} = file:read_file(File),
    #{vectors := Vectors} = jsx:decode(Bin, [{labels, atom}, return_maps]),
    Vectors.

%% Only test supported configurations
-spec noise_test_filter([map()], protocol_filter()) -> [map()].
noise_test_filter(Tests0, FilterFun) ->
    [T || T = #{protocol_name := Name} <- Tests0, is_supported(Name, FilterFun)].

-spec is_supported(binary(), protocol_filter()) -> boolean().
is_supported(Name, FilterFun) ->
    try
        FilterFun(enoise_protocol:from_name(Name))
    catch _:_ ->
        false
    end.
