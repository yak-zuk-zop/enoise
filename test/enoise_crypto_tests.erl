-module(enoise_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec curve25519_test() -> _.
curve25519_test() ->
    DH = dh25519,
    KeyPair1 = enoise_keypair:new(DH),
    KeyPair2 = enoise_keypair:new(DH),

    SharedA = enoise_crypto:dh(KeyPair1, KeyPair2),
    SharedB = enoise_crypto:dh(KeyPair2, KeyPair1),
    ?assertMatch(SharedA, SharedB),

    #{a_pub := APub, a_priv := APriv,
      b_pub := BPub, b_priv := BPriv, shared := Shared} = test_utils:curve25519_data(),

    KeyPair3 = enoise_keypair:new(DH, APriv, APub),
    KeyPair4 = enoise_keypair:new(DH, BPriv, BPub),
    ?assertMatch(Shared, enoise_crypto:dh(KeyPair3, KeyPair4)),
    ?assertMatch(Shared, enoise_crypto:dh(KeyPair4, KeyPair3)),

    ok.

%%

-spec chachapoly_test() -> _.
chachapoly_test() ->
    Cipher = 'ChaChaPoly',
    #{key := Key, nonce := Nonce, ad := AD, mac := MAC,
       pt := PlainText, ct := CipherText} = test_utils:chacha_data(),
    PTLen  = byte_size(PlainText),
    CTLen  = byte_size(CipherText),
    MACLen = byte_size(MAC),

    %% Sanity check
    ?assert(PTLen == CTLen),

    <<CipherText0:CTLen/binary, MAC0:MACLen/binary>> =
        enoise_crypto:encrypt(Cipher, Key, Nonce, AD, PlainText),

    ?assertMatch(CipherText, CipherText0),
    ?assertMatch(MAC, MAC0),

    <<PlainText0:PTLen/binary>> =
        enoise_crypto:decrypt(Cipher, Key, Nonce, AD, <<CipherText/binary, MAC/binary>>),

    ?assertMatch(PlainText, PlainText0),

    Key1 = enoise_crypto:rekey(Cipher, Key),
    <<CipherText1:CTLen/binary, MAC1:MACLen/binary>> =
        enoise_crypto:encrypt(Cipher, Key1, Nonce, AD, PlainText),
    <<PlainText1:PTLen/binary>> =
        enoise_crypto:decrypt(Cipher, Key1, Nonce, AD, <<CipherText1/binary, MAC1/binary>>),
    ?assertMatch(PlainText, PlainText1),
    ok.

%%

-spec blake2b_test() -> _.
blake2b_test() ->
    hash_test_int(blake2b).

-spec blake2s_test() -> _.
blake2s_test() ->
    hash_test_int(blake2s).

-spec blake2b_hmac_test() -> _.
blake2b_hmac_test() ->
    hmac_test_int(blake2b).

-spec blake2b_hkdf_test() -> _.
blake2b_hkdf_test() ->
    hkdf_test_int(blake2b).

%%-- internals ----------------------------------------------------------------

hash_test_int(Hash) ->
    Test = fun(#{input := In, output := Out}) ->
        ?assertMatch(Out, enoise_crypto:hash(Hash, In))
    end,
    lists:foreach(Test, test_utils:hash_data(Hash)).

hmac_test_int(Hash) ->
    Test = fun(#{key := Key, data := Data, hmac := HMAC}) ->
        ?assertMatch(HMAC, enoise_crypto:hmac(Hash, Key, Data))
    end,
    lists:foreach(Test, test_utils:hmac_data(Hash)).

hkdf_test_int(Hash) ->
    Test = fun(#{key := Key, data := Data, out1 := Out1, out2 := Out2}) ->
        ?assertMatch([Out1, Out2, _], enoise_crypto:hkdf(Hash, Key, Data))
    end,
    lists:foreach(Test, test_utils:hkdf_data(Hash)).
