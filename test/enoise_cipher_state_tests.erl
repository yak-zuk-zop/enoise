-module(enoise_cipher_state_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

%%-- tests --------------------------------------------------------------------

-spec chachapoly_test() -> _.
chachapoly_test() ->
    cipher_test_int('ChaChaPoly').

-spec aes_gcm_test() -> _.
aes_gcm_test() ->
    cipher_test_int('AESGCM').

%%-- internals ----------------------------------------------------------------

cipher_test_int(Cipher) ->
    #{key := Key, nonce := Nonce, ad := AD, mac := MAC,
      pt := PlainText, ct := CipherText} = test_utils:cipher_data(Cipher),
    PTLen  = byte_size(PlainText),
    CTLen  = byte_size(CipherText),
    MACLen = byte_size(MAC),

    CS0 = enoise_cipher_state:init(Key, Cipher),
    CS1 = enoise_cipher_state:set_nonce(CS0, Nonce),

    {ok, _CS2, <<CipherText0:CTLen/binary, MAC0:MACLen/binary>>} =
        enoise_cipher_state:encrypt_with_ad(CS1, AD, PlainText),

    ?assertMatch(CipherText, CipherText0),
    ?assertMatch(MAC, MAC0),

    {ok, _CS3, <<PlainText0:PTLen/binary>>} =
        enoise_cipher_state:decrypt_with_ad(CS1, AD, <<CipherText/binary, MAC/binary>>),

    ?assertMatch(PlainText, PlainText0),

    % rekey test
    CS4 = enoise_cipher_state:rekey(CS1),
    {ok, _CS5, <<CipherText1:CTLen/binary, MAC1:MACLen/binary>>} =
        enoise_cipher_state:encrypt_with_ad(CS4, AD, PlainText),
    {ok, _CS6, <<PlainText1:PTLen/binary>>} =
        enoise_cipher_state:decrypt_with_ad(CS4, AD, <<CipherText1/binary, MAC1/binary>>),
    ?assertMatch(PlainText, PlainText1),
    ok.
