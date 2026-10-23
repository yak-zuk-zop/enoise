-module(enoise_cipher_state_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-import(enoise_cipher_state, [
    encrypt_with_ad/3,
    decrypt_with_ad/3
]).

-import(test_utils, [
    cipher_data/1
]).

-type cipher() :: enoise_crypto:noise_cipher().
-type test_data() :: test_utils:cipher_data().
-type cipher_state() :: enoise_cipher_state:state().

%%-- tests --------------------------------------------------------------------

-spec cipher_test_() -> _.
cipher_test_() ->
    Ciphers = maps:get(cipher, enoise_protocol:supported()),
    Inits = lists:flatten([
        [{init_cipher_state(C, Data), Data} || Data <- cipher_data(C)] || C <- Ciphers
    ]),
    [
        {"encrypt/decrypt", [
            fun() -> enc_dec_test_int(CS, Data) end
                || {CS, Data} <- Inits
        ]},
        {"rekey", [
            fun() -> rekey_test_int(CS, Data) end
                || {CS, Data} <- Inits
        ]}
    ].

%%-- internals ----------------------------------------------------------------

-spec init_cipher_state(cipher(), test_data()) -> cipher_state().
init_cipher_state(Cipher, #{key := Key, nonce := Nonce}) ->
    CS = enoise_cipher_state:init(Key, Cipher),
    enoise_cipher_state:set_nonce(CS, Nonce).

-spec enc_dec_test_int(cipher_state(), test_data()) -> _.
enc_dec_test_int(CS, #{ad := AD, mac := MAC, pt := PlainText, ct := CipherText}) ->
    CTLen = byte_size(CipherText),
    CipherTextAndMAC = <<CipherText/binary, MAC/binary>>,

    {ok, _CS1, Encrypted} = encrypt_with_ad(CS, AD, PlainText),
    {ok, _CS2, Decrypted} = decrypt_with_ad(CS, AD, CipherTextAndMAC),

    <<CipherText1:CTLen/binary, MAC0/binary>> = Encrypted,
    ?assertMatch(MAC, MAC0),
    ?assertMatch(CipherText, CipherText1),
    ?assertMatch(PlainText, Decrypted).

-spec rekey_test_int(cipher_state(), test_data()) -> _.
rekey_test_int(CS0, #{ad := AD, pt := PlainText}) ->
    CS = enoise_cipher_state:rekey(CS0),

    {ok, _CS1, Encrypted} = encrypt_with_ad(CS, AD, PlainText),
    {ok, _CS2, Decrypted} = decrypt_with_ad(CS, AD, Encrypted),

    ?assertMatch(PlainText, Decrypted).
