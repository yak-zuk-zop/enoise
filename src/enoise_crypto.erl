%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module implementing crypto primitives needed by Noise protocol
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_crypto).

%% API
-export([
    decrypt/5,
    dh/3,
    dhlen/1,
    encrypt/5,
    hash/2,
    hashlen/1,
    hkdf/3,
    hmac/3,
    pad/3,
    rekey/2
]).

-export_type([
    noise_dh/0,
    noise_cipher/0,
    noise_hash/0,
    nonce/0
]).

-define(MAC_LEN, 16).
-define(MAX_NONCE, 16#FFFFFFFFFFFFFFFF).

-type noise_cipher() :: 'ChaChaPoly' | 'AESGCM'.
-type noise_dh()     :: dh25519 | dh448.
-type noise_hash()   :: sha256 | sha512 | blake2s | blake2b.
-type nonce()        :: non_neg_integer().
-type keypair()      :: enoise_keypair:keypair().

%%-- API ----------------------------------------------------------------------

%% @doc Perform a Diffie-Hellman calculation with the secret key from `Key1'
%% and the public key from `Key2' with algorithm `Algo'.
-spec dh(noise_dh(), keypair(), keypair()) -> binary().
dh(dh25519, Key1, Key2) ->
    SecKey1 = enoise_keypair:seckey(Key1),
    PubKey2 = enoise_keypair:pubkey(Key2),
    enacl:curve25519_scalarmult(SecKey1, PubKey2);
dh(dh448, Key1, Key2) ->
    SecKey1 = enoise_keypair:seckey(Key1),
    PubKey2 = enoise_keypair:pubkey(Key2),
    crypto:compute_key(ecdh, PubKey2, SecKey1, x448);
dh(Type, _Key1, _Key2) ->
    error({unsupported_diffie_hellman, Type}).

-spec hmac(noise_hash(), binary(), binary()) -> binary().
hmac(Hash, Key, Data) ->
    BLen = blocklen(Hash),
    Block1 = hmac_format_key(Hash, Key, 16#36, BLen),
    Hash1 = hash(Hash, <<Block1/binary, Data/binary>>),
    Block2 = hmac_format_key(Hash, Key, 16#5C, BLen),
    hash(Hash, <<Block2/binary, Hash1/binary>>).

-spec hkdf(noise_hash(), binary(), binary()) -> [binary()].
hkdf(Hash, Key, Data) ->
    TempKey = hmac(Hash, Key, Data),
    Output1 = hmac(Hash, TempKey, <<1:8>>),
    Output2 = hmac(Hash, TempKey, <<Output1/binary, 2:8>>),
    Output3 = hmac(Hash, TempKey, <<Output2/binary, 3:8>>),
    [Output1, Output2, Output3].

-spec rekey(noise_cipher(), binary()) -> binary() | {error, term()}.
rekey('ChaChaPoly', K0) ->
    KLen = enacl:aead_chacha20poly1305_ietf_KEYBYTES(),
    <<K:KLen/binary, _/binary>> = encrypt('ChaChaPoly', K0, ?MAX_NONCE, <<>>, <<0:(32*8)>>),
    K;
rekey(Cipher, K) ->
    encrypt(Cipher, K, ?MAX_NONCE, <<>>, <<0:(32*8)>>).

%%

-spec encrypt(noise_cipher(), Key :: binary(), nonce(), Ad :: binary(), PlainText :: binary()) ->
    binary().
encrypt('ChaChaPoly', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    enacl:aead_chacha20poly1305_ietf_encrypt(PlainText, Ad, Nonce, K);
encrypt('AESGCM', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64>>,
    {CipherText, CipherTag} = crypto:crypto_one_time_aead(
        aes_256_gcm, K, Nonce, PlainText, Ad, true
    ),
    <<CipherText/binary, CipherTag/binary>>.

-spec decrypt(noise_cipher(), Key :: binary(), nonce(), Ad :: binary(), CipherText :: binary()) ->
    binary() | {error, term()}.
decrypt('ChaChaPoly', K, N, Ad, CipherText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    enacl:aead_chacha20poly1305_ietf_decrypt(CipherText, Ad, Nonce, K);
decrypt('AESGCM', K, N, Ad, CipherText0) ->
    CTLen = byte_size(CipherText0) - ?MAC_LEN,
    <<CipherText:CTLen/binary, MAC:?MAC_LEN/binary>> = CipherText0,
    Nonce = <<0:32, N:64>>,
    case crypto:crypto_one_time_aead(aes_256_gcm, K, Nonce, CipherText, Ad, MAC, false) of
        error -> {error, decrypt_failed};
        Data  -> Data
    end.

%%

-spec hash(noise_hash(), binary()) -> binary().
hash(blake2b, Data) ->
    enacl:generichash(64, Data);
hash(blake2s, Data) ->
    crypto:hash(blake2s, Data);
hash(sha256, Data) ->
    crypto:hash(sha256, Data);
hash(sha512, Data) ->
    crypto:hash(sha512, Data);
hash(Hash, _Data) ->
    error({hash_not_implemented_yet, Hash}).

-spec pad(binary(), non_neg_integer(), integer()) -> binary().
pad(Data, MinSize, PadByte) ->
    case byte_size(Data) of
        N when N >= MinSize ->
            Data;
        N ->
            PadData = binary:copy(<<PadByte:8>>, MinSize - N),
            <<Data/binary, PadData/binary>>
    end.

-spec hashlen(noise_hash()) -> pos_integer().
hashlen(sha256)  -> 32;
hashlen(sha512)  -> 64;
hashlen(blake2s) -> 32;
hashlen(blake2b) -> 64.

-spec blocklen(noise_hash()) -> pos_integer().
blocklen(sha256)  -> 64;
blocklen(sha512)  -> 128;
blocklen(blake2s) -> 64;
blocklen(blake2b) -> 128.

-spec dhlen(noise_dh()) -> pos_integer().
dhlen(dh25519) -> 32;
dhlen(dh448)   -> 56.

%%-- internals ----------------------------------------------------------------

hmac_format_key(Hash, Key0, Pad, BLen) ->
    Key1 = case byte_size(Key0) =< BLen of
        true  -> Key0;
        false -> hash(Hash, Key0)
    end,
    Key2 = pad(Key1, BLen, 0),
    PadWord = (Pad bsl 24) bor (Pad bsl 16) bor (Pad bsl 8) bor Pad,
    << <<(Word bxor PadWord):32>> || <<Word:32>> <= Key2 >>.
