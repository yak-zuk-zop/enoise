%% ----------------------------------------------------------------------------
%% @doc Module implementing crypto primitives needed by Noise protocol
%%
%% @end
%% ----------------------------------------------------------------------------

-module(enoise_crypto).

%% API
-export([
    decrypt/5,
    dh/2,
    dhlen/1,
    encrypt/5,
    hash/2,
    hashlen/1,
    hkdf/3,
    pad/3,
    rekey/2,
    pubkey_from_secret/2,
    new_key_pair/1
]).

-ifdef(TEST).
-export([hmac/3]).
-endif.

-export_type([
    noise_dh/0,
    noise_cipher/0,
    noise_hash/0,
    noise_key/0,
    nonce/0
]).

-define(MAC_LEN, 16).
-define(MAX_NONCE, 16#FFFFFFFFFFFFFFFF).
-define(HMAC_INNER_MAGIC, 16#36).
-define(HMAC_OUTER_MAGIC, 16#5C).

-type noise_cipher() :: 'ChaChaPoly' | 'AESGCM'.
-type noise_dh()     :: dh25519 | dh448.
-type noise_hash()   :: sha256 | sha512 | blake2s | blake2b.
-type nonce()        :: non_neg_integer().
-type noise_key()    :: binary().
-type keypair()      :: enoise_keypair:keypair().

-type cipher_aead()  :: aes_256_gcm | chacha20_poly1305.
-type edwards_curve_ed() :: x25519 | x448.

%%-- API ----------------------------------------------------------------------

%% @doc Perform a Diffie-Hellman calculation with the secret key from `Key1'
%% and the public key from `Key2' with algorithm `noise_dh()'.
%% DH(SK1, PK2) == DH(SK2, PK1)
%% @end
-spec dh(keypair(), keypair()) -> binary().
dh(Key1, Key2) ->
    SecKey1 = enoise_keypair:seckey(Key1),
    PubKey2 = enoise_keypair:pubkey(Key2),
    case {enoise_keypair:keytype(Key1), enoise_keypair:keytype(Key2)} of
        {T, T} ->
            crypto:compute_key(ecdh, PubKey2, SecKey1, curve_ecdh(T));
        Wrong ->
            error({badarg, Wrong})
    end.

%% @doc hash-based message authentication code
%% Key - secret key for parties
%% @end
-spec hmac(noise_hash(), noise_key(), binary()) -> binary().
hmac(Hash, Key, Data) ->
    BLen = blocklen(Hash),
    Block1 = hmac_format_key(Hash, Key, ?HMAC_INNER_MAGIC, BLen),
    Hash1 = hash(Hash, <<Block1/binary, Data/binary>>),
    Block2 = hmac_format_key(Hash, Key, ?HMAC_OUTER_MAGIC, BLen),
    hash(Hash, <<Block2/binary, Hash1/binary>>).

%% @doc HMAC key derivation function
-spec hkdf(noise_hash(), noise_key(), binary()) -> [binary()].
hkdf(Hash, Key, Data) ->
    TempKey = hmac(Hash, Key, Data),
    Output1 = hmac(Hash, TempKey, <<1:8>>),
    Output2 = hmac(Hash, TempKey, <<Output1/binary, 2:8>>),
    Output3 = hmac(Hash, TempKey, <<Output2/binary, 3:8>>),
    [Output1, Output2, Output3].

%% @doc Generate new session key
-spec rekey(noise_cipher(), noise_key()) -> noise_key().
rekey(Cipher, K0) ->
    <<K:256/binary-unit:1, _/binary>> = encrypt(Cipher, K0, ?MAX_NONCE, <<>>, <<0:256>>),
    K.

%% @doc Restore public key from a secret
-spec pubkey_from_secret(noise_dh(), noise_key()) -> noise_key().
pubkey_from_secret(Curve, Secret) ->
    {PK, _SK} = crypto:generate_key(ecdh, curve_ecdh(Curve), Secret),
    PK.

%% @doc Generate new key pair
-spec new_key_pair(noise_dh()) -> #{public := noise_key(), secret := noise_key()}.
new_key_pair(Curve) ->
    {PK, SK} = crypto:generate_key(ecdh, curve_ecdh(Curve)),
    #{public => PK, secret => SK}.

%%

-spec encrypt(noise_cipher(), noise_key(), nonce(), Ad :: binary(), PlainText :: binary()) ->
    binary().
encrypt('ChaChaPoly', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    {CipherText, CipherTag} = crypto:crypto_one_time_aead(
        chacha20_poly1305, K, Nonce, PlainText, Ad, true
    ),
    <<CipherText/binary, CipherTag/binary>>;
encrypt('AESGCM', K, N, Ad, PlainText) ->
    Nonce = <<0:32, N:64>>,
    {CipherText, CipherTag} = crypto:crypto_one_time_aead(
        aes_256_gcm, K, Nonce, PlainText, Ad, true
    ),
    <<CipherText/binary, CipherTag/binary>>.

-spec decrypt(noise_cipher(), noise_key(), nonce(), Ad :: binary(), CipherText :: binary()) ->
    binary() | {error, term()}.
decrypt('ChaChaPoly', K, N, Ad, CipherText) ->
    Nonce = <<0:32, N:64/little-unsigned-integer>>,
    decrypt_crypto(chacha20_poly1305, K, Nonce, CipherText, Ad);
decrypt('AESGCM', K, N, Ad, CipherText) ->
    Nonce = <<0:32, N:64>>,
    decrypt_crypto(aes_256_gcm, K, Nonce, CipherText, Ad).

%%

-spec hash(noise_hash(), binary()) -> binary().
hash(H, Data) when H == blake2b; H == blake2s; H == sha256; H == sha512 ->
    crypto:hash(H, Data);
hash(Hash, _Data) ->
    error({unsupported, {hash, Hash}}).

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

-spec hmac_format_key(noise_hash(), noise_key(), byte(), pos_integer()) -> binary().
hmac_format_key(Hash, Key0, Pad, BLen) ->
    Key1 = case byte_size(Key0) =< BLen of
        true  -> Key0;
        false -> hash(Hash, Key0)
    end,
    Key2 = pad(Key1, BLen, 16#00),
    PadWord = (Pad bsl 24) bor (Pad bsl 16) bor (Pad bsl 8) bor Pad,
    << <<(Word bxor PadWord):32>> || <<Word:32>> <= Key2 >>.

-spec curve_ecdh(noise_dh()) -> edwards_curve_ed().
curve_ecdh(dh25519) -> x25519;
curve_ecdh(dh448) -> x448;
curve_ecdh(T) -> error({unsupported, {dh, T}}).

-spec decrypt_crypto(Cipher, K, Nonce, CipherText0, Ad) -> binary() | {error, term()} when
    Cipher :: cipher_aead(),
    K :: noise_key(),
    Nonce :: binary(),
    CipherText0 :: binary(),
    Ad :: binary().
decrypt_crypto(Cipher, K, Nonce, CipherText0, Ad) ->
    CTLen = byte_size(CipherText0) - ?MAC_LEN,
    <<CipherText:CTLen/binary, MAC:?MAC_LEN/binary>> = CipherText0,
    case crypto:crypto_one_time_aead(Cipher, K, Nonce, CipherText, Ad, MAC, false) of
        error -> {error, decrypt_failed};
        Data  -> Data
    end.
