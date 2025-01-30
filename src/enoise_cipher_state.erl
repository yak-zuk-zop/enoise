%%-----------------------------------------------------------------------------
%% @copyright 2018, Aeternity Anstalt
%%
%% @doc Module encapsulating a Noise Cipher state
%%
%% A CipherState object contains k and n variables, which it uses to
%% encrypt and decrypt ciphertexts. During the handshake phase each
%% party has a single CipherState, but during the transport phase each
%% party has two CipherState objects: one for sending, and one for receiving.
%%
%% k - A cipher key of 32 bytes (or empty). Empty is a special value which
%%     indicates k has not yet been initialized.
%%
%% n - An 8-byte (64-bit) unsigned integer nonce.
%%
%% @end
%%-----------------------------------------------------------------------------

-module(enoise_cipher_state).

-export([
    init/2,
    has_key/1,
    key/1,
    rekey/1,
    set_key/2,
    set_nonce/2,
    decrypt_with_ad/3,
    encrypt_with_ad/3
]).

-type noise_cipher() :: enoise_crypto:noise_cipher().
-type nonce()        :: enoise_crypto:nonce().
-type key()          :: empty | binary().

-record(noise_cs, {
    k      :: key(),
    n      :: nonce(),
    cipher :: noise_cipher()
}).

-opaque state() :: #noise_cs{}.

-export_type([
    state/0
]).

%%-- API ----------------------------------------------------------------------

-spec init(key(), noise_cipher()) -> state().
init(Key, Cipher) ->
    #noise_cs{k = Key, n = 0, cipher = Cipher}.

-spec key(state()) -> key().
key(#noise_cs{k = K}) ->
    K.

-spec set_key(state(), key()) -> state().
set_key(CState, NewKey) ->
    CState#noise_cs{k = NewKey, n = 0}.

-spec has_key(state()) -> boolean().
has_key(#noise_cs{k = Key}) ->
    Key =/= empty.

-spec rekey(state()) -> state().
rekey(CState = #noise_cs{k = K, cipher = Cipher}) ->
    CState#noise_cs{
        k = enoise_crypto:rekey(Cipher, K)
    }.

-spec set_nonce(state(), nonce()) -> state().
set_nonce(CState = #noise_cs{}, Nonce) ->
    CState#noise_cs{n = Nonce}.

%%

-spec encrypt_with_ad(state(), AD :: binary(), PlainText :: binary()) ->
    {ok, state(), binary()}.
encrypt_with_ad(CState = #noise_cs{k = empty}, _AD, PlainText) ->
    {ok, CState, PlainText};
encrypt_with_ad(CState = #noise_cs{k = K, n = N, cipher = Cipher}, AD, PlainText) ->
    Encrypted = enoise_crypto:encrypt(Cipher, K, N, AD, PlainText),
    {ok, CState#noise_cs{n = N + 1}, Encrypted}.

-spec decrypt_with_ad(state(), AD :: binary(), CipherText :: binary()) ->
    {ok, state(), binary()} | {error, term()}.
decrypt_with_ad(CState = #noise_cs{k = empty}, _AD, CipherText) ->
    {ok, CState, CipherText};
decrypt_with_ad(CState = #noise_cs{k = K, n = N, cipher = Cipher}, AD, CipherText) ->
    case enoise_crypto:decrypt(Cipher, K, N, AD, CipherText) of
        PlainText when is_binary(PlainText) ->
            {ok, CState#noise_cs{n = N + 1}, PlainText};
        Err = {error, _} ->
            Err
    end.
