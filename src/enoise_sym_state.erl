%%-----------------------------------------------------------------------------
%% @copyright 2018, Aeternity Anstalt
%%
%% @doc Module encapsulating a Noise symmetric (hash) state
%%
%% A SymmetricState object contains a CipherState plus ck and h variables.
%% It is so-named because it encapsulates all the "symmetric crypto" used
%% by Noise. During the handshake phase each party has a single SymmetricState,
%% which can be deleted once the handshake is finished.
%%
%% ck - chaining key of HASHLEN bytes.
%% h  - hash output of HASHLEN bytes.
%%
%% @end
%%-----------------------------------------------------------------------------

-module(enoise_sym_state).

-export([
    init/1,
    mix_key/2,
    mix_hash/2,
    mix_key_and_hash/2,
    encrypt_and_hash/2,
    decrypt_and_hash/2,
    split/1,
    cipher_state/1,
    ck/1,
    h/1
]).

-export_type([
    state/0
]).

-record(noise_ss, {
    cs   :: enoise_cipher_state:state(),
    ck   :: binary(),
    h    :: binary(),
    hash :: enoise_crypto:noise_hash()
}).

-opaque state() :: #noise_ss{}.

%%-- API ----------------------------------------------------------------------

-spec init(enoise_protocol:protocol()) -> state().
init(Protocol) ->
    Hash    = enoise_protocol:hash(Protocol),
    Cipher  = enoise_protocol:cipher(Protocol),
    Name    = enoise_protocol:to_name(Protocol),
    HashLen = enoise_crypto:hashlen(Hash),
    H1 = case byte_size(Name) > HashLen of
        true  -> enoise_crypto:hash(Hash, Name);
        false -> enoise_crypto:pad(Name, HashLen, 16#00)
    end,
    #noise_ss{
        cs = enoise_cipher_state:init(empty, Cipher),
        ck = H1,
        h = H1,
        hash = Hash
    }.

-spec mix_key(state(), binary()) -> state().
mix_key(SState = #noise_ss{hash = Hash, ck = CK0, cs = CS0}, InputKeyMaterial) ->
    [CK1, <<TempK:32/binary, _/binary>> | _] =
        enoise_crypto:hkdf(Hash, CK0, InputKeyMaterial),
    CS1 = enoise_cipher_state:set_key(CS0, TempK),
    SState#noise_ss{ck = CK1, cs = CS1}.

-spec mix_hash(state(), binary()) -> state().
mix_hash(SState = #noise_ss{hash = Hash, h = H0}, Data) ->
    SState#noise_ss{
        h = enoise_crypto:hash(Hash, <<H0/binary, Data/binary>>)
    }.

-spec mix_key_and_hash(state(), InputKeyMaterial :: binary()) -> state().
mix_key_and_hash(SState = #noise_ss{hash = Hash, ck = CK0, cs = CS0}, InputKeyMaterial) ->
    [CK1, TempH, <<TempK:32/binary, _/binary>>] =
        enoise_crypto:hkdf(Hash, CK0, InputKeyMaterial),
    CS1 = enoise_cipher_state:set_key(CS0, TempK),
    mix_hash(SState#noise_ss{ck = CK1, cs = CS1}, TempH).

-spec encrypt_and_hash(state(), binary()) -> {ok, state(), binary()}.
encrypt_and_hash(SState = #noise_ss{cs = CS0, h = H}, PlainText) ->
    {ok, CS1, CipherText} = enoise_cipher_state:encrypt_with_ad(CS0, H, PlainText),
    {ok, mix_hash(SState#noise_ss{cs = CS1}, CipherText), CipherText}.

-spec decrypt_and_hash(state(), binary()) -> {ok, state(), binary()} | {error, term()}.
decrypt_and_hash(SState = #noise_ss{cs = CS0, h = H}, CipherText) ->
    case enoise_cipher_state:decrypt_with_ad(CS0, H, CipherText) of
        {error, _} = Err ->
            Err;
        {ok, CS1, PlainText} ->
            {ok, mix_hash(SState#noise_ss{cs = CS1}, CipherText), PlainText}
    end.

-spec split(state()) -> {enoise_cipher_state:state(), enoise_cipher_state:state()}.
split(#noise_ss{hash = Hash, ck = CK, cs = CS}) ->
    [<<TempK1:32/binary, _/binary>>, <<TempK2:32/binary, _/binary>>, _] =
        enoise_crypto:hkdf(Hash, CK, <<>>),
    {enoise_cipher_state:set_key(CS, TempK1), enoise_cipher_state:set_key(CS, TempK2)}.

%%

-spec cipher_state(state()) -> enoise_cipher_state:state().
cipher_state(#noise_ss{cs = CS}) ->
    CS.

-spec ck(state()) -> binary().
ck(#noise_ss{ck = CK}) ->
    CK.

-spec h(state()) -> binary().
h(#noise_ss{h = H}) ->
    H.
