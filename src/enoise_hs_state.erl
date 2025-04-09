%% ----------------------------------------------------------------------------
%% @doc Module encapsulating a Noise handshake state
%%
%% A HandshakeState object contains a SymmetricState plus DH variables (s, e, rs, re)
%% and a variable representing the handshake pattern. During the handshake phase each
%% party has a single HandshakeState, which can be deleted once the handshake is finished.
%%
%% s  - local static key pair
%% e  - local ephemeral key pair
%% rs - remote party's static public key
%% re - remote party's ephemeral public key
%%
%% @end
%% ----------------------------------------------------------------------------

-module(enoise_hs_state).

-export([
    init/4,
    init/5,
    finalize/1,
    remote_keys/1,
    next_message/1,
    read_message/2,
    write_message/2
]).

-type noise_role()  :: initiator | responder.
-type noise_token() :: enoise_protocol:noise_token().
-type keypair()     :: enoise_keypair:keypair().
-type noise_key()   :: enoise_crypto:noise_key().
-type noise_split_state() :: #{
    rx := enoise_cipher_state:state(),
    tx := enoise_cipher_state:state(),
    hs_hash := binary(),
    final_state => state()
}.
-type initial_keypairs() :: {
    keypair() | undefined,
    keypair() | undefined,
    keypair() | undefined,
    keypair() | undefined
}.

-record(noise_hs, {
    ss   :: enoise_sym_state:state(),
    s    :: keypair() | undefined,
    e    :: keypair() | undefined,
    rs   :: keypair() | undefined,
    re   :: keypair() | undefined,
    psk  :: noise_key() | undefined,
    role :: noise_role(),
    dh   :: enoise_crypto:noise_dh(),
    msgs :: [enoise_protocol:noise_msg()]
}).

-opaque state() :: #noise_hs{}.

-export_type([
    noise_role/0,
    noise_split_state/0,
    state/0
]).

%%-- API ----------------------------------------------------------------------

-spec init(Protocol :: enoise_protocol:protocol(),
           Role :: noise_role(), Prologue :: binary(),
           Keys :: initial_keypairs()) -> state().
init(Protocol, Role, Prologue, Keys) ->
    init(Protocol, Role, Prologue, Keys, undefined).

-spec init(Protocol :: enoise_protocol:protocol(),
           Role :: noise_role(), Prologue :: binary(),
           Keys :: initial_keypairs(),
           PSK  :: noise_key() | undefined) -> state().
init(Protocol, Role, Prologue, {S, E, RS, RE}, PSK) ->
    SS0 = enoise_sym_state:init(Protocol),
    SS1 = enoise_sym_state:mix_hash(SS0, Prologue),
    HS = #noise_hs{
        ss = SS1,
        s = S, e = E, rs = RS, re = RE,
        psk = PSK,
        role = Role,
        dh = enoise_protocol:dh(Protocol),
        msgs = enoise_protocol:msgs(Role, Protocol)
    },
    PreMsgs = enoise_protocol:pre_msgs(Role, Protocol),
    lists:foldl(fun({out, [s]}, HS0) -> mix_hash(HS0, enoise_keypair:pubkey(S));
                   ({out, [e]}, HS0) -> mix_hash(HS0, enoise_keypair:pubkey(E));
                   ({in, [s]}, HS0)  -> mix_hash(HS0, enoise_keypair:pubkey(RS));
                   ({in, [e]}, HS0)  -> mix_hash(HS0, enoise_keypair:pubkey(RE))
                end, HS, PreMsgs).

-spec finalize(state()) -> {ok, noise_split_state()} | no_return().
finalize(HS = #noise_hs{msgs = [], ss = SS, role = Role}) ->
    {C1, C2} = enoise_sym_state:split(SS),
    HSHash   = enoise_sym_state:h(SS),
    Final    = #{hs_hash => HSHash, final_state => HS},
    case Role of
        initiator -> {ok, Final#{tx => C1, rx => C2}};
        responder -> {ok, Final#{rx => C1, tx => C2}}
    end;
finalize(HS) ->
    error({expected, next_message(HS)}).

-spec next_message(state()) -> in | out | done.
next_message(#noise_hs{msgs = [{Dir, _} | _]}) -> Dir;
next_message(#noise_hs{}) -> done.

-spec write_message(state(), PayLoad :: binary()) ->
    {ok, state(), binary()} | {error, term()}.
write_message(HS = #noise_hs{msgs = [{out, Msg} | Msgs]}, PayLoad) ->
    {HS1, MsgBuf1} = write_message(HS#noise_hs{msgs = Msgs}, Msg, <<>>),
    {ok, HS2, MsgBuf2} = encrypt_and_hash(HS1, PayLoad),
    {ok, HS2, <<MsgBuf1/binary, MsgBuf2/binary>>};
write_message(HS, _) ->
    {error, {expected, next_message(HS)}}.

%%

-spec read_message(state(), Message :: binary()) ->
    {ok, state(), binary()} | {error, term()}.
read_message(HS = #noise_hs{msgs = [{in, Tokens} | Msgs]}, Message) ->
    case read_message(HS#noise_hs{msgs = Msgs}, Tokens, Message) of
        {ok, HS1, RestBuf1}  -> decrypt_and_hash(HS1, RestBuf1);
        {error, _} = Err -> Err
    end;
read_message(HS, _) ->
    {error, {expected, next_message(HS)}}.

-spec remote_keys(state()) -> keypair().
remote_keys(#noise_hs{rs = RS}) ->
    RS.

%%-- internals ----------------------------------------------------------------

-spec read_message(state(), [noise_token()], Msg :: binary()) ->
    {ok, state(), binary()} | {error, term()}.
read_message(HS, [], Msg) ->
    {ok, HS, Msg};
read_message(HS, [Token | Tokens], Msg0) ->
    case read_token(HS, Token, Msg0) of
        {ok, HS1, Msg1} -> read_message(HS1, Tokens, Msg1);
        {error, _} = Err -> Err
    end.

-spec write_message(state(), [noise_token()], Msg :: binary()) ->
    {state(), Msg :: binary()}.
write_message(HS, [], MsgBuf) ->
    {HS, MsgBuf};
write_message(HS, [Token | Tokens], MsgBuf0) ->
    {HS1, MsgBuf1} = write_token(HS, Token),
    write_message(HS1, Tokens, <<MsgBuf0/binary, MsgBuf1/binary>>).

%%

-spec read_token(state(), noise_token(), binary()) ->
    {ok, state(), binary()} | {error, term()}.
read_token(HS = #noise_hs{re = undefined, dh = DH}, Token = e, Data0) ->
    DHLen = enoise_crypto:dhlen(DH),
    case Data0 of
        <<REPub:DHLen/binary, Data1/binary>> ->
            RE = enoise_keypair:new(DH, REPub),
            HS2 = mix_hash(HS#noise_hs{re = RE}, REPub),
            {ok, psk_maybe_mix_key(HS2, REPub), Data1};
        _ ->
            {error, {bad_data, {failed_to_read_token, Token, DHLen}}}
    end;
read_token(HS = #noise_hs{rs = undefined, dh = DH}, Token = s, Data0) ->
    DHLen = case has_key(HS) of
        true  -> enoise_crypto:dhlen(DH) + 16;
        false -> enoise_crypto:dhlen(DH)
    end,
    case Data0 of
        <<Temp:DHLen/binary, Data1/binary>> ->
            case decrypt_and_hash(HS, Temp) of
                {ok, HS1, RSPub} ->
                    RS = enoise_keypair:new(DH, RSPub),
                    {ok, HS1#noise_hs{rs = RS}, Data1};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, {bad_data, {failed_to_read_token, Token, DHLen}}}
    end;
read_token(HS = #noise_hs{psk = PSK}, psk, Data) ->
    {ok, mix_key_and_hash(HS, PSK), Data};
read_token(HS, Token, Data) ->
    {ok, mix_key(HS, dh(dh_token(HS, Token))), Data}.

%%

-spec write_token(state(), noise_token()) ->
    {state(), PubKey :: binary()}.
write_token(HS = #noise_hs{e = undefined, dh = DH}, e) ->
    E = enoise_keypair:new(DH),
    PubE = enoise_keypair:pubkey(E),
    {mix_hash(HS#noise_hs{e = E}, PubE), PubE};
%% Should only apply during test - TODO: secure this
write_token(HS = #noise_hs{e = E}, e) ->
    PubE = enoise_keypair:pubkey(E),
    HS2 = mix_hash(HS, PubE),
    {psk_maybe_mix_key(HS2, PubE), PubE};
write_token(HS = #noise_hs{s = S}, s) ->
    {ok, HS1, Msg} = encrypt_and_hash(HS, enoise_keypair:pubkey(S)),
    {HS1, Msg};
write_token(HS = #noise_hs{psk = PSK}, psk) ->
    {mix_key_and_hash(HS, PSK), <<>>};
write_token(HS, Token) ->
    {mix_key(HS, dh(dh_token(HS, Token))), <<>>}.

-spec dh_token(state(), noise_token()) -> {keypair() | undefined, keypair() | undefined}.
dh_token(#noise_hs{e = E, re = RE}                  , ee) -> {E, RE};
dh_token(#noise_hs{e = E, rs = RS, role = initiator}, es) -> {E, RS};
dh_token(#noise_hs{s = S, re = RE, role = responder}, es) -> {S, RE};
dh_token(#noise_hs{s = S, re = RE, role = initiator}, se) -> {S, RE};
dh_token(#noise_hs{e = E, rs = RS, role = responder}, se) -> {E, RS};
dh_token(#noise_hs{s = S, rs = RS}                  , ss) -> {S, RS}.

%%-- Local wrappers -----------------------------------------------------------

-spec dh({keypair(), keypair()}) -> binary().
dh({Key1, Key2}) ->
    enoise_crypto:dh(Key1, Key2).

-spec has_key(state()) -> boolean().
has_key(#noise_hs{ss = SS}) ->
    enoise_cipher_state:has_key(enoise_sym_state:cipher_state(SS)).

-spec mix_key(state(), binary()) -> state().
mix_key(HS = #noise_hs{ss = SS0}, Data) ->
    HS#noise_hs{ss = enoise_sym_state:mix_key(SS0, Data)}.

-spec mix_hash(state(), binary()) -> state().
mix_hash(HS = #noise_hs{ss = SS0}, Data) ->
    HS#noise_hs{ss = enoise_sym_state:mix_hash(SS0, Data)}.

-spec psk_maybe_mix_key(state(), binary()) -> state().
psk_maybe_mix_key(HS = #noise_hs{psk = undefined}, _Data) ->
    HS;
psk_maybe_mix_key(HS, Data) ->
    mix_key(HS, Data).

-spec mix_key_and_hash(state(), binary()) -> state().
mix_key_and_hash(HS = #noise_hs{ss = SS0}, Data) ->
    HS#noise_hs{ss = enoise_sym_state:mix_key_and_hash(SS0, Data)}.

-spec encrypt_and_hash(state(), PlainText :: binary()) ->
    {ok, state(), CipherText :: binary()}.
encrypt_and_hash(HS = #noise_hs{ss = SS0}, PlainText) ->
    {ok, SS1, CipherText} = enoise_sym_state:encrypt_and_hash(SS0, PlainText),
    {ok, HS#noise_hs{ss = SS1}, CipherText}.

-spec decrypt_and_hash(state(), binary()) ->
    {ok, state(), binary()} | {error, term()}.
decrypt_and_hash(HS = #noise_hs{ss = SS0}, CipherText) ->
    case enoise_sym_state:decrypt_and_hash(SS0, CipherText) of
        {ok, SS1, PlainText} ->
            {ok, HS#noise_hs{ss = SS1}, PlainText};

        {error, _} = Err ->
            Err
    end.
