%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module is an abstract data type for a key pair.
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_keypair).

-export([
    new/1,
    new/2,
    new/3,
    pubkey/1,
    seckey/1,
    keytype/1
]).

-type key_type() :: enoise_crypto:noise_dh().

-record(kp, {
    type :: key_type(),
    sec  :: binary() | undefined,
    pub  :: binary()
}).

-opaque keypair() :: #kp{}.

-export_type([
    keypair/0
]).

%%-- API ----------------------------------------------------------------------

%% @doc Generate a new keypair of type `Type'.
-spec new(key_type()) -> keypair().
new(Type) ->
    #{secret := Sec, public := Pub} = enoise_crypto:new_key_pair(Type),
    #kp{type = Type, sec = Sec, pub = Pub}.

%% @doc Create a new keypair of type `Type'. If `Public' is `undefined'
%% it will be computed from the `Secret' (using the curve/algorithm
%% indicated by `Type').
-spec new(Type :: key_type(),
          Secret :: binary() | undefined,
          Public :: binary() | undefined) -> keypair().
new(Type, Secret, undefined) when Secret =/= undefined ->
    new(Type, Secret, enoise_crypto:pubkey_from_secret(Type, Secret));
new(Type, Secret, Public) ->
    #kp{type = Type, sec = Secret, pub = Public}.

%% @doc Define a "public only" keypair - holding just a public key and
%% `undefined' for secret key.
-spec new(Type :: key_type(), Public :: binary()) -> keypair().
new(Type, Public) ->
    #kp{type = Type, sec = undefined, pub = Public}.

%%

-spec keytype(keypair()) -> key_type().
keytype(#kp{type = T}) ->
    T.

-spec pubkey(keypair()) -> binary().
pubkey(#kp{pub = P}) ->
    P.

-spec seckey(keypair()) -> binary().
seckey(#kp{sec = undefined}) ->
    error(keypair_is_public_only);
seckey(#kp{sec = S}) ->
    S.
