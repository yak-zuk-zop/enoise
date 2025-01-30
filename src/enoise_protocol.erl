%%% ------------------------------------------------------------------
%%% @copyright 2018, Aeternity Anstalt
%%%
%%% @doc Module defining Noise protocol configurations
%%%
%%% @end
%%% ------------------------------------------------------------------

-module(enoise_protocol).

%% API
-export([
    cipher/1,
    dh/1,
    from_name/1,
    hash/1,
    msgs/2,
    pattern/1,
    pre_msgs/2,
    supported/0,
    to_name/1
]).

-ifdef(TEST).
-export([to_name/4]).
-endif.

-type noise_dh() :: enoise_crypto:noise_dh().
-type noise_cipher() :: enoise_crypto:noise_cipher().
-type noise_hash() :: enoise_crypto:noise_hash().
-type noise_pattern() :: nn | kn | nk | kk | nx | kx | xn | in | xk | ik | xx | ix.
-type noise_token() :: s | e | ee | ss | es | se. % TODO: add psk
-type noise_msg()     :: {in | out, [noise_token()]}.

-record(noise_protocol, {
    hs_pattern :: noise_pattern(),
    dh         :: noise_dh(),
    cipher     :: noise_cipher(),
    hash       :: noise_hash()
}).

-opaque protocol() :: #noise_protocol{}.

-export_type([
    noise_msg/0,
    noise_pattern/0,
    noise_token/0,
    protocol/0
]).

%%-- API ----------------------------------------------------------------------

-spec cipher(protocol()) -> noise_cipher().
cipher(#noise_protocol{cipher = Cipher}) ->
    Cipher.

-spec dh(protocol()) -> noise_dh().
dh(#noise_protocol{dh = Dh}) ->
    Dh.

-spec hash(protocol()) -> noise_hash().
hash(#noise_protocol{hash = Hash}) ->
    Hash.

-spec pattern(protocol()) -> noise_pattern().
pattern(#noise_protocol{hs_pattern = Pattern}) ->
    Pattern.

%%

-spec to_name(protocol()) -> binary().
to_name(Protocol) ->
    case is_supported(Protocol) of
        true  ->
            #noise_protocol{
                hs_pattern = Pattern,
                dh = Dh,
                cipher = Cipher,
                hash = Hash
            } = Protocol,
            to_name(Pattern, Dh, Cipher, Hash);
        false ->
            error({protocol_not_recognized, Protocol})
    end.

-spec from_name(Name :: string() | binary()) -> protocol().
from_name(Bin) when is_binary(Bin) ->
    from_name(binary_to_list(Bin));
from_name(String) ->
    case string:lexemes(String, "_") of
        ["Noise", PatStr, DhStr, CipStr, HashStr] ->
            Protocol = #noise_protocol{
                hs_pattern = from_name_pattern(PatStr),
                dh = from_name_dh(DhStr),
                cipher = from_name_cipher(CipStr),
                hash = from_name_hash(HashStr)
            },
            case is_supported(Protocol) of
                true ->
                    Protocol;
                false ->
                    error({name_not_recognized, String})
            end;
        _ ->
            error({name_not_recognized, String})
    end.

%%

-spec msgs(enoise_hs_state:noise_role(), protocol()) -> [noise_msg()].
msgs(Role, #noise_protocol{hs_pattern = Pattern}) ->
    {_Pre, Msgs} = protocol(Pattern),
    role_adapt(Role, Msgs).

-spec pre_msgs(enoise_hs_state:noise_role(), protocol()) -> [noise_msg()].
pre_msgs(Role, #noise_protocol{hs_pattern = Pattern}) ->
    {PreMsgs, _Msgs} = protocol(Pattern),
    role_adapt(Role, PreMsgs).

-spec role_adapt(enoise_hs_state:noise_role(), [noise_msg()]) -> [noise_msg()].
role_adapt(initiator, Msgs) ->
    Msgs;
role_adapt(responder, Msgs) ->
    Flip = fun
        ({in, Msg}) -> {out, Msg};
        ({out, Msg}) -> {in, Msg}
    end,
    lists:map(Flip, Msgs).

%%

%% The first character refers to the initiator's static key:
%%
%%  * N = No static key for initiator
%%  * K = Static key for initiator Known to responder
%%  * X = Static key for initiator Xmitted ("transmitted") to responder
%%  * I = Static key for initiator Immediately transmitted to responder, despite reduced or absent identity hiding
%%
%% The second character refers to the responder's static key:
%%
%%  * N = No static key for responder
%%  * K = Static key for responder Known to initiator
%%  * X = Static key for responder Xmitted ("transmitted") to initiator

%% patterns se & es differs from https://noiseprotocol.org/noise.html#handshake-patterns

-spec protocol(noise_pattern()) -> {list(PreMsg :: noise_msg()), list(noise_msg())}.
protocol(nn) ->
    {[], [{out, [e]}, {in, [e, ee]}]};
protocol(kn) ->
    {[{out, [s]}], [{out, [e]}, {in, [e, ee, se]}]};
protocol(nk) ->
    {[{in, [s]}], [{out, [e, es]}, {in, [e, ee]}]};
protocol(kk) ->
    {[{out, [s]}, {in, [s]}], [{out, [e, es, ss]}, {in, [e, ee, se]}]};
protocol(nx) ->
    {[], [{out, [e]}, {in, [e, ee, s, es]}]};
protocol(kx) ->
    {[{out, [s]}], [{out, [e]}, {in, [e, ee, se, s, es]}]};
protocol(xn) ->
    {[], [{out, [e]}, {in, [e, ee]}, {out, [s, se]}]};
protocol(in) ->
    {[], [{out, [e, s]}, {in, [e, ee, se]}]};
protocol(xk) ->
    {[{in, [s]}], [{out, [e, es]}, {in, [e, ee]}, {out, [s, se]}]};
protocol(ik) ->
    {[{in, [s]}], [{out, [e, es, s, ss]}, {in, [e, ee, se]}]};
protocol(xx) ->
    {[], [{out, [e]}, {in, [e, ee, s, es]}, {out, [s, se]}]};
protocol(ix) ->
    {[], [{out, [e, s]}, {in, [e, ee, se, s, es]}]}.

%% TODO: One-way handshake patterns
%protocol(n) ->
%    {[{out, [s]}], [{in, [e, se]}]};
%protocol(k) ->
%    {[{in, [s]}, {out, [s]}], [{in, [e, se, ss]}]};
%protocol(x) ->
%    {[{out, [s]}], [{in, [e, se, s, ss]}]}.

%%

-spec is_supported(protocol()) -> boolean().
is_supported(#noise_protocol{hs_pattern = Pattern, dh = Dh, cipher = Cipher, hash = Hash}) ->
    Supported = supported(),
    lists:member(Pattern, maps:get(hs_pattern, Supported)) andalso
    lists:member(Cipher, maps:get(cipher, Supported)) andalso
    lists:member(Dh, maps:get(dh, Supported)) andalso
    lists:member(Hash, maps:get(hash, Supported)).

-spec supported() -> map().
supported() ->
    #{
        hs_pattern => [nn, kn, nk, kk, nx, kx, xn, in, xk, ik, xx, ix],
        hash       => [blake2b, blake2s, sha256, sha512],
        cipher     => ['ChaChaPoly', 'AESGCM'],
        dh         => [dh25519, dh448]
    }.

%%

-spec to_name(noise_pattern(), noise_dh(), noise_cipher(), noise_hash()) -> binary().
to_name(Pattern, Dh, Cipher, Hash) ->
    StrList = ["Noise", to_name_pattern(Pattern), to_name_dh(Dh),
        to_name_cipher(Cipher), to_name_hash(Hash)],
    list_to_binary(lists:join("_", StrList)).

to_name_pattern(Atom) ->
    [Simple | Rest] = string:lexemes(atom_to_list(Atom), "_"),
    string:uppercase(Simple) ++ lists:join("+", Rest).

from_name_pattern(String) ->
    [Init | Mod2] = string:lexemes(String, "+"),
    {Simple, Mod1} = lists:splitwith(fun(C) -> C >= $A andalso C =< $Z end, Init),
    list_to_atom(string:lowercase(Simple) ++
        case Mod1 of
            "" -> "";
            _  -> "_" ++ lists:join([Mod1 | Mod2], "_")
        end).

to_name_dh(dh25519) -> "25519";
to_name_dh(dh448)   -> "448".

from_name_dh(Dh) -> list_to_atom("dh" ++ Dh).

to_name_cipher(Cipher) -> atom_to_list(Cipher).

from_name_cipher(Cipher) -> list_to_atom(Cipher).

-spec to_name_hash(noise_hash()) -> string().
to_name_hash(sha256)  -> "SHA256";
to_name_hash(sha512)  -> "SHA512";
to_name_hash(blake2s) -> "BLAKE2s";
to_name_hash(blake2b) -> "BLAKE2b".

-spec from_name_hash(string()) -> noise_hash().
from_name_hash(Hash) -> list_to_atom(string:lowercase(Hash)).
