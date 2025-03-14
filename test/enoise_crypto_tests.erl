-module(enoise_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

-define(H2B(S), test_utils:hex2bin(S)).

-spec test() -> _.

%%-- tests --------------------------------------------------------------------

-spec diffie_hellman_test_() -> _.
diffie_hellman_test_() ->
    {setup,
        fun () ->
            DHs = maps:get(dh, enoise_protocol:supported()),
            Types = [dynamic, static],
            [{T, DH} || T <- Types, DH <- DHs]
        end,
        fun (DHs) ->
            [fun () -> dh_test_int(DH) end || DH <- DHs]
        end
    }.

-spec hash_test_() -> _.
hash_test_() ->
    {setup,
        fun() ->
            Hashs = maps:get(hash, enoise_protocol:supported()),
            lists:flatten([[{H, Data} || Data <- hash_data(H)] || H <- Hashs])
        end,
        fun (Hashs) ->
            [fun () -> hash_test_int(H, Data) end || {H, Data} <- Hashs]
        end
    }.

%%

-spec chachapoly_test() -> _.
chachapoly_test() ->
    cipher_test_int('ChaChaPoly').

-spec aes_gcm_test() -> _.
aes_gcm_test() ->
    cipher_test_int('AESGCM').

-spec blake2b_hmac_test() -> _.
blake2b_hmac_test() ->
    hmac_test_int(blake2b).

-spec blake2b_hkdf_test() -> _.
blake2b_hkdf_test() ->
    hkdf_test_int(blake2b).

%%-- internals ----------------------------------------------------------------

hash_test_int(Hash, #{input := In, output := Out}) ->
    ?assertMatch(Out, enoise_crypto:hash(Hash, In)).

hmac_test_int(Hash) ->
    Test = fun(#{key := Key, data := Data, hmac := HMAC}) ->
        ?assertMatch(HMAC, enoise_crypto:hmac(Hash, Key, Data))
    end,
    lists:foreach(Test, hmac_data(Hash)).

hkdf_test_int(Hash) ->
    Test = fun(#{key := Key, data := Data, out1 := Out1, out2 := Out2}) ->
        ?assertMatch([Out1, Out2, _], enoise_crypto:hkdf(Hash, Key, Data))
    end,
    lists:foreach(Test, hkdf_data(Hash)).

dh_test_int({dynamic, DH}) ->
    KeyPair1 = enoise_keypair:new(DH),
    KeyPair2 = enoise_keypair:new(DH),

    SharedA = enoise_crypto:dh(KeyPair1, KeyPair2),
    SharedB = enoise_crypto:dh(KeyPair2, KeyPair1),
    ?assertMatch(SharedA, SharedB);
dh_test_int({static, DH}) ->
    #{alice := AKeyPair, bob := BKeyPair, shared := Shared} = diffie_hellman_data(DH),

    ?assertMatch(Shared, enoise_crypto:dh(AKeyPair, BKeyPair)),
    ?assertMatch(Shared, enoise_crypto:dh(BKeyPair, AKeyPair)).

cipher_test_int(Cipher) ->
    #{key := Key, nonce := Nonce, ad := AD, mac := MAC,
       pt := PlainText, ct := CipherText} = test_utils:cipher_data(Cipher),
    PTLen  = byte_size(PlainText),
    CTLen  = byte_size(CipherText),
    MACLen = byte_size(MAC),

    %% Sanity check
    ?assert(PTLen == CTLen),

    <<CipherText0:CTLen/binary, MAC0:MACLen/binary>> =
        enoise_crypto:encrypt(Cipher, Key, Nonce, AD, PlainText),

    ?assertMatch(CipherText, CipherText0),
    ?assertMatch(MAC, MAC0),

    <<PlainText0:PTLen/binary>> = enoise_crypto:decrypt(
        Cipher, Key, Nonce, AD, <<CipherText/binary, MAC/binary>>
    ),

    ?assertMatch(PlainText, PlainText0),

    % rekey test
    Key1 = enoise_crypto:rekey(Cipher, Key),
    <<CipherText1:CTLen/binary, MAC1:MACLen/binary>> =
        enoise_crypto:encrypt(Cipher, Key1, Nonce, AD, PlainText),
    <<PlainText1:PTLen/binary>> =
        enoise_crypto:decrypt(Cipher, Key1, Nonce, AD, <<CipherText1/binary, MAC1/binary>>),
    ?assertMatch(PlainText, PlainText1),
    ok.

%%-- fixtures -----------------------------------------------------------------

-spec diffie_hellman_data(enoise_crypto:noise_dh()) ->
    #{alice := enoise_keypair:keypair(), bob := enoise_keypair:keypair(), shared := binary()}.
diffie_hellman_data(DH = dh25519) ->
    APriv  = ?H2B("0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    APub   = ?H2B("0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    BPriv  = ?H2B("0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
    BPub   = ?H2B("0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
    Shared = ?H2B("0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
    #{
        alice  => enoise_keypair:new(DH, APriv, APub),
        bob    => enoise_keypair:new(DH, BPriv, BPub),
        shared => Shared
    };
diffie_hellman_data(DH = dh448) ->
    APriv = ?H2B(
        "0x9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
        "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
    ),
    APub = ?H2B(
        "0x9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
        "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
    ),
    BPriv = ?H2B(
        "0x1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
        "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
    ),
    BPub = ?H2B(
        "0x3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
        "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    ),
    Shared = ?H2B(
        "0x07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
        "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    ),
    #{
        alice  => enoise_keypair:new(DH, APriv, APub),
        bob    => enoise_keypair:new(DH, BPriv, BPub),
        shared => Shared
    }.

-spec hash_data(enoise_crypto:noise_hash()) ->
    [#{input := binary(), output := binary()}].
hash_data(blake2b) ->
    [#{ input => <<>>,
        output => ?H2B(
            "0x786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
      },
     #{ input => <<"abc">>,
        output => ?H2B(
            "0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
      },
     #{ input => <<"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq">>,
        output => ?H2B(
            "0x7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141"
            "ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888")
      },
     #{ input => <<"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                   "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu">>,
        output => ?H2B(
            "0xce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11"
            "ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52")
    }];
hash_data(blake2s) ->
    [#{ input => <<>>,
        output => ?H2B(
            "0x69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
    },
    #{ input => <<"abc">>,
        output => ?H2B(
            "0x508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982")
    },
    #{ input => <<"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq">>,
        output => ?H2B(
            "0x6f4df5116a6f332edab1d9e10ee87df6557beab6259d7663f3bcd5722c13f189")
    },
    #{ input => <<"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                  "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu">>,
        output => ?H2B(
            "0x358dd2ed0780d4054e76cb6f3a5bce2841e8e2f547431d4d09db21b66d941fc7")
    }];
hash_data(sha256) ->
    [#{ input => <<>>,
        output => ?H2B(
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    },
    #{ input => <<"abc">>,
       output => ?H2B(
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    },
    #{ input => <<"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq">>,
       output => ?H2B(
            "0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }];
hash_data(sha512) ->
    [#{ input => <<>>,
        output => ?H2B(
            "0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    },
    #{ input => <<"abc">>,
       output => ?H2B(
            "0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    },
    #{ input => <<"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                  "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu">>,
       output => ?H2B(
            "0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
    }].

-spec hmac_data(enoise_crypto:noise_hash()) ->
    [#{key := binary(), data := binary(), hmac := binary()}].
hmac_data(blake2b) ->
    [#{ key  => binary:copy(<<16#AA>>, 64),
        data => binary:copy(<<16#66>>, 128),
        hmac => ?H2B(
            "0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
            "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9")
      },
     #{ key  => ?H2B(
            "0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
            "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9"),
        data => <<16#01>>,
        hmac => ?H2B(
            "0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
            "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB76")
      },
     #{ key  => ?H2B(
            "0x4054489AA4225A07BD7F4C89330AA6412B612AADC8FA86AFBC8EC6AC2D0F3AC8"
            "ECDB6601B060F47488D4074C562F848B9F6168BA8CDEE22E399057B5D53129C9"),
        data => ?H2B(
            "0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
            "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB7602"),
        hmac => ?H2B(
            "0x37E23F26F8445E3B5A88949B98606131774BA4D15F2C6E17A0A43972BB4EB6B5"
            "CBB42F57D8B1B63B4C9EA64B0493E82A6F6D3A7037C33212EF6E4F56E321D4D9")
    }].

-spec hkdf_data(enoise_crypto:noise_hash()) ->
    [#{key := binary(), data := binary(), out1 := binary(), out2 := binary()}].
hkdf_data(blake2b) ->
    [#{ key  => binary:copy(<<16#AA>>, 64),
        data => binary:copy(<<16#66>>, 128),
        out1 => ?H2B(
            "0x359D3AA619DF4F73E4E8EA31D05F5631C96F119D46F6BB44B5C7772B862747E7"
            "818D4BC8907C1EBA90B06AD7925EC5E751E4E92D0E0233F893CD3FED8DD6FB76"),
        out2 => ?H2B(
            "0x37E23F26F8445E3B5A88949B98606131774BA4D15F2C6E17A0A43972BB4EB6B5"
            "CBB42F57D8B1B63B4C9EA64B0493E82A6F6D3A7037C33212EF6E4F56E321D4D9")
    }].
