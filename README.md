enoise
======

An Erlang implementation of the [Noise protocol](https://noiseprotocol.org/)

`enoise` provides a generic handshake mechanism, that can be used in a couple
of different ways. There is also a plain `gen_tcp`-wrapper, where you can
"upgrade" a TCP socket to a Noise socket and use it in much the same way as you
would use `gen_tcp`.

Features
--------

`enoise` aims to support noise protocol rev.34

- cipher: ChaChaPoly, AESGCM
- dh: 25519, 448
- hash: sha2-256, sha2-512, blake2s, blake2b
- interactive fundamental patterns
- interactive deferred patterns
- oneway patterns
- modifiers psk0-3

The fallback madifier is waiting to be implemented.

Handshakes
---------------------

When using `enoise` to do an interactive handshake, `enoise` will only take
care of message composition/decomposition and encryption/decryption - i.e. the
user has to do the actual sending and receiving.

An example of the interactive handshake can be seen in the `test_handshake`
test in `test/enoise_handshake_tests.erl`.

Generic handshake
-----------------

There is also the option to use an automated handshake procedure. If provided
with a generic _Communication state_ that describe how data is sent and
received, the handshake procedure is done automatically. The result of a
successful handshake is two Cipher states that can be used to encrypt/decrypt a
RX channel and a TX channel respectively.

The provided `gen_tcp`-wrapper is implemented using the generic handshake, see
`src/enoise.erl`.

Build & Test
------------

```sh
make compile
make tests
```

Quick demo
----------

This demo uses `NN` handshake pattern, which is:
```
NN:
  -> e
  <- e, ee
```

Start Erlang shell by `erl -pa _build/default/lib/*/ebin`, then paste lines below into shell:

```erlang
Protocol = <<"Noise_NN_25519_ChaChaPoly_SHA256">>,

AliceOpts = [
    {noise, Protocol},
    {role, initiator}
],

BobOpts = [
    {noise, Protocol},
    {role, responder}
],

AliceHS0 = enoise:create_hstate(AliceOpts),
BobHS0 = enoise:create_hstate(BobOpts),

{ok, send, EncMsg1, AliceHS1} = enoise:step_handshake(AliceHS0, {send, <<>>}),
{ok, rcvd, <<>>, BobHS1} = enoise:step_handshake(BobHS0, {rcvd, EncMsg1}),

{ok, send, EncMsg2, BobHS2} = enoise:step_handshake(BobHS1, {send, <<>>}),
{ok, done, #{rx := BobRX}} = enoise:step_handshake(BobHS2, done),

{ok, rcvd, <<>>, AliceHS2} = enoise:step_handshake(AliceHS1, {rcvd, EncMsg2}),
{ok, done, #{tx := AliceTX}} = enoise:step_handshake(AliceHS2, done),

{ok, _, EncMsg3} = enoise:encrypt(AliceTX, <<"Hello!">>),
{ok, _, HelloMsg} = enoise:decrypt(BobRX, EncMsg3), HelloMsg.
```

Noise Protocol Architecture
---------------------------

```
+----------------------------------------------+
|               Handshake State                |
|         Patterns & tokens processing         |
| +------------------------------------------+ |
| |            Symmetric State               | |
| |  key ratcheting, mixing data into state  | |
| | +--------------------------------------+ | |
| | |            Cipher State              | | |
| | |            AEAD + nonce              | | |
| | +--------------------------------------+ | |
| +------------------------------------------+ |
+----------------------------------------------+
```
