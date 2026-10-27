# goose-crypto

Hashes, public-key cryptography, and transaction signing in [Goose](https://github.com/aardappel/goose). The implementations are Goose, with no foreign calls and no vendored C. Every module checks itself against a published test vector.

Copyright 2026 Macho0x. Licensed under Apache-2.0, the same license as Goose.

## Check

Install the Goose compiler, then from this directory:

```sh
goose sha256.goose
```

A good run prints `sha256 ok`. The same holds for every module below.

```sh
goose self_check.goose
```

runs all of them and prints `crypto ok`.

`import sha256` loads `sha256.goose` from the directory of the program you pass to goose, which is why the modules sit side by side. From a program in another directory:

```goose
import crypto from "../crypto";
import crypto.sha256;

fn main() {
    let dig = sha256::hash("abc");
}
```

`crypto.goose` is only the package entry. Importing the package does not pull in the algorithms; `import crypto.sha256` does.

## Modules

| Module | What it does |
| --- | --- |
| `sha256` | SHA-256 and HMAC-SHA256 |
| `keccak256` | Keccak-256, the hash Ethereum uses |
| `blake3` | BLAKE3: hash, keyed hash, key derivation, extendable output |
| `chacha20poly1305` | ChaCha20-Poly1305, the ChaCha20 stream, and Poly1305 |
| `x25519` | X25519 |
| `ed25519` | Ed25519. SHA-512 lives in this file |
| `secp256k1` | ECDSA with an RFC 6979 nonce, low-s, recovery id 27..30 |
| `argon2id` | Argon2id |
| `eip191` | `personal_sign` |
| `eip712` | Typed-data digest and signature |
| `eth_tx` | RLP, and signing hashes for legacy, EIP-155, and type 1, 2, 3, and 4 transactions, plus EIP-7702 authorization |
| `bip340` | Schnorr signatures |
| `btc_legacy` | Legacy sighash and strict DER |
| `btc_segwit` | BIP-143 |
| `btc_taproot` | BIP-341 key-path and script-path |
| `bip322` | Simple BIP-322 proofs for P2PKH, P2WPKH, and P2TR |
| `solana` | Legacy and v0 transaction messages, and off-chain messages |

Bitcoin sighash flags are ALL, NONE, SINGLE, and ANYONECANPAY. Callers pass the script, the keys, and the message. There is no script interpreter, no UTXO set, no HD derivation, and no address codec. BIP-322 is simple proofs only. An EIP-4844 signature covers the transaction fields and the blob versioned hashes, not the blob payload. A Dogecoin legacy signature is `btc_legacy`. BNB Smart Chain is `eth_tx` with chain id 56.

This code does not run in constant time. Secret-dependent choices are masked in the field arithmetic, and multiplication can still take data-dependent time. Do not use it where a secret's timing can be observed.

## Benchmarks

`bench.goose` times the primitives. The signing modules call those primitives; their self-checks are the correctness test and are not part of the timing.

```sh
goose build -o crypto-bench bench.goose --cc gcc
./crypto-bench
```

`goose bench.goose` is the same program through TinyCC, which is how `goose file.goose` runs a module. One batch runs untimed. Further batches run until the window elapses, and the clock calls sit outside the timed section. Hashes use a batch of 64 and a 250 ms window. The 4 KB hashes and the AEAD use a batch of 16. X25519, Ed25519, and Argon2id use one call and a 400 ms window. secp256k1, BIP-340, and EIP-191 use one call and a 2 s window. Each call contributes a result byte to a sink printed at the end, so the compiler has to do the work. `secp256k1 verify` decompresses a compressed public key. The Argon2id row is the module's published vector, 32 KiB, 3 passes, 4 lanes, not a production memory setting. A TinyCC signature that lasts longer than the window is a single timed call.

Measured on 27 October 2026, Intel i7-1165G7, Goose `64d62fc`, gcc 16.2.1.

| Operation | gcc | TinyCC |
| --- | ---: | ---: |
| sha256 32B | 426 ns | 2.28 µs |
| sha256 4KB | 26.6 µs | 125 µs |
| keccak256 empty | 3.04 µs | 17.2 µs |
| keccak256 32B | 3.11 µs | 15.3 µs |
| keccak256 4KB | 99.8 µs | 467 µs |
| blake3 32B | 339 ns | 4.57 µs |
| blake3 4KB | 15.5 µs | 192 µs |
| chacha20poly1305 seal 32B | 466 ns | 5.88 µs |
| x25519 public | 891 µs | 5.16 ms |
| ed25519 sign | 3.72 ms | 22.2 ms |
| ed25519 verify | 4.23 ms | 25.5 ms |
| secp256k1 sign | 242 ms | 1.72 s |
| secp256k1 verify | 470 ms | 3.41 s |
| bip340 sign | 459 ms | 3.27 s |
| bip340 verify | 453 ms | 3.29 s |
| eip191 personal_sign | 239 ms | 1.71 s |
| argon2id 32KiB t=3 p=4 | 241 µs | 2.47 ms |

[eth.zig](https://github.com/StrobeLabs/eth.zig) publishes a comparison with alloy.rs. Those figures are from another machine, and that library vendors libsecp256k1 and XKCP Keccak. Run `bench.goose` on the machine you care about.
