# goose-crypto

Version 0.13.

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
| `sha512` | SHA-512 and HMAC-SHA512 |
| `ripemd160` | RIPEMD-160. Bitcoin HASH160 is this hash of a SHA-256 digest |
| `hkdf` | HKDF-SHA256 |
| `keccak256` | Keccak-256, the hash Ethereum uses |
| `blake3` | BLAKE3: hash, keyed hash, key derivation, extendable output |
| `chacha20poly1305` | ChaCha20-Poly1305, the ChaCha20 stream, and Poly1305 |
| `x25519` | X25519 |
| `ed25519` | Ed25519 |
| `secp256k1` | ECDSA with an RFC 6979 nonce, low-s, recover, recovery id 27..30 |
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

`goose bench.goose` is the same program through TinyCC, which is how `goose file.goose` runs a module.

The implementations are straight-line Goose: schoolbook field multiplication, no assembly, and no precomputed tables. Timings depend on the machine and the Goose commit, so this page does not publish them. Run the bench above on the machine you care about. Faster code is welcome when `goose self_check.goose` still prints `crypto ok`.

[eth.zig](https://github.com/StrobeLabs/eth.zig) publishes a comparison with alloy.rs. Those figures are from another machine, and that library vendors libsecp256k1 and XKCP Keccak.
