# goose-crypto

Version 0.17.

Hashes, ciphers, and public-key algorithms in [Goose](https://github.com/aardappel/goose). Transaction and typed-data signing is [goose-signature](../signature). The implementations are Goose, with no foreign calls and no vendored C. The tests in `tests/` check each module against a published vector.

Copyright 2026 Macho0x. Licensed under Apache-2.0, the same license as Goose.

## Check

Install the Goose compiler, then from this directory:

```sh
goose tests/sha256.goose
```

A good run prints `sha256 ok`. The same holds for every module below.

```sh
goose tests/self_check.goose
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
| `bip340` | Schnorr signatures |

Transaction and typed-data signing is goose-signature. `bip340` is in this package. Taproot and BIP-322 call it, and it is a key algorithm alongside `ed25519`.

This code does not run in constant time. Secret-dependent choices are masked in the field arithmetic, and multiplication can still take data-dependent time. Do not use it where a secret's timing can be observed.

## Benchmarks

`bench.goose` times the modules in the table above. goose-signature calls those modules, and the tests in that package check the signers.

```sh
goose build -o crypto-bench bench.goose --cc clang
./crypto-bench
```

That clang build is the speed build. `goose bench.goose` is the same program through TinyCC, which is how `goose file.goose` runs a module.

secp256k1 reduces products by the field prime and the group order, and multiplies the generator from a precomputed comb. Keccak absorbs eight bytes at a time. The other modules are straight-line Goose. There is no assembly. Timings depend on the machine and the Goose commit, so this page does not publish them. Run the bench above on the machine you care about. Faster code is welcome when `goose tests/self_check.goose` still prints `crypto ok`.

[eth.zig](https://github.com/StrobeLabs/eth.zig) publishes a comparison with alloy.rs. Those figures are from another machine, and that library vendors libsecp256k1 and XKCP Keccak.
