<p align="center">
  <img src="logo.png" alt="A goose holding a golden key" width="220">
</p>

<h1 align="center">goose-crypto</h1>

<p align="center">
  🔑 Hashes, ciphers, and public keys for <a href="https://github.com/aardappel/goose">Goose</a><br>
  <strong>0.18.1</strong> · <a href="LICENSE">Apache-2.0</a>
</p>

Hashes, ciphers, and public-key algorithms, written in Goose. There are no foreign calls and no vendored C. Transaction and typed-data signing lives in [goose-signature](https://github.com/Macho0x/goose-signature). The tests in `tests/` check each module against a published vector.

## Example

From a program that sits next to this repo:

```goose
import crypto from "../crypto";
import crypto.sha256;

fn main() {
    let dig = sha256::hash("abc");
    print(dig);
}
```

`crypto.goose` is only the package entry. Importing the package does not pull in the algorithms. `import crypto.sha256` does.

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

`bip340` stays here. Taproot and BIP-322 in goose-signature call it, and it is a key algorithm alongside `ed25519`.

## Good to know

This code does not run in constant time. Secret-dependent choices are masked in the field arithmetic, and multiplication can still take data-dependent time. Do not use it where a secret's timing can be observed.

## Benchmarks

`bench.goose` times the modules in the table above.

```sh
goose build -o crypto-bench bench.goose --cc clang
./crypto-bench
```

That clang build is the speed build. `goose bench.goose` is the same program through TinyCC.

secp256k1 reduces products by the field prime and the group order, and multiplies the generator from a precomputed comb. Keccak absorbs eight bytes at a time. The other modules are straight-line Goose. There is no assembly. Timings depend on the machine and the Goose commit, so this page does not publish them. Faster code is welcome when `goose tests/self_check.goose` still prints `crypto ok`.

## License

Apache-2.0. Free and open to everyone. The terms are in [LICENSE](LICENSE).
