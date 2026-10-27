// EIP-191 personal_sign. The digest is keccak256 of
// "\x19Ethereum Signed Message:\n" || decimal(length) || message.
// sign returns r || s || v, with v in 27..30.

import std;
import keccak256;
import secp256k1;

namespace eip191;

fn write_dec(dst: u8[:], at: i64, n: i64) -> i64 {
    if n == 0 {
        dst[at] = '0';
        return 1;
    }
    var v = n;
    var digits = 0;
    while v > 0 {
        v /= 10;
        digits += 1;
    }
    v = n;
    for i in 0..digits {
        dst[at + digits - 1 - i] = ('0' + (v % 10)) as! u8;
        v /= 10;
    }
    return digits;
}

fn digest(message: u8[:]) -> u8[32] {
    let prefix = "\x19Ethereum Signed Message:\n";
    var buf: u8[>..] = [];
    buf.resize(prefix.len + 20 + message.len, 0);
    for i in 0..prefix.len { buf[i] = prefix[i]; }
    let nd = write_dec(buf[prefix.len..], 0, message.len);
    let start = prefix.len + nd;
    for i in 0..message.len { buf[start + i] = message[i]; }
    buf.resize(start + message.len, 0);
    return keccak256::hash(buf);
}

fn sign(secret: u8[:], message: u8[:]) -> u8[65], bool {
    let dig = digest(message);
    let sig, ok, v = secp256k1::sign(secret, dig);
    if !ok { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    for i in 0..64 { out[i] = sig[i]; }
    out[64] = v;
    return out, true;
}

fn verify(public: u8[:], message: u8[:], sig: u8[:]) -> bool {
    if sig.len != 65 || sig[64] < 27 || sig[64] > 30 { return false; }
    return secp256k1::verify(public, digest(message), sig[..64]);
}

fn nibble(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn eq_hex(got: u8[:], hex: u8[:]) -> bool {
    if got.len * 2 != hex.len { return false; }
    for i in 0..got.len {
        let v = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
        if got[i] != v { return false; }
    }
    return true;
}

fn unhex(hex: u8[:], out: u8[:]) {
    for i in 0..out.len { out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]); }
}

fn self_check() -> bool {
    var secret: u8[32] = [0; 32];
    unhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", secret);
    let dig = digest("hello world");
    if !dig.eq_hex("d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68") { return false; }
    let sig, ok = sign(secret, "hello world");
    if !ok || !sig.eq_hex("0d5df3f9681b000a5b3a1d4252803318136714deba10c578f9b33718ad9c816e5520a6f19168136aa11e38d691d28a422bce4be3bf290fdb8efe45cdaefb20251c") { return false; }
    let pk, pok = secp256k1::pubkey_compressed(secret);
    if !pok || !verify(pk, "hello world", sig) { return false; }
    let raw, rok = secp256k1::pubkey_uncompressed(secret);
    if !rok || !verify(raw, "hello world", sig) { return false; }
    sig[64] = 26;
    if verify(pk, "hello world", sig) { return false; }
    return true;
}

fn ::main() {
    if eip191::self_check() { print("eip191 ok"); } else { print("eip191 FAIL"); exit(1); }
}
