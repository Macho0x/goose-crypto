// EIP-712 typed-data hashing and signing. encodeData values are 32-byte
// words: integers and addresses are left-padded, bytes1..bytes32 are
// right-padded, and string, bytes, arrays, and structs are keccak256.
// The caller builds the canonical encodeType string, referenced structs
// sorted by name. sign returns r || s || v, with v in 27..30.

import std;
import keccak256;
import secp256k1;

namespace eip712;

fn word_uint(src: u8[:]) -> u8[32], bool {
    var o: u8[32] = [0; 32];
    if src.len > 32 { return o, false; }
    let n = src.len;
    for i in 0..n { o[32 - n + i] = src[i]; }
    return o, true;
}

fn word_int(src: u8[:]) -> u8[32], bool {
    var o: u8[32] = [0; 32];
    if src.len == 0 || src.len > 32 { return o, false; }
    let fill: u8 = if (src[0] & 0x80) == 0x80 { 255 } else { 0 };
    for i in 0..32 { o[i] = fill; }
    let n = src.len;
    for i in 0..n { o[32 - n + i] = src[i]; }
    return o, true;
}

fn word_address(src: u8[:]) -> u8[32], bool {
    if src.len != 20 { return [0; 32], false; }
    return word_uint(src);
}

fn word_bytes(src: u8[:]) -> u8[32], bool {
    var o: u8[32] = [0; 32];
    if src.len == 0 || src.len > 32 { return o, false; }
    for i in 0..src.len { o[i] = src[i]; }
    return o, true;
}

fn word_hash(src: u8[:]) -> u8[32] { keccak256::hash(src) }

fn hash_encoded(encoded: u8[:]) -> u8[32], bool {
    if encoded.len == 0 || encoded.len % 32 != 0 { return [0; 32], false; }
    return keccak256::hash(encoded), true;
}

fn digest(domain: u8[:], struct_hash: u8[:]) -> u8[32], bool {
    if domain.len != 32 || struct_hash.len != 32 { return [0; 32], false; }
    var b: u8[66] = [0; 66];
    b[0] = 0x19;
    b[1] = 0x01;
    for i in 0..32 {
        b[2 + i] = domain[i];
        b[34 + i] = struct_hash[i];
    }
    return keccak256::hash(b), true;
}

fn sign(secret: u8[:], domain: u8[:], struct_hash: u8[:]) -> u8[65], bool {
    let dig, ok = digest(domain, struct_hash);
    if !ok { return [0; 65], false; }
    let sig, sok, v = secp256k1::sign(secret, dig);
    if !sok { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    for i in 0..64 { out[i] = sig[i]; }
    out[64] = v;
    return out, true;
}

fn verify(public: u8[:], domain: u8[:], struct_hash: u8[:], sig: u8[:]) -> bool {
    if sig.len != 65 || sig[64] < 27 || sig[64] > 30 { return false; }
    let dig, ok = digest(domain, struct_hash);
    if !ok { return false; }
    return secp256k1::verify(public, dig, sig[..64]);
}

fn write_at(dst: u8[:], at: i64, src: u8[:]) {
    for i in 0..src.len { dst[at + i] = src[i]; }
}
