import crypto from "..";
import crypto.secp256k1;

namespace secp256k1;

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
    var one: u8[32] = [0; 32];
    one[31] = 1;
    let pk, ok = pubkey_compressed(one);
    if !ok || !pk.eq_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") { return false; }
    var two: u8[32] = [0; 32];
    two[31] = 2;
    let pk2, ok2 = pubkey_compressed(two);
    if !ok2 || !pk2.eq_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5") { return false; }
    var nm1: u8[32] = [0; 32];
    unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", nm1);
    let pkn, okn = pubkey_compressed(nm1);
    if !okn || !pkn.eq_hex("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") { return false; }
    var digest: u8[32] = [0; 32];
    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest);
    let sig, sok, v = sign(one, digest);
    if !sok || !sig.eq_hex("77c8d336572f6f466055b5f70f433851f8f535f6c4fc71133a6cfd71079d03b70ed9f5eb8aa5b266abac35d416c3207e7a538bf5f37649727d7a9823b1069577") { return false; }
    if !verify(pk, digest, sig) { return false; }
    var high: u8[64] = sig;
    store_be(sub8(order(), load_be(high[32..])), high[32..]);
    if verify(pk, digest, high) { return false; }
    let raw, rok = pubkey_uncompressed(one);
    if !rok || !verify(raw, digest, sig) { return false; }
    var full: u8[65] = [0; 65];
    for i in 0..64 { full[i] = sig[i]; }
    full[64] = v;
    let got, gok = recover(digest, full);
    if !gok || got != raw { return false; }
    var high65: u8[65] = [0; 65];
    for i in 0..64 { high65[i] = high[i]; }
    high65[64] = v;
    let _, hok = recover(digest, high65);
    if hok { return false; }
    full[64] = 26;
    let _, vok = recover(digest, full);
    if vok { return false; }
    sig[63] ^= 1;
    if verify(pk, digest, sig) { return false; }
    return true;
}

fn ::main() {
    if secp256k1::self_check() { print("secp256k1 ok"); } else { print("secp256k1 FAIL"); exit(1); }
}
