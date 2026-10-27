// HKDF-SHA256 (RFC 5869). extract returns a 32-byte PRK.
// expand writes L bytes into the caller buffer, L from 1 to 255 * 32.
// An empty salt is 32 zero bytes.

import std;
import sha256;

namespace hkdf;

fn append(out: u8[>..]&, src: u8[:]) {
    if src.len == 0 { return; }
    let n = out.len;
    out.resize(n + src.len, 0);
    for i in 0..src.len { out[n + i] = src[i]; }
}

fn append_byte(out: u8[>..]&, b: u8) {
    let n = out.len;
    out.resize(n + 1, 0);
    out[n] = b;
}

fn extract(salt: u8[:], ikm: u8[:]) -> u8[32] {
    if salt.len != 0 { return sha256::hmac(salt, ikm); }
    var z: u8[32] = [0; 32];
    return sha256::hmac(z, ikm);
}

fn expand(prk: u8[:], info: u8[:], out: u8[:]) -> bool {
    if out.len == 0 || out.len > 255 * 32 { return false; }
    var prev: u8[32] = [0; 32];
    var done = 0;
    var n = 1;
    while done < out.len {
        var msg: u8[>..] = [];
        if n > 1 { append(msg, prev); }
        append(msg, info);
        append_byte(msg, n as! u8);
        let tag = sha256::hmac(prk, msg);
        var take = 32;
        if done + take > out.len { take = out.len - done; }
        for i in 0..take { out[done + i] = tag[i]; }
        prev = tag;
        done += take;
        n += 1;
    }
    return true;
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
    var ikm: u8[22] = [0x0b; 22];
    var salt: u8[13] = [0; 13];
    unhex("000102030405060708090a0b0c", salt);
    var info: u8[10] = [0; 10];
    unhex("f0f1f2f3f4f5f6f7f8f9", info);
    let prk = extract(salt, ikm);
    if !prk.eq_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5") { return false; }
    var okm: u8[42] = [0; 42];
    if !expand(prk, info, okm) { return false; }
    if !okm.eq_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") { return false; }

    var ikm2: u8[80] = [0; 80];
    var salt2: u8[80] = [0; 80];
    var info2: u8[80] = [0; 80];
    for i in 0..80 { ikm2[i] = i as! u8; }
    for i in 0..80 { salt2[i] = (0x60 + i) as! u8; }
    for i in 0..80 { info2[i] = (0xb0 + i) as! u8; }
    let prk2 = extract(salt2, ikm2);
    if !prk2.eq_hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244") { return false; }
    var okm2: u8[82] = [0; 82];
    if !expand(prk2, info2, okm2) { return false; }
    if !okm2.eq_hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87") { return false; }

    let prk3 = extract("", ikm);
    if !prk3.eq_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04") { return false; }
    var okm3: u8[42] = [0; 42];
    if !expand(prk3, "", okm3) { return false; }
    if !okm3.eq_hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8") { return false; }
    var sink: u8[1] = [0; 1];
    if expand(prk, info, sink[..0]) { return false; }
    return true;
}

fn ::main() {
    if hkdf::self_check() { print("hkdf ok"); } else { print("hkdf FAIL"); exit(1); }
}
