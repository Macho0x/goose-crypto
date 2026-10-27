// SHA-512 (FIPS 180-4) and HMAC-SHA512 (RFC 2104).
// Words are wrapping u64. Digests and HMAC tags are 64 bytes.
// The block is 128 bytes.

import std;

namespace sha512;

const K: u64[80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

struct Ctx {
    h: u64[8],
    buf: u8[128],
    n: i64,
    bytes: u64,
}

fn rotr(x: u64, n: u64) -> u64 { (x >> n) | (x << (64 - n)) }

fn init(c: Ctx&) {
    c.h[0] = 0x6a09e667f3bcc908;
    c.h[1] = 0xbb67ae8584caa73b;
    c.h[2] = 0x3c6ef372fe94f82b;
    c.h[3] = 0xa54ff53a5f1d36f1;
    c.h[4] = 0x510e527fade682d1;
    c.h[5] = 0x9b05688c2b3e6c1f;
    c.h[6] = 0x1f83d9abfb41bd6b;
    c.h[7] = 0x5be0cd19137e2179;
    c.n = 0;
    c.bytes = 0;
}

fn compress(h: u64[8]&, buf: u8[:]) {
    var w: u64[80] = [0; 80];
    for i in 0..16 {
        let j = i * 8;
        var x: u64 = 0;
        for k in 0..8 {
            let byte: u64 = buf[j + k];
            x |= byte << ((7 - k) * 8);
        }
        w[i] = x;
    }
    for i in 16..80 {
        let x = w[i - 15];
        let y = w[i - 2];
        let s0 = rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
        let s1 = rotr(y, 19) ^ rotr(y, 61) ^ (y >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3];
    var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7];
    for i in 0..80 {
        let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        let ch = (e & f) ^ (~e & g);
        let t1 = hh + s1 + ch + K[i] + w[i];
        let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

fn update(c: Ctx&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        let space = 128 - c.n;
        var take = data.len - off;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[off + i]; }
        c.n += take;
        off += take;
        c.bytes += take as u64;
        if c.n == 128 {
            compress(c.h, c.buf);
            c.n = 0;
        }
    }
}

// finish consumes c.
fn finish(c: Ctx&) -> u8[64] {
    let n = c.n;
    c.buf[n] = 0x80;
    if n >= 112 {
        for i in (n + 1)..128 { c.buf[i] = 0; }
        compress(c.h, c.buf);
        for i in 0..112 { c.buf[i] = 0; }
    } else {
        for i in (n + 1)..112 { c.buf[i] = 0; }
    }
    let bits = c.bytes << 3;
    for k in 0..8 { c.buf[112 + k] = 0; }
    for k in 0..8 { c.buf[120 + k] = (bits >> ((7 - k) * 8)) as! u8; }
    compress(c.h, c.buf);
    var out: u8[64] = [0; 64];
    for i in 0..8 {
        let v = c.h[i];
        for k in 0..8 { out[i * 8 + k] = (v >> ((7 - k) * 8)) as! u8; }
    }
    return out;
}

fn hash(data: u8[:]) -> u8[64] {
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, data);
    return finish(c);
}

fn hmac(key: u8[:], data: u8[:]) -> u8[64] {
    var k: u8[128] = [0; 128];
    if key.len > 128 {
        let hk = hash(key);
        for i in 0..64 { k[i] = hk[i]; }
    } else {
        for i in 0..key.len { k[i] = key[i]; }
    }
    var ipad: u8[128] = [0; 128];
    var opad: u8[128] = [0; 128];
    for i in 0..128 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    var inner: Ctx = default<Ctx>();
    init(inner);
    update(inner, ipad);
    update(inner, data);
    let ih = finish(inner);
    var outer: Ctx = default<Ctx>();
    init(outer);
    update(outer, opad);
    update(outer, ih);
    return finish(outer);
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

fn self_check() -> bool {
    if !hash("").eq_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") { return false; }
    if !hash("abc").eq_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") { return false; }
    let long = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    if !hash(long).eq_hex("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, "ab");
    update(c, "c");
    if !finish(c).eq_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") { return false; }
    var key: u8[20] = [0x0b; 20];
    if !hmac(key, "Hi There").eq_hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854") { return false; }
    if !hmac("Jefe", "what do ya want for nothing?").eq_hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737") { return false; }
    return true;
}

fn ::main() {
    if sha512::self_check() { print("sha512 ok"); } else { print("sha512 FAIL"); exit(1); }
}
