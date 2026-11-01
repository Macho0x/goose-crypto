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

const IV: u64[8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

// The length field's low word holds the bit count. Messages stay under 2^61 bytes.
const MAX_BYTES: u64 = 0x2000000000000000;

struct Ctx {
    h: u64[8] = IV,
    buf: u8[128],
    n: i64,
    bytes: u64,
}

fn rotr(x: u64, n: u64) -> u64 { (x >> n) | (x << (64 - n)) }

fn load_be64(s: u8[:], i: i64) -> u64 {
    let c = s[i..i + 8];
    return (c[0] as u64) << 56 | (c[1] as u64) << 48 | (c[2] as u64) << 40 | (c[3] as u64) << 32 |
        (c[4] as u64) << 24 | (c[5] as u64) << 16 | (c[6] as u64) << 8 | c[7];
}

inline fn round(a: u64&, b: u64&, c: u64&, d: u64&, e: u64&, f: u64&, g: u64&, h: u64&, k: u64, x: u64) {
    let t1 = h + (rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)) + (g ^ (e & (f ^ g))) + k + x;
    let t2 = (rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)) + ((a & b) | (c & (a | b)));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
}

// data is a whole number of 128-byte blocks.
fn blocks(state: u64[8]&, data: u8[:]) {
    var w: u64[16] = [0; 16];
    var i = 0;
    while i + 128 <= data.len {
        let chunk = data[i..i + 128];
        var a = state[0];
        var b = state[1];
        var c = state[2];
        var d = state[3];
        var e = state[4];
        var f = state[5];
        var g = state[6];
        var h = state[7];
        for t in 0..16 {
            let x = load_be64(chunk, 8 * t);
            w[t] = x;
            round(a, b, c, d, e, f, g, h, K[t], x);
        }
        for t in 16..80 {
            let w15 = w[(t - 15) & 15];
            let w2 = w[(t - 2) & 15];
            let s0 = rotr(w15, 1) ^ rotr(w15, 8) ^ (w15 >> 7);
            let s1 = rotr(w2, 19) ^ rotr(w2, 61) ^ (w2 >> 6);
            let x = w[t & 15] + s0 + w[(t - 7) & 15] + s1;
            w[t & 15] = x;
            round(a, b, c, d, e, f, g, h, K[t], x);
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
        i += 128;
    }
}

fn check_length(total: u64, more: i64) {
    let m = more as u64;
    if m >= MAX_BYTES - total { abort("sha512: a message must be shorter than 2^61 bytes"); }
}

fn init(c: Ctx&) {
    c.h = IV;
    c.n = 0;
    c.bytes = 0;
}

fn update(c: Ctx&, data: u8[:]) {
    check_length(c.bytes, data.len);
    c.bytes += data.len as u64;
    var off = 0;
    if c.n > 0 {
        let space = 128 - c.n;
        var take = data.len;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[i]; }
        c.n += take;
        off = take;
        if c.n < 128 { return; }
        blocks(c.h, c.buf);
        c.n = 0;
    }
    let whole = ((data.len - off) / 128) * 128;
    if whole > 0 { blocks(c.h, data[off..off + whole]); }
    off += whole;
    let tail = data.len - off;
    for i in 0..tail { c.buf[i] = data[off + i]; }
    c.n = tail;
}

fn store_be64(dst: u8[:], at: i64, v: u64) {
    for k in 0..8 { dst[at + k] = (v >> ((7 - k) * 8)) as! u8; }
}

// The digest so far. c is left as it was.
fn finish(c: Ctx&) -> u8[64] {
    var h = copy(c.h);
    let n = c.n;
    var tailbuf: u8[256] = [0; 256];
    for i in 0..n { tailbuf[i] = c.buf[i]; }
    tailbuf[n] = 0x80;
    let nblk = if n >= 112 { 256 } else { 128 };
    store_be64(tailbuf, nblk - 8, c.bytes << 3);
    blocks(h, tailbuf[..nblk]);
    var out: u8[64] = [0; 64];
    for i in 0..8 { store_be64(out, i * 8, h[i]); }
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
