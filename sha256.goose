// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
// Words are wrapping u32. Digests and HMAC tags are 32 bytes.

import std;

namespace sha256;

const K: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: u32[8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// FIPS 180-4 limits a message to less than 2^64 bits.
const MAX_BYTES: u64 = 0x2000000000000000;

struct Ctx {
    h: u32[8] = IV,
    buf: u8[64],
    n: i64,
    bytes: u64,
}

// Inner and outer states after the key block. Copy one to MAC another
// message under the same key.
struct Mac {
    inner: Ctx,
    outer: Ctx,
}

fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

fn load_be32(s: u8[:], i: i64) -> u32 {
    let c = s[i..i + 4];
    return (c[0] as u32) << 24 | (c[1] as u32) << 16 | (c[2] as u32) << 8 | c[3];
}

fn store_be64(dst: u8[:], at: i64, v: u64) {
    for i in 0..8 {
        dst[at + i] = (v >> ((7 - i) * 8)) as! u8;
    }
}

fn store_be32(dst: u8[:], at: i64, v: u32) {
    dst[at] = (v >> 24) as! u8;
    dst[at + 1] = (v >> 16) as! u8;
    dst[at + 2] = (v >> 8) as! u8;
    dst[at + 3] = v as! u8;
}

inline fn round(a: u32&, b: u32&, c: u32&, d: u32&, e: u32&, f: u32&, g: u32&, h: u32&, k: u32, x: u32) {
    let t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + (g ^ (e & (f ^ g))) + k + x;
    let t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) | (c & (a | b)));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
}

// data is a whole number of 64-byte blocks.
fn blocks(state: u32[8]&, data: u8[:]) {
    var w: u32[16] = [0; 16];
    var i = 0;
    while i + 64 <= data.len {
        let chunk = data[i..i + 64];
        var a = state[0];
        var b = state[1];
        var c = state[2];
        var d = state[3];
        var e = state[4];
        var f = state[5];
        var g = state[6];
        var h = state[7];
        for t in 0..16 {
            let x = load_be32(chunk, 4 * t);
            w[t] = x;
            round(a, b, c, d, e, f, g, h, K[t], x);
        }
        for t in 16..64 {
            let w15 = w[(t - 15) & 15];
            let w2 = w[(t - 2) & 15];
            let s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
            let s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
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
        i += 64;
    }
}

fn check_length(total: u64, more: i64) {
    let m = more as u64;
    if m >= MAX_BYTES - total { abort("sha256: a message must be shorter than 2^61 bytes"); }
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
        let space = 64 - c.n;
        var take = data.len;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[i]; }
        c.n += take;
        off = take;
        if c.n < 64 { return; }
        blocks(c.h, c.buf);
        c.n = 0;
    }
    let whole = ((data.len - off) / 64) * 64;
    if whole > 0 { blocks(c.h, data[off..off + whole]); }
    off += whole;
    let tail = data.len - off;
    for i in 0..tail { c.buf[i] = data[off + i]; }
    c.n = tail;
}

// The digest so far. c is left as it was.
fn finish(c: Ctx&) -> u8[32] {
    var h = copy(c.h);
    let n = c.n;
    var tailbuf: u8[128] = [0; 128];
    for i in 0..n { tailbuf[i] = c.buf[i]; }
    tailbuf[n] = 0x80;
    let nblk = if n >= 56 { 128 } else { 64 };
    store_be64(tailbuf, nblk - 8, c.bytes << 3);
    blocks(h, tailbuf[..nblk]);
    var out: u8[32] = [0; 32];
    for i in 0..8 { store_be32(out, i * 4, h[i]); }
    return out;
}

fn hash(data: u8[:]) -> u8[32] {
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, data);
    return finish(c);
}

// SHA-256(SHA-256(data)). The second hash is one block.
fn hash256(data: u8[:]) -> u8[32] {
    let first = hash(data);
    var h = IV;
    var msgblk: u8[64] = [0; 64];
    for i in 0..32 { msgblk[i] = first[i]; }
    msgblk[32] = 0x80;
    msgblk[62] = 0x01;
    blocks(h, msgblk);
    var out: u8[32] = [0; 32];
    for i in 0..8 { store_be32(out, i * 4, h[i]); }
    return out;
}

fn mac_start(key: u8[:]) -> Mac {
    var k: u8[64] = [0; 64];
    if key.len > 64 {
        let hk = hash(key);
        for i in 0..32 { k[i] = hk[i]; }
    } else {
        for i in 0..key.len { k[i] = key[i]; }
    }
    var ipad: u8[64] = [0; 64];
    var opad: u8[64] = [0; 64];
    for i in 0..64 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    var m: Mac = default<Mac>();
    init(m.inner);
    init(m.outer);
    update(m.inner, ipad);
    update(m.outer, opad);
    return m;
}

fn mac_update(m: Mac&, data: u8[:]) { update(m.inner, data); }

fn mac_finish(m: Mac&) -> u8[32] {
    let d = finish(m.inner);
    var outer = copy(m.outer);
    update(outer, d);
    return finish(outer);
}

fn hmac(key: u8[:], data: u8[:]) -> u8[32] {
    var m = mac_start(key);
    mac_update(m, data);
    return mac_finish(m);
}
