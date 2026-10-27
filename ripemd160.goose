// RIPEMD-160. Digests are 20 bytes, little-endian words.
// Bitcoin HASH160 is RIPEMD-160(SHA-256(data)). This file is only the hash.

import std;

namespace ripemd160;

const NL: i64[80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const NR: i64[80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const SL: u32[80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SR: u32[80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

struct Ctx {
    h: u32[5],
    buf: u8[64],
    n: i64,
    bytes: u64,
}

fn rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn init(c: Ctx&) {
    c.h[0] = 0x67452301;
    c.h[1] = 0xefcdab89;
    c.h[2] = 0x98badcfe;
    c.h[3] = 0x10325476;
    c.h[4] = 0xc3d2e1f0;
    c.n = 0;
    c.bytes = 0;
}

fn f_left(round: i64, x: u32, y: u32, z: u32) -> u32 {
    if round == 0 { return x ^ y ^ z; }
    if round == 1 { return (x & y) | (~x & z); }
    if round == 2 { return (x | ~y) ^ z; }
    if round == 3 { return (x & z) | (y & ~z); }
    return x ^ (y | ~z);
}

fn f_right(round: i64, x: u32, y: u32, z: u32) -> u32 {
    if round == 0 { return x ^ (y | ~z); }
    if round == 1 { return (x & z) | (y & ~z); }
    if round == 2 { return (x | ~y) ^ z; }
    if round == 3 { return (x & y) | (~x & z); }
    return x ^ y ^ z;
}

fn k_left(round: i64) -> u32 {
    if round == 0 { return 0; }
    if round == 1 { return 0x5a827999; }
    if round == 2 { return 0x6ed9eba1; }
    if round == 3 { return 0x8f1bbcdc; }
    return 0xa953fd4e;
}

fn k_right(round: i64) -> u32 {
    if round == 0 { return 0x50a28be6; }
    if round == 1 { return 0x5c4dd124; }
    if round == 2 { return 0x6d703ef3; }
    if round == 3 { return 0x7a6d76e9; }
    return 0;
}

fn compress(h: u32[5]&, buf: u8[:]) {
    var x: u32[16] = [0; 16];
    for i in 0..16 {
        let j = i * 4;
        let b0: u32 = buf[j];
        let b1: u32 = buf[j + 1];
        let b2: u32 = buf[j + 2];
        let b3: u32 = buf[j + 3];
        x[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]; var e = h[4];
    var aa = a; var bb = b; var cc = c; var dd = d; var ee = e;
    for i in 0..80 {
        let round = i / 16;
        let t = rotl(a + f_left(round, b, c, d) + x[NL[i]] + k_left(round), SL[i]) + e;
        a = e; e = d; d = rotl(c, 10); c = b; b = t;
        let tr = rotl(aa + f_right(round, bb, cc, dd) + x[NR[i]] + k_right(round), SR[i]) + ee;
        aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    }
    let t = h[1] + c + dd;
    h[1] = h[2] + d + ee;
    h[2] = h[3] + e + aa;
    h[3] = h[4] + a + bb;
    h[4] = h[0] + b + cc;
    h[0] = t;
}

fn update(c: Ctx&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        let space = 64 - c.n;
        var take = data.len - off;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[off + i]; }
        c.n += take;
        off += take;
        c.bytes += take as u64;
        if c.n == 64 {
            compress(c.h, c.buf);
            c.n = 0;
        }
    }
}

fn store_le32(dst: u8[:], at: i64, v: u32) {
    dst[at] = v as! u8;
    dst[at + 1] = (v >> 8) as! u8;
    dst[at + 2] = (v >> 16) as! u8;
    dst[at + 3] = (v >> 24) as! u8;
}

// finish consumes c.
fn finish(c: Ctx&) -> u8[20] {
    let n = c.n;
    c.buf[n] = 0x80;
    if n >= 56 {
        for i in (n + 1)..64 { c.buf[i] = 0; }
        compress(c.h, c.buf);
        for i in 0..56 { c.buf[i] = 0; }
    } else {
        for i in (n + 1)..56 { c.buf[i] = 0; }
    }
    let bits = c.bytes << 3;
    for k in 0..8 { c.buf[56 + k] = (bits >> (k * 8)) as! u8; }
    compress(c.h, c.buf);
    var out: u8[20] = [0; 20];
    for i in 0..5 { store_le32(out, i * 4, c.h[i]); }
    return out;
}

fn hash(data: u8[:]) -> u8[20] {
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, data);
    return finish(c);
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
    if !hash("").eq_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31") { return false; }
    if !hash("abc").eq_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") { return false; }
    if !hash("abcdefghijklmnopqrstuvwxyz").eq_hex("f71c27109c692c1b56bbdceb5b9d2865b3708dbc") { return false; }
    let eighty = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    if !hash(eighty).eq_hex("9b752e45573d4b39f4dbd3323cab82bf63326bfb") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, "ab");
    update(c, "c");
    if !finish(c).eq_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") { return false; }
    return true;
}

fn ::main() {
    if ripemd160::self_check() { print("ripemd160 ok"); } else { print("ripemd160 FAIL"); exit(1); }
}
