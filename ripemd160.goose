// RIPEMD-160. Digests are 20 bytes, little-endian words.
// Bitcoin HASH160 is RIPEMD-160(SHA-256(data)). This file is only the hash.

import std;

namespace ripemd160;

struct Ctx {
    h: u32[5],
    buf: u8[64],
    n: i64,
    bytes: u64,
}

fn rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn load_le32(s: u8[:], i: i64) -> u32 {
    let c = s[i..i + 4];
    return c[0] | (c[1] as u32) << 8 | (c[2] as u32) << 16 | (c[3] as u32) << 24;
}

fn init(c: Ctx&) {
    c.h[0] = 0x67452301;
    c.h[1] = 0xefcdab89;
    c.h[2] = 0x98badcfe;
    c.h[3] = 0x10325476;
    c.h[4] = 0xc3d2e1f0;
    c.n = 0;
    c.bytes = 0;
}

fn compress(h: u32[5]&, buf: u8[:]) {
    assert(buf.len >= 64);
    var x: u32[16] = [0; 16];
    for i in 0..16 { x[i] = load_le32(buf, 4 * i); }
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]; var e = h[4];
    var aa = a; var bb = b; var cc = c; var dd = d; var ee = e;
    var t: u32 = 0;
    var tr: u32 = 0;
    t = rotl(a + (b ^ c ^ d) + x[0] + 0, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[5] + 0x50a28be6, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[1] + 0, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[14] + 0x50a28be6, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[2] + 0, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[7] + 0x50a28be6, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[3] + 0, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[0] + 0x50a28be6, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[4] + 0, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[9] + 0x50a28be6, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[5] + 0, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[2] + 0x50a28be6, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[6] + 0, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[11] + 0x50a28be6, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[7] + 0, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[4] + 0x50a28be6, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[8] + 0, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[13] + 0x50a28be6, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[9] + 0, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[6] + 0x50a28be6, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[10] + 0, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[15] + 0x50a28be6, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[11] + 0, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[8] + 0x50a28be6, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[12] + 0, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[1] + 0x50a28be6, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[13] + 0, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[10] + 0x50a28be6, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[14] + 0, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[3] + 0x50a28be6, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ c ^ d) + x[15] + 0, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ (cc | ~dd)) + x[12] + 0x50a28be6, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[7] + 0x5a827999, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[6] + 0x5c4dd124, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[4] + 0x5a827999, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[11] + 0x5c4dd124, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[13] + 0x5a827999, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[3] + 0x5c4dd124, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[1] + 0x5a827999, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[7] + 0x5c4dd124, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[10] + 0x5a827999, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[0] + 0x5c4dd124, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[6] + 0x5a827999, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[13] + 0x5c4dd124, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[15] + 0x5a827999, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[5] + 0x5c4dd124, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[3] + 0x5a827999, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[10] + 0x5c4dd124, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[12] + 0x5a827999, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[14] + 0x5c4dd124, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[0] + 0x5a827999, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[15] + 0x5c4dd124, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[9] + 0x5a827999, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[8] + 0x5c4dd124, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[5] + 0x5a827999, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[12] + 0x5c4dd124, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[2] + 0x5a827999, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[4] + 0x5c4dd124, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[14] + 0x5a827999, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[9] + 0x5c4dd124, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[11] + 0x5a827999, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[1] + 0x5c4dd124, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & c) | (~b & d)) + x[8] + 0x5a827999, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & dd) | (cc & ~dd)) + x[2] + 0x5c4dd124, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[3] + 0x6ed9eba1, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[15] + 0x6d703ef3, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[10] + 0x6ed9eba1, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[5] + 0x6d703ef3, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[14] + 0x6ed9eba1, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[1] + 0x6d703ef3, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[4] + 0x6ed9eba1, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[3] + 0x6d703ef3, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[9] + 0x6ed9eba1, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[7] + 0x6d703ef3, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[15] + 0x6ed9eba1, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[14] + 0x6d703ef3, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[8] + 0x6ed9eba1, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[6] + 0x6d703ef3, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[1] + 0x6ed9eba1, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[9] + 0x6d703ef3, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[2] + 0x6ed9eba1, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[11] + 0x6d703ef3, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[7] + 0x6ed9eba1, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[8] + 0x6d703ef3, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[0] + 0x6ed9eba1, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[12] + 0x6d703ef3, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[6] + 0x6ed9eba1, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[2] + 0x6d703ef3, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[13] + 0x6ed9eba1, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[10] + 0x6d703ef3, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[11] + 0x6ed9eba1, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[0] + 0x6d703ef3, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[5] + 0x6ed9eba1, 7) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[4] + 0x6d703ef3, 7) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b | ~c) ^ d) + x[12] + 0x6ed9eba1, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb | ~cc) ^ dd) + x[13] + 0x6d703ef3, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[1] + 0x8f1bbcdc, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[8] + 0x7a6d76e9, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[9] + 0x8f1bbcdc, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[6] + 0x7a6d76e9, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[11] + 0x8f1bbcdc, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[4] + 0x7a6d76e9, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[10] + 0x8f1bbcdc, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[1] + 0x7a6d76e9, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[0] + 0x8f1bbcdc, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[3] + 0x7a6d76e9, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[8] + 0x8f1bbcdc, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[11] + 0x7a6d76e9, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[12] + 0x8f1bbcdc, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[15] + 0x7a6d76e9, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[4] + 0x8f1bbcdc, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[0] + 0x7a6d76e9, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[13] + 0x8f1bbcdc, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[5] + 0x7a6d76e9, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[3] + 0x8f1bbcdc, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[12] + 0x7a6d76e9, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[7] + 0x8f1bbcdc, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[2] + 0x7a6d76e9, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[15] + 0x8f1bbcdc, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[13] + 0x7a6d76e9, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[14] + 0x8f1bbcdc, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[9] + 0x7a6d76e9, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[5] + 0x8f1bbcdc, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[7] + 0x7a6d76e9, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[6] + 0x8f1bbcdc, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[10] + 0x7a6d76e9, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + ((b & d) | (c & ~d)) + x[2] + 0x8f1bbcdc, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + ((bb & cc) | (~bb & dd)) + x[14] + 0x7a6d76e9, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[4] + 0xa953fd4e, 9) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[12] + 0, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[0] + 0xa953fd4e, 15) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[15] + 0, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[5] + 0xa953fd4e, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[10] + 0, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[9] + 0xa953fd4e, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[4] + 0, 9) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[7] + 0xa953fd4e, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[1] + 0, 12) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[12] + 0xa953fd4e, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[5] + 0, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[2] + 0xa953fd4e, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[8] + 0, 14) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[10] + 0xa953fd4e, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[7] + 0, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[14] + 0xa953fd4e, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[6] + 0, 8) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[1] + 0xa953fd4e, 12) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[2] + 0, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[3] + 0xa953fd4e, 13) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[13] + 0, 6) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[8] + 0xa953fd4e, 14) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[14] + 0, 5) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[11] + 0xa953fd4e, 11) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[0] + 0, 15) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[6] + 0xa953fd4e, 8) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[3] + 0, 13) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[15] + 0xa953fd4e, 5) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[9] + 0, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    t = rotl(a + (b ^ (c | ~d)) + x[13] + 0xa953fd4e, 6) + e;
    a = e; e = d; d = rotl(c, 10); c = b; b = t;
    tr = rotl(aa + (bb ^ cc ^ dd) + x[11] + 0, 11) + ee;
    aa = ee; ee = dd; dd = rotl(cc, 10); cc = bb; bb = tr;
    let fold = h[1] + c + dd;
    h[1] = h[2] + d + ee;
    h[2] = h[3] + e + aa;
    h[3] = h[4] + a + bb;
    h[4] = h[0] + b + cc;
    h[0] = fold;
}

fn update(c: Ctx&, data: u8[:]) {
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
        compress(c.h, c.buf);
        c.n = 0;
    }
    let whole = ((data.len - off) / 64) * 64;
    var i = 0;
    while i < whole {
        compress(c.h, data[off + i..off + i + 64]);
        i += 64;
    }
    off += whole;
    let tail = data.len - off;
    for i in 0..tail { c.buf[i] = data[off + i]; }
    c.n = tail;
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
