// Keccak-256, the original Keccak submission (rate 1088, capacity 512,
// domain byte 0x01). This is the hash Ethereum calls keccak256, not
// NIST SHA3-256, which uses domain byte 0x06.

import std;

namespace keccak256;

const RATE = 136;

const RNDC: u64[24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

struct Ctx {
    st: u64[25],
    buf: u8[RATE],
    n: i64,
}

inline fn rotl(x: u64, n: i64) -> u64 { (x << n) | (x >> (64 - n)) }

inline fn chi(st: u64[25]&, o: i64) {
    let a = st[o];
    let b = st[o + 1];
    let c = st[o + 2];
    let d = st[o + 3];
    let e = st[o + 4];
    st[o] ^= (~b) & c;
    st[o + 1] ^= (~c) & d;
    st[o + 2] ^= (~d) & e;
    st[o + 3] ^= (~e) & a;
    st[o + 4] ^= (~a) & b;
}

inline fn step(st: u64[25]&, rc: u64) {
    let b0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
    let b1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
    let b2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
    let b3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
    let b4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
    let t0 = b4 ^ rotl(b1, 1);
    let t1 = b0 ^ rotl(b2, 1);
    let t2 = b1 ^ rotl(b3, 1);
    let t3 = b2 ^ rotl(b4, 1);
    let t4 = b3 ^ rotl(b0, 1);
    st[0] ^= t0;
    st[5] ^= t0;
    st[10] ^= t0;
    st[15] ^= t0;
    st[20] ^= t0;
    st[1] ^= t1;
    st[6] ^= t1;
    st[11] ^= t1;
    st[16] ^= t1;
    st[21] ^= t1;
    st[2] ^= t2;
    st[7] ^= t2;
    st[12] ^= t2;
    st[17] ^= t2;
    st[22] ^= t2;
    st[3] ^= t3;
    st[8] ^= t3;
    st[13] ^= t3;
    st[18] ^= t3;
    st[23] ^= t3;
    st[4] ^= t4;
    st[9] ^= t4;
    st[14] ^= t4;
    st[19] ^= t4;
    st[24] ^= t4;
    var t = st[1];
    var n = st[10];
    st[10] = rotl(t, 1);
    t = n;
    n = st[7];
    st[7] = rotl(t, 3);
    t = n;
    n = st[11];
    st[11] = rotl(t, 6);
    t = n;
    n = st[17];
    st[17] = rotl(t, 10);
    t = n;
    n = st[18];
    st[18] = rotl(t, 15);
    t = n;
    n = st[3];
    st[3] = rotl(t, 21);
    t = n;
    n = st[5];
    st[5] = rotl(t, 28);
    t = n;
    n = st[16];
    st[16] = rotl(t, 36);
    t = n;
    n = st[8];
    st[8] = rotl(t, 45);
    t = n;
    n = st[21];
    st[21] = rotl(t, 55);
    t = n;
    n = st[24];
    st[24] = rotl(t, 2);
    t = n;
    n = st[4];
    st[4] = rotl(t, 14);
    t = n;
    n = st[15];
    st[15] = rotl(t, 27);
    t = n;
    n = st[23];
    st[23] = rotl(t, 41);
    t = n;
    n = st[19];
    st[19] = rotl(t, 56);
    t = n;
    n = st[13];
    st[13] = rotl(t, 8);
    t = n;
    n = st[12];
    st[12] = rotl(t, 25);
    t = n;
    n = st[2];
    st[2] = rotl(t, 43);
    t = n;
    n = st[20];
    st[20] = rotl(t, 62);
    t = n;
    n = st[14];
    st[14] = rotl(t, 18);
    t = n;
    n = st[22];
    st[22] = rotl(t, 39);
    t = n;
    n = st[9];
    st[9] = rotl(t, 61);
    t = n;
    n = st[6];
    st[6] = rotl(t, 20);
    t = n;
    n = st[1];
    st[1] = rotl(t, 44);
    chi(st, 0);
    chi(st, 5);
    chi(st, 10);
    chi(st, 15);
    chi(st, 20);
    st[0] ^= rc;
}

inline fn permute(st: u64[25]&) {
    for round in 0..24 { step(st, RNDC[round]); }
}

fn xor_byte(st: u64[25]&, i: i64, b: u8) {
    let x: u64 = b;
    st[i / 8] ^= x << ((i % 8) * 8);
}

fn xor_lane(st: u64[25]&, buf: u8[:], lane: i64) {
    let c = buf[lane * 8..lane * 8 + 8];
    let w = c[0] | (c[1] as u64) << 8 | (c[2] as u64) << 16 | (c[3] as u64) << 24 |
        (c[4] as u64) << 32 | (c[5] as u64) << 40 | (c[6] as u64) << 48 | (c[7] as u64) << 56;
    st[lane] ^= w;
}

// A full rate. The lane index is a 0..17 counter, so the loads carry no check.
inline fn xor_rate(st: u64[25]&, buf: u8[:]) {
    assert(buf.len >= RATE);
    for lane in 0..17 {
        let c = buf[(lane * 8)..(lane * 8 + 8)];
        let w = c[0] | (c[1] as u64) << 8 | (c[2] as u64) << 16 | (c[3] as u64) << 24 |
            (c[4] as u64) << 32 | (c[5] as u64) << 40 | (c[6] as u64) << 48 | (c[7] as u64) << 56;
        st[lane] ^= w;
    }
}

fn xor_buf(st: u64[25]&, buf: u8[:]) {
    assert(buf.len <= RATE);
    let lanes = buf.len / 8;
    for lane in 0..lanes { xor_lane(st, buf, lane); }
    for i in (lanes * 8)..buf.len { xor_byte(st, i, buf[i]); }
}

fn squeeze(st: u64[25]&) -> u8[32] {
    var out: u8[32] = [0; 32];
    for i in 0..32 {
        out[i] = (st[i / 8] >> ((i % 8) * 8)) as! u8;
    }
    return out;
}

fn init(c: Ctx&) {
    for i in 0..25 { c.st[i] = 0; }
    c.n = 0;
}

fn update(c: Ctx&, data: u8[:]) {
    var off = 0;
    if c.n > 0 {
        let space = RATE - c.n;
        var take = data.len;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[i]; }
        c.n += take;
        off = take;
        if c.n < RATE { return; }
        xor_rate(c.st, c.buf);
        permute(c.st);
        c.n = 0;
    }
    let whole = ((data.len - off) / RATE) * RATE;
    var i = 0;
    while i < whole {
        xor_rate(c.st, data[off + i..off + i + RATE]);
        permute(c.st);
        i += RATE;
    }
    off += whole;
    let tail = data.len - off;
    for i in 0..tail { c.buf[i] = data[off + i]; }
    c.n = tail;
}

fn finish(c: Ctx&) -> u8[32] {
    c.buf[c.n] = 0x01;
    for i in (c.n + 1)..RATE { c.buf[i] = 0; }
    c.buf[RATE - 1] |= 0x80;
    xor_buf(c.st, c.buf);
    permute(c.st);
    return squeeze(c.st);
}

fn hash_short(data: u8[:]) -> u8[32] {
    var st: u64[25] = [0; 25];
    xor_buf(st, data);
    xor_byte(st, data.len, 0x01);
    xor_byte(st, RATE - 1, 0x80);
    permute(st);
    return squeeze(st);
}

fn hash(data: u8[:]) -> u8[32] {
    if data.len < RATE { return hash_short(data); }
    var c: Ctx = default<Ctx>();
    update(c, data);
    return finish(c);
}
