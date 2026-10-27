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

const ROTC: i64[24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: i64[24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

struct Ctx {
    st: u64[25],
    buf: u8[RATE],
    n: i64,
}

fn rotl(x: u64, n: i64) -> u64 { (x << n) | (x >> (64 - n)) }

fn permute(st: u64[25]&) {
    for round in 0..24 {
        var bc: u64[5] = [0; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
            var j = 0;
            while j < 25 {
                st[j + i] ^= t;
                j += 5;
            }
        }
        var t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let nxt = st[j];
            st[j] = rotl(t, ROTC[i]);
            t = nxt;
        }
        var j = 0;
        while j < 25 {
            var col: u64[5] = [0; 5];
            for i in 0..5 { col[i] = st[j + i]; }
            for i in 0..5 {
                st[j + i] ^= (~col[(i + 1) % 5]) & col[(i + 2) % 5];
            }
            j += 5;
        }
        st[0] ^= RNDC[round];
    }
}

fn xor_buf(st: u64[25]&, buf: u8[:]) {
    for i in 0..buf.len {
        st[i / 8] ^= (buf[i] as u64) << ((i % 8) * 8);
    }
}

fn init(c: Ctx&) {
    for i in 0..25 { c.st[i] = 0; }
    c.n = 0;
}

fn update(c: Ctx&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        let space = RATE - c.n;
        var take = data.len - off;
        if take > space { take = space; }
        for i in 0..take { c.buf[c.n + i] = data[off + i]; }
        c.n += take;
        off += take;
        if c.n == RATE {
            xor_buf(c.st, c.buf);
            permute(c.st);
            c.n = 0;
        }
    }
}

fn finish(c: Ctx&) -> u8[32] {
    c.buf[c.n] = 0x01;
    for i in (c.n + 1)..RATE { c.buf[i] = 0; }
    c.buf[RATE - 1] |= 0x80;
    xor_buf(c.st, c.buf);
    permute(c.st);
    var out: u8[32] = [0; 32];
    for i in 0..32 {
        out[i] = (c.st[i / 8] >> ((i % 8) * 8)) as! u8;
    }
    return out;
}

fn hash(data: u8[:]) -> u8[32] {
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
    if !hash("").eq_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") { return false; }
    if !hash("abc").eq_hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45") { return false; }
    var a136: u8[136] = ['a'; 136];
    if !hash(a136).eq_hex("a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e") { return false; }
    var a137: u8[137] = ['a'; 137];
    if !hash(a137).eq_hex("d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39") { return false; }
    var seq: u8[200] = [0; 200];
    for i in 0..200 { seq[i] = i as! u8; }
    if !hash(seq).eq_hex("bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890") { return false; }
    return true;
}

fn ::main() {
    if keccak256::self_check() { print("keccak256 ok"); } else { print("keccak256 FAIL"); exit(1); }
}
