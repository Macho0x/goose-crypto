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

struct Ctx {
    h: u32[8],
    buf: u8[64],
    n: i64,
    bytes: u64,
}

fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

fn init(c: Ctx&) {
    c.h[0] = 0x6a09e667;
    c.h[1] = 0xbb67ae85;
    c.h[2] = 0x3c6ef372;
    c.h[3] = 0xa54ff53a;
    c.h[4] = 0x510e527f;
    c.h[5] = 0x9b05688c;
    c.h[6] = 0x1f83d9ab;
    c.h[7] = 0x5be0cd19;
    c.n = 0;
    c.bytes = 0;
}

fn compress(h: u32[8]&, buf: u8[:]) {
    var w: u32[64] = [0; 64];
    for i in 0..16 {
        let j = i * 4;
        let b0: u32 = buf[j];
        let b1: u32 = buf[j + 1];
        let b2: u32 = buf[j + 2];
        let b3: u32 = buf[j + 3];
        w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }
    for i in 16..64 {
        let x = w[i - 15];
        let y = w[i - 2];
        let s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        let s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];
    for i in 0..64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ (~e & g);
        let t1 = hh + s1 + ch + K[i] + w[i];
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
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

// finish consumes c.
fn finish(c: Ctx&) -> u8[32] {
    let n = c.n;
    c.buf[n] = 0x80;
    if n >= 56 {
        for i in (n + 1)..64 { c.buf[i] = 0; }
        compress(c.h, c.buf);
        for i in 0..56 { c.buf[i] = 0; }
    } else {
        for i in (n + 1)..56 { c.buf[i] = 0; }
    }
    store_be64(c.buf, 56, c.bytes << 3);
    compress(c.h, c.buf);
    var out: u8[32] = [0; 32];
    for i in 0..8 { store_be32(out, i * 4, c.h[i]); }
    return out;
}

fn hash(data: u8[:]) -> u8[32] {
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, data);
    return finish(c);
}

fn hmac(key: u8[:], data: u8[:]) -> u8[32] {
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
    if !hash("").eq_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") { return false; }
    if !hash("abc").eq_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") { return false; }
    let classic = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    if !hash(classic).eq_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") { return false; }
    var a1000: u8[1000] = ['a'; 1000];
    if !hash(a1000).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, a1000[..100]);
    update(c, a1000[100..700]);
    update(c, a1000[700..]);
    if !finish(c).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    let fox = "The quick brown fox jumps over the lazy dog";
    if !hmac("key", fox).eq_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") { return false; }
    var longk: u8[80] = ['k'; 80];
    if !hmac(longk, "data").eq_hex("db0b0964fe44311ab89fac8b72ed6f349c5b3bc574c92b87d92a3dbc5de20a8f") { return false; }
    return true;
}

fn ::main() {
    if sha256::self_check() { print("sha256 ok"); } else { print("sha256 FAIL"); exit(1); }
}
