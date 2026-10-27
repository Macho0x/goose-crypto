// IETF ChaCha20-Poly1305 (RFC 8439): 32-byte key, 12-byte nonce,
// ciphertext followed by a 16-byte tag. Also the raw ChaCha20 stream
// and Poly1305 MAC those are built from.

import std;

namespace chacha20poly1305;

fn rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn le32(b: u8[:], i: i64) -> u32 {
    let b0: u32 = b[i];
    let b1: u32 = b[i + 1];
    let b2: u32 = b[i + 2];
    let b3: u32 = b[i + 3];
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

fn put_le32(b: u8[:], i: i64, v: u32) {
    b[i] = v as! u8;
    b[i + 1] = (v >> 8) as! u8;
    b[i + 2] = (v >> 16) as! u8;
    b[i + 3] = (v >> 24) as! u8;
}

fn put_le64(b: u8[:], i: i64, v: u64) {
    var x = v;
    for k in 0..8 {
        b[i + k] = x as! u8;
        x = x >> 8;
    }
}

fn quarter(s: u32[16]&, a: i64, b: i64, c: i64, d: i64) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 7);
}

fn chacha_block(key: u8[:], nonce: u8[:], counter: u32) -> u8[64] {
    var s: u32[16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        le32(key, 0), le32(key, 4), le32(key, 8), le32(key, 12),
        le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28),
        counter, le32(nonce, 0), le32(nonce, 4), le32(nonce, 8),
    ];
    var w = s;
    for i in 0..10 {
        quarter(w, 0, 4, 8, 12);
        quarter(w, 1, 5, 9, 13);
        quarter(w, 2, 6, 10, 14);
        quarter(w, 3, 7, 11, 15);
        quarter(w, 0, 5, 10, 15);
        quarter(w, 1, 6, 11, 12);
        quarter(w, 2, 7, 8, 13);
        quarter(w, 3, 4, 9, 14);
    }
    var out: u8[64] = [0; 64];
    for i in 0..16 { put_le32(out, i * 4, w[i] + s[i]); }
    return out;
}

// Xors data with the ChaCha20 keystream into out. counter is the first
// block counter (1 for the AEAD payload, 0 for the one-time Poly1305 key).
fn chacha20(key: u8[:], nonce: u8[:], counter: u32, data: u8[:], out: u8[:]) -> bool {
    if key.len != 32 || nonce.len != 12 || out.len < data.len { return false; }
    var off = 0;
    var ctr = counter;
    while off < data.len {
        let ks = chacha_block(key, nonce, ctr);
        var n = data.len - off;
        if n > 64 { n = 64; }
        for i in 0..n { out[off + i] = data[off + i] ^ ks[i]; }
        off += n;
        ctr += 1;
    }
    return true;
}

const MASK26: u32 = 0x3ffffff;

struct Poly {
    h: u32[5],
    r: u32[5],
    s: u32[4],
    buf: u8[16],
    n: i64,
}

fn poly_init(p: Poly&, key: u8[:]) {
    for i in 0..5 { p.h[i] = 0; }
    var t0: u64 = le32(key, 0) & 0x0fffffff;
    var t1: u64 = le32(key, 4) & 0x0ffffffc;
    let t2: u64 = le32(key, 8) & 0x0ffffffc;
    let t3: u64 = le32(key, 12) & 0x0ffffffc;
    p.r[0] = (t0 & MASK26) as! u32;
    t0 = (t0 >> 26) | (t1 << 6);
    p.r[1] = (t0 & MASK26) as! u32;
    t0 = (t0 >> 26) | (t2 << 12);
    p.r[2] = (t0 & MASK26) as! u32;
    t0 = (t0 >> 26) | (t3 << 18);
    p.r[3] = (t0 & MASK26) as! u32;
    t0 = t0 >> 26;
    p.r[4] = (t0 & MASK26) as! u32;
    for i in 0..4 { p.s[i] = le32(key, 16 + i * 4); }
    p.n = 0;
}

fn poly_absorb(p: Poly&, m: u8[:], hibit: u32) {
    let m0 = le32(m, 0);
    let m1 = le32(m, 3);
    let m2 = le32(m, 6);
    let m3 = le32(m, 9);
    let m4 = le32(m, 12);
    p.h[0] += m0 & MASK26;
    p.h[1] += (m1 >> 2) & MASK26;
    p.h[2] += (m2 >> 4) & MASK26;
    p.h[3] += (m3 >> 6) & MASK26;
    p.h[4] += (m4 >> 8) | hibit;
    let r0 = p.r[0] as u64;
    let r1 = p.r[1] as u64;
    let r2 = p.r[2] as u64;
    let r3 = p.r[3] as u64;
    let r4 = p.r[4] as u64;
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;
    let h0 = p.h[0] as u64;
    let h1 = p.h[1] as u64;
    let h2 = p.h[2] as u64;
    let h3 = p.h[3] as u64;
    let h4 = p.h[4] as u64;
    var d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    let m26: u64 = MASK26;
    var c = d0 >> 26; p.h[0] = (d0 & m26) as! u32; d1 += c;
    c = d1 >> 26; p.h[1] = (d1 & m26) as! u32; d2 += c;
    c = d2 >> 26; p.h[2] = (d2 & m26) as! u32; d3 += c;
    c = d3 >> 26; p.h[3] = (d3 & m26) as! u32; d4 += c;
    c = d4 >> 26; p.h[4] = (d4 & m26) as! u32;
    let h0b = p.h[0] + c * 5;
    c = h0b >> 26;
    p.h[0] = (h0b & m26) as! u32;
    p.h[1] += c as! u32;
}

fn poly_update(p: Poly&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        let space = 16 - p.n;
        var take = data.len - off;
        if take > space { take = space; }
        for i in 0..take { p.buf[p.n + i] = data[off + i]; }
        p.n += take;
        off += take;
        if p.n == 16 {
            poly_absorb(p, p.buf, 1 << 24);
            p.n = 0;
        }
    }
}

fn poly_tag(p: Poly&) -> u8[16] {
    var h0 = p.h[0];
    var h1 = p.h[1];
    var h2 = p.h[2];
    var h3 = p.h[3];
    var h4 = p.h[4];
    var c = h1 >> 26; h1 &= MASK26; h2 += c;
    c = h2 >> 26; h2 &= MASK26; h3 += c;
    c = h3 >> 26; h3 &= MASK26; h4 += c;
    c = h4 >> 26; h4 &= MASK26; h0 += c * 5;
    c = h0 >> 26; h0 &= MASK26; h1 += c;
    var g0 = h0 + 5; c = g0 >> 26; g0 &= MASK26;
    var g1 = h1 + c; c = g1 >> 26; g1 &= MASK26;
    var g2 = h2 + c; c = g2 >> 26; g2 &= MASK26;
    var g3 = h3 + c; c = g3 >> 26; g3 &= MASK26;
    let g4: u32 = h4 + c - (1 << 26);
    let mask: u32 = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);
    let hw0 = h0 as u64;
    let hw1 = h1 as u64;
    let hw2 = h2 as u64;
    let hw3 = h3 as u64;
    let hw4 = h4 as u64;
    let t0 = (hw0 | (hw1 << 26)) & 0xffffffff;
    let t1 = ((hw1 >> 6) | (hw2 << 20)) & 0xffffffff;
    let t2 = ((hw2 >> 12) | (hw3 << 14)) & 0xffffffff;
    let t3 = ((hw3 >> 18) | (hw4 << 8)) & 0xffffffff;
    let s0: u64 = p.s[0];
    let s1w: u64 = p.s[1];
    let s2w: u64 = p.s[2];
    let s3w: u64 = p.s[3];
    var f = t0 + s0;
    var out: u8[16] = [0; 16];
    put_le32(out, 0, f as! u32);
    f = t1 + s1w + (f >> 32);
    put_le32(out, 4, f as! u32);
    f = t2 + s2w + (f >> 32);
    put_le32(out, 8, f as! u32);
    f = t3 + s3w + (f >> 32);
    put_le32(out, 12, f as! u32);
    return out;
}

fn poly_final(p: Poly&) -> u8[16] {
    if p.n > 0 {
        p.buf[p.n] = 1;
        for i in (p.n + 1)..16 { p.buf[i] = 0; }
        poly_absorb(p, p.buf, 0);
    }
    return poly_tag(p);
}

fn poly1305(key: u8[:], data: u8[:]) -> u8[16] {
    var p: Poly = default<Poly>();
    poly_init(p, key);
    poly_update(p, data);
    return poly_final(p);
}

fn pad16(p: Poly&, n: i64) {
    let rem = n % 16;
    if rem != 0 {
        var z: u8[16] = [0; 16];
        poly_update(p, z[..16 - rem]);
    }
}

fn aead_tag(key: u8[:], nonce: u8[:], aad: u8[:], ct: u8[:]) -> u8[16] {
    let otk = chacha_block(key, nonce, 0);
    var p: Poly = default<Poly>();
    poly_init(p, otk[..32]);
    poly_update(p, aad);
    pad16(p, aad.len);
    poly_update(p, ct);
    pad16(p, ct.len);
    var lens: u8[16] = [0; 16];
    put_le64(lens, 0, aad.len as u64);
    put_le64(lens, 8, ct.len as u64);
    poly_update(p, lens);
    return poly_final(p);
}

fn ct_eq(a: u8[:], b: u8[:]) -> bool {
    if a.len != b.len { return false; }
    var d: u8 = 0;
    for i in 0..a.len { d |= a[i] ^ b[i]; }
    return d == 0;
}

// Appends ciphertext || tag to out.
fn seal(key: u8[:], nonce: u8[:], aad: u8[:], pt: u8[:], out: u8[>..]&) -> bool {
    if key.len != 32 || nonce.len != 12 { return false; }
    let start = out.len;
    out.resize(start + pt.len + 16, 0);
    if pt.len > 0 { chacha20(key, nonce, 1, pt, out[start..start + pt.len]); }
    let tag = aead_tag(key, nonce, aad, out[start..start + pt.len]);
    for i in 0..16 { out[start + pt.len + i] = tag[i]; }
    return true;
}

// Appends plaintext to out. Returns false, and writes nothing, if the tag
// does not match.
fn open(key: u8[:], nonce: u8[:], aad: u8[:], sealed: u8[:], out: u8[>..]&) -> bool {
    if key.len != 32 || nonce.len != 12 || sealed.len < 16 { return false; }
    let ct = sealed[..^16];
    let tag = sealed[^16..];
    let expect = aead_tag(key, nonce, aad, ct);
    if !ct_eq(tag, expect) { return false; }
    let start = out.len;
    if ct.len > 0 {
        out.resize(start + ct.len, 0);
        chacha20(key, nonce, 1, ct, out[start..]);
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
    for i in 0..out.len {
        out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
    }
}

fn self_check() -> bool {
    let pkey = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
    var pk: u8[32] = [0; 32];
    unhex(pkey, pk);
    let msg = "Cryptographic Forum Research Group";
    if !poly1305(pk, msg).eq_hex("a8061dc1305136c6c22b8baf0c0127a9") { return false; }
    if !poly1305(pk, "").eq_hex("0103808afb0db2fd4abff6af4149f51b") { return false; }

    var key: u8[32] = [0; 32];
    for i in 0..32 { key[i] = i as! u8; }
    var nonce: u8[12] = [0; 12];
    unhex("000000090000004a00000000", nonce);
    var zeros: u8[64] = [0; 64];
    var ks: u8[64] = [0; 64];
    if !chacha20(key, nonce, 1, zeros, ks) { return false; }
    if !ks.eq_hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e") { return false; }

    var akey: u8[32] = [0; 32];
    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", akey);
    var an: u8[12] = [0; 12];
    unhex("070000004041424344454647", an);
    var aad: u8[12] = [0; 12];
    unhex("50515253c0c1c2c3c4c5c6c7", aad);
    let pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var sealed: u8[>..] = [];
    if !seal(akey, an, aad, pt, sealed) { return false; }
    if !sealed.eq_hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691") { return false; }
    var opened: u8[>..] = [];
    if !open(akey, an, aad, sealed, opened) { return false; }
    if opened != pt { return false; }
    sealed[10] ^= 1;
    var rejected: u8[>..] = [];
    if open(akey, an, aad, sealed, rejected) { return false; }
    if rejected.len != 0 { return false; }
    return true;
}

fn ::main() {
    if chacha20poly1305::self_check() { print("chacha20poly1305 ok"); }
    else { print("chacha20poly1305 FAIL"); exit(1); }
}
