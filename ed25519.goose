// Ed25519 (RFC 8032). Point arithmetic is on the same 2^255-19 field as
// X25519. Signatures are 64 bytes, R || S, with S reduced modulo L.
// Reduction mod L blends with a mask instead of branching on the scalar.

import std;
import x25519;

namespace ed25519;

type Fe = x25519::Fe;

struct Pt { x: Fe, y: Fe, z: Fe, t: Fe }

fn f0() -> Fe { return x25519::fe_zero(); }
fn f1() -> Fe { return x25519::fe_one(); }
fn fadd(a: Fe, b: Fe) -> Fe { return x25519::fe_add(a, b); }
fn fsub(a: Fe, b: Fe) -> Fe { return x25519::fe_sub(a, b); }
fn fmul(a: Fe, b: Fe) -> Fe { return x25519::fe_mul(a, b); }
fn fsqr(a: Fe) -> Fe { return x25519::fe_sqr(a); }
fn finv(a: Fe) -> Fe { return x25519::fe_inv(a); }
fn ffrom(b: u8[:]) -> Fe { return x25519::fe_from_bytes(b); }
fn fto(a: Fe) -> u8[32] { return x25519::fe_to_bytes(a); }

fn fsmall(n: u64) -> Fe {
    var f = f0();
    f.l[0] = n;
    return f;
}

fn fneg(a: Fe) -> Fe { return fsub(f0(), a); }

fn ed_d() -> Fe {
    return fmul(fneg(fsmall(121665)), finv(fsmall(121666)));
}

// a^((p+3)/8) = a^(2^252-2).
fn fpow2523(a: Fe) -> Fe {
    var z = a;
    for i in 1..251 { z = fmul(fsqr(z), a); }
    return fsqr(z);
}

fn sqrt_m1() -> Fe {
    // 2^((p-1)/4) = 2^(2^253-5). Bits 0..252 of that exponent are set except bit 2.
    let a = fsmall(2);
    var r = f1();
    for step in 0..253 {
        r = fsqr(r);
        if 252 - step != 2 { r = fmul(r, a); }
    }
    return r;
}

fn same(a: Fe, b: Fe) -> bool { return fto(a) == fto(b); }

fn pick_sign(x: Fe, sign: u64) -> Fe {
    let b = fto(x);
    if (b[0] & 1) != sign { return fneg(x); }
    return x;
}

fn recover_x(y: Fe, sign: u64, d: Fe) -> Fe, bool {
    let y2 = fsqr(y);
    let num = fsub(y2, f1());
    let den = fadd(fmul(d, y2), f1());
    let x2 = fmul(num, finv(den));
    let x = fpow2523(x2);
    let got = fsqr(x);
    if same(got, x2) { return pick_sign(x, sign), true; }
    if same(got, fneg(x2)) { return pick_sign(fmul(x, sqrt_m1()), sign), true; }
    return f0(), false;
}

fn pt_id() -> Pt { return Pt { f0(), f1(), f1(), f0() }; }

fn pt_add(p: Pt, q: Pt, d: Fe) -> Pt {
    let a = fmul(fsub(p.y, p.x), fsub(q.y, q.x));
    let b = fmul(fadd(p.y, p.x), fadd(q.y, q.x));
    let c = fmul(fmul(p.t, q.t), fadd(d, d));
    let zz = fmul(fadd(p.z, p.z), q.z);
    let e = fsub(b, a);
    let f = fsub(zz, c);
    let g = fadd(zz, c);
    let h = fadd(b, a);
    return Pt { fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h) };
}

fn pt_dbl(p: Pt) -> Pt {
    let a = fsqr(p.x);
    let b = fsqr(p.y);
    let c = fadd(fsqr(p.z), fsqr(p.z));
    let nega = fneg(a);
    let e = fsub(fsub(fsqr(fadd(p.x, p.y)), a), b);
    let g = fadd(nega, b);
    let f = fsub(g, c);
    let h = fsub(nega, b);
    return Pt { fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h) };
}

fn fe_select(a: Fe, b: Fe, bit: u64) -> Fe {
    let m: u64 = 0 - bit;
    var r = a;
    for i in 0..5 { r.l[i] = a.l[i] ^ ((a.l[i] ^ b.l[i]) & m); }
    return r;
}

fn pt_select(a: Pt, b: Pt, bit: u64) -> Pt {
    return Pt {
        fe_select(a.x, b.x, bit),
        fe_select(a.y, b.y, bit),
        fe_select(a.z, b.z, bit),
        fe_select(a.t, b.t, bit),
    };
}

fn scalar_bit(s: u8[:], i: i64) -> u64 {
    let byte: u64 = s[i / 8];
    return (byte >> (i % 8)) & 1;
}

fn pt_mul(p: Pt, s: u8[:], d: Fe) -> Pt {
    var acc = pt_id();
    for step in 0..256 {
        acc = pt_dbl(acc);
        let added = pt_add(acc, p, d);
        acc = pt_select(acc, added, scalar_bit(s, 255 - step));
    }
    return acc;
}

fn encode(p: Pt) -> u8[32] {
    let zinv = finv(p.z);
    let x = fmul(p.x, zinv);
    let y = fmul(p.y, zinv);
    var o = fto(y);
    let xb = fto(x);
    o[31] |= (xb[0] & 1) << 7;
    return o;
}

fn decode(b: u8[:], d: Fe) -> Pt, bool {
    if b.len != 32 { return pt_id(), false; }
    let sign: u64 = b[31] >> 7;
    let y = ffrom(b);
    var canon: u8[32] = [0; 32];
    for i in 0..32 { canon[i] = b[i]; }
    canon[31] &= 127;
    if fto(y) != canon { return pt_id(), false; }
    let x, ok = recover_x(y, sign, d);
    if !ok { return pt_id(), false; }
    return Pt { x, y, f1(), fmul(x, y) }, true;
}

fn base(d: Fe) -> Pt, bool {
    let y = fmul(fsmall(4), finv(fsmall(5)));
    let x, ok = recover_x(y, 0, d);
    if !ok { return pt_id(), false; }
    return Pt { x, y, f1(), fmul(x, y) }, true;
}

// --- SHA-512 (FIPS 180-4). Digests are 64 bytes. ---

const K512: u64[80] = [
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

struct Sha {
    h: u64[8],
    buf: u8[128],
    n: i64,
    bytes: u64,
}

fn rotr64(x: u64, n: u64) -> u64 { (x >> n) | (x << (64 - n)) }

fn sha_init(c: Sha&) {
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

fn sha_compress(h: u64[8]&, buf: u8[:]) {
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
        let s0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
        let s1 = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3];
    var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7];
    for i in 0..80 {
        let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        let ch = (e & f) ^ (~e & g);
        let t1 = hh + s1 + ch + K512[i] + w[i];
        let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

fn sha_update(c: Sha&, data: u8[:]) {
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
            sha_compress(c.h, c.buf);
            c.n = 0;
        }
    }
}

fn sha_finish(c: Sha&) -> u8[64] {
    let n = c.n;
    c.buf[n] = 0x80;
    if n >= 112 {
        for i in (n + 1)..128 { c.buf[i] = 0; }
        sha_compress(c.h, c.buf);
        for i in 0..112 { c.buf[i] = 0; }
    } else {
        for i in (n + 1)..112 { c.buf[i] = 0; }
    }
    let bits = c.bytes << 3;
    for k in 0..8 { c.buf[112 + k] = 0; }
    for k in 0..8 { c.buf[120 + k] = (bits >> ((7 - k) * 8)) as! u8; }
    sha_compress(c.h, c.buf);
    var out: u8[64] = [0; 64];
    for i in 0..8 {
        let v = c.h[i];
        for k in 0..8 { out[i * 8 + k] = (v >> ((7 - k) * 8)) as! u8; }
    }
    return out;
}

fn sha512(data: u8[:]) -> u8[64] {
    var c: Sha = default<Sha>();
    sha_init(c);
    sha_update(c, data);
    return sha_finish(c);
}

fn sha512_2(a: u8[:], b: u8[:]) -> u8[64] {
    var c: Sha = default<Sha>();
    sha_init(c);
    sha_update(c, a);
    sha_update(c, b);
    return sha_finish(c);
}

fn sha512_3(a: u8[:], b: u8[:], c: u8[:]) -> u8[64] {
    var s: Sha = default<Sha>();
    sha_init(s);
    sha_update(s, a);
    sha_update(s, b);
    sha_update(s, c);
    return sha_finish(s);
}

// --- scalars mod L ---

fn order() -> u32[9] {
    return [0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0, 0, 0, 0x10000000, 0];
}

fn ct_lt(a: u64, b: u64) -> u64 {
    let z = a - b;
    (z ^ ((a ^ b) & (b ^ z))) >> 63
}

fn sc_gte_mask(a: u32[9], b: u32[9]) -> u32 {
    var gt: u64 = 0;
    var lt: u64 = 0;
    for i in 0..9 {
        let j = 8 - i;
        let ai: u64 = a[j];
        let bi: u64 = b[j];
        let fresh = 1 - (gt | lt);
        gt |= ct_lt(bi, ai) & fresh;
        lt |= ct_lt(ai, bi) & fresh;
    }
    return (1 - lt) as! u32;
}

fn sc_gte(a: u32[9], b: u32[9]) -> bool { sc_gte_mask(a, b) == 1 }

fn sc_sub(a: u32[9], b: u32[9]) -> u32[9] {
    var r: u32[9] = [0; 9];
    var borrow: u64 = 0;
    for i in 0..9 {
        let bi = b[i] + borrow;
        let ai: u64 = a[i];
        let under = ct_lt(ai, bi);
        let plain = ai - bi;
        let wrapped = ai + 0x100000000 - bi;
        let m = 0 - under;
        r[i] = ((plain & ~m) | (wrapped & m)) as! u32;
        borrow = under;
    }
    return r;
}

fn select9(a: u32[9], b: u32[9], bit: u32) -> u32[9] {
    let m: u32 = 0 - bit;
    var r = a;
    for i in 0..9 { r[i] = a[i] ^ ((a[i] ^ b[i]) & m); }
    return r;
}

fn sc_reduce(w: u32[16]) -> u32[8] {
    var r: u32[9] = [0; 9];
    let n = order();
    for bit in 0..512 {
        let idx = 511 - bit;
        let limb = w[idx / 32];
        let b = (limb >> (idx % 32)) & 1;
        var carry = b;
        for i in 0..9 {
            let next = r[i] >> 31;
            r[i] = (r[i] << 1) | carry;
            carry = next;
        }
        r = select9(r, sc_sub(r, n), sc_gte_mask(r, n));
    }
    var out: u32[8] = [0; 8];
    for i in 0..8 { out[i] = r[i]; }
    return out;
}

fn sc_mul(a: u32[8], b: u32[8]) -> u32[8] {
    var w: u32[16] = [0; 16];
    for i in 0..8 {
        var carry: u64 = 0;
        for j in 0..8 {
            let ai: u64 = a[i];
            let bj: u64 = b[j];
            let uv = w[i + j] + ai * bj + carry;
            w[i + j] = uv as! u32;
            carry = uv >> 32;
        }
        w[i + 8] = carry as! u32;
    }
    return sc_reduce(w);
}

fn sc_add(a: u32[8], b: u32[8]) -> u32[8] {
    var w: u32[16] = [0; 16];
    var c: u64 = 0;
    for i in 0..8 {
        let ai: u64 = a[i];
        let bi: u64 = b[i];
        let t = ai + bi + c;
        w[i] = t as! u32;
        c = t >> 32;
    }
    w[8] = c as! u32;
    return sc_reduce(w);
}

fn sc_from32(b: u8[:]) -> u32[8] {
    var s: u32[8] = [0; 8];
    for i in 0..8 {
        let j = i * 4;
        let b0: u32 = b[j];
        let b1: u32 = b[j + 1];
        let b2: u32 = b[j + 2];
        let b3: u32 = b[j + 3];
        s[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    return s;
}

fn sc_from64(b: u8[:]) -> u32[8] {
    var w: u32[16] = [0; 16];
    for i in 0..16 {
        let j = i * 4;
        let b0: u32 = b[j];
        let b1: u32 = b[j + 1];
        let b2: u32 = b[j + 2];
        let b3: u32 = b[j + 3];
        w[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    return sc_reduce(w);
}

fn sc_to_bytes(s: u32[8]) -> u8[32] {
    var o: u8[32] = [0; 32];
    for i in 0..8 {
        let v = s[i];
        o[i * 4] = v as! u8;
        o[i * 4 + 1] = (v >> 8) as! u8;
        o[i * 4 + 2] = (v >> 16) as! u8;
        o[i * 4 + 3] = (v >> 24) as! u8;
    }
    return o;
}

fn sc_below_l(b: u8[:]) -> bool {
    var a: u32[9] = [0; 9];
    let s = sc_from32(b);
    for i in 0..8 { a[i] = s[i]; }
    return !sc_gte(a, order());
}

fn clamp_scalar(h: u8[:], out: u8[:]) {
    for i in 0..32 { out[i] = h[i]; }
    out[0] &= 248;
    out[31] &= 63;
    out[31] |= 64;
}

fn public_key(seed: u8[:]) -> u8[32], bool {
    if seed.len != 32 { return [0; 32], false; }
    let h = sha512(seed);
    var a: u8[32] = [0; 32];
    clamp_scalar(h, a);
    let d = ed_d();
    let bp, ok = base(d);
    if !ok { return [0; 32], false; }
    return encode(pt_mul(bp, a, d)), true;
}

fn sign(seed: u8[:], msg: u8[:]) -> u8[64], bool {
    if seed.len != 32 { return [0; 64], false; }
    let h = sha512(seed);
    var a: u8[32] = [0; 32];
    clamp_scalar(h, a);
    let d = ed_d();
    let bp, ok = base(d);
    if !ok { return [0; 64], false; }
    let pub = encode(pt_mul(bp, a, d));
    let r_hash = sha512_2(h[32..64], msg);
    let r = sc_to_bytes(sc_from64(r_hash));
    let rr = encode(pt_mul(bp, r, d));
    let k_hash = sha512_3(rr, pub, msg);
    let k = sc_from64(k_hash);
    let s = sc_add(sc_from32(r), sc_mul(k, sc_from32(a)));
    let sb = sc_to_bytes(s);
    var sig: u8[64] = [0; 64];
    for i in 0..32 {
        sig[i] = rr[i];
        sig[32 + i] = sb[i];
    }
    return sig, true;
}

fn verify(public: u8[:], msg: u8[:], sig: u8[:]) -> bool {
    if public.len != 32 || sig.len != 64 { return false; }
    if !sc_below_l(sig[32..64]) { return false; }
    let d = ed_d();
    let a, aok = decode(public, d);
    let r, rok = decode(sig[..32], d);
    if !aok || !rok { return false; }
    let bp, bok = base(d);
    if !bok { return false; }
    let k_hash = sha512_3(sig[..32], public, msg);
    let k = sc_to_bytes(sc_from64(k_hash));
    let left = encode(pt_mul(bp, sig[32..64], d));
    let right = encode(pt_add(r, pt_mul(a, k, d), d));
    return left == right;
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
    if !sha512("").eq_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") { return false; }
    if !sha512("abc").eq_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") { return false; }
    let d = ed_d();
    let bp, bok = base(d);
    if !bok || !encode(bp).eq_hex("5866666666666666666666666666666666666666666666666666666666666666") { return false; }
    var one: u8[32] = [0; 32];
    one[0] = 1;
    if encode(pt_mul(bp, one, d)) != encode(bp) { return false; }
    var seed: u8[32] = [0; 32];
    unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed);
    let pk, ok = public_key(seed);
    if !ok || !pk.eq_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") { return false; }
    let sig, sok = sign(seed, "");
    if !sok || !sig.eq_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b") { return false; }
    if !verify(pk, "", sig) { return false; }
    var seed2: u8[32] = [0; 32];
    unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed2);
    let pk2, ok2 = public_key(seed2);
    if !ok2 || !pk2.eq_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c") { return false; }
    var msg: u8[1] = [0x72];
    let sig2, sok2 = sign(seed2, msg);
    if !sok2 || !sig2.eq_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00") { return false; }
    if !verify(pk2, msg, sig2) { return false; }
    sig2[0] ^= 1;
    if verify(pk2, msg, sig2) { return false; }
    return true;
}

fn ::main() {
    if ed25519::self_check() { print("ed25519 ok"); } else { print("ed25519 FAIL"); exit(1); }
}
