// Ed25519 (RFC 8032). Point arithmetic is on the same 2^255-19 field as
// X25519. Signatures are 64 bytes, R || S, with S reduced modulo L.
// Reduction mod L blends with a mask instead of branching on the scalar.
// Scalar multiplication is a 4-bit window, and the digit is chosen with a mask.

import std;
import x25519;
import sha512;

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
    Fe { [0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029, 0x739c663a03cbb, 0x52036cee2b6ff] }
}

fn fsqn(a: Fe, n: i64) -> Fe {
    var r = a;
    for i in 0..n { r = fsqr(r); }
    return r;
}

// a^((p+3)/8) = a^(2^252-2).
fn fpow2523(a: Fe) -> Fe {
    let o1 = a;
    let o2 = fmul(fsqr(o1), o1);
    let o4 = fmul(fsqn(o2, 2), o2);
    let o8 = fmul(fsqn(o4, 4), o4);
    let o16 = fmul(fsqn(o8, 8), o8);
    let o32 = fmul(fsqn(o16, 16), o16);
    let o64 = fmul(fsqn(o32, 32), o32);
    let o128 = fmul(fsqn(o64, 64), o64);
    var r = o128;
    r = fmul(fsqn(r, 64), o64);
    r = fmul(fsqn(r, 32), o32);
    r = fmul(fsqn(r, 16), o16);
    r = fmul(fsqn(r, 8), o8);
    r = fmul(fsqn(r, 2), o2);
    r = fmul(fsqr(r), o1);
    return fsqr(r);
}

fn sqrt_m1() -> Fe {
    Fe { [0x61b274a0ea0b0, 0xd5a5fc8f189d, 0x7ef5e9cbd0c60, 0x78595a6804c9e, 0x2b8324804fc1d] }
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

fn pt_lookup(tab: Pt[:], nib: u64) -> Pt {
    var r = tab[0];
    for i in 1..16 {
        let diff = nib ^ (i as u64);
        let nz = (diff | (0 - diff)) >> 63;
        r = pt_select(r, tab[i], 1 - nz);
    }
    return r;
}

fn pt_mul(p: Pt, s: u8[:], d: Fe) -> Pt {
    var tab: Pt[16] = [pt_id(); 16];
    tab[1] = p;
    for i in 2..16 { tab[i] = pt_add(tab[i - 1], p, d); }
    var acc = pt_id();
    for w in 0..64 {
        acc = pt_dbl(pt_dbl(pt_dbl(pt_dbl(acc))));
        let low = 252 - w * 4;
        let nib = scalar_bit(s, low) | (scalar_bit(s, low + 1) << 1) |
            (scalar_bit(s, low + 2) << 2) | (scalar_bit(s, low + 3) << 3);
        acc = pt_add(acc, pt_lookup(tab, nib), d);
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

fn base() -> Pt {
    let x = Fe { [0x62d608f25d51a, 0x412a4b4f6592a, 0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5] };
    let y = Fe { [0x6666666666658, 0x4cccccccccccc, 0x1999999999999, 0x3333333333333, 0x6666666666666] };
    return Pt {
        x,
        y,
        f1(),
        Fe { [0x68ab3a5b7dda3, 0xeea2a5eadbb, 0x2af8df483c27e, 0x332b375274732, 0x67875f0fd78b7] },
    };
}

// SHA-512 lives in sha512.goose. These wrap the two- and three-part hashes
// Ed25519 feeds to the scalar.

fn h512(data: u8[:]) -> u8[64] { return sha512::hash(data); }

fn h512_2(a: u8[:], b: u8[:]) -> u8[64] {
    var c: sha512::Ctx = default<sha512::Ctx>();
    sha512::init(c);
    sha512::update(c, a);
    sha512::update(c, b);
    return sha512::finish(c);
}

fn h512_3(a: u8[:], b: u8[:], c: u8[:]) -> u8[64] {
    var s: sha512::Ctx = default<sha512::Ctx>();
    sha512::init(s);
    sha512::update(s, a);
    sha512::update(s, b);
    sha512::update(s, c);
    return sha512::finish(s);
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
    let h = h512(seed);
    var a: u8[32] = [0; 32];
    clamp_scalar(h, a);
    let d = ed_d();
    return encode(pt_mul(base(), a, d)), true;
}

fn sign(seed: u8[:], msg: u8[:]) -> u8[64], bool {
    if seed.len != 32 { return [0; 64], false; }
    let h = h512(seed);
    var a: u8[32] = [0; 32];
    clamp_scalar(h, a);
    let d = ed_d();
    let bp = base();
    let pub = encode(pt_mul(bp, a, d));
    let r_hash = h512_2(h[32..64], msg);
    let r = sc_to_bytes(sc_from64(r_hash));
    let rr = encode(pt_mul(bp, r, d));
    let k_hash = h512_3(rr, pub, msg);
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

fn same_pt(p: Pt, q: Pt) -> bool {
    if same(p.z, f0()) || same(q.z, f0()) { return false; }
    return same(fmul(p.x, q.z), fmul(q.x, p.z)) && same(fmul(p.y, q.z), fmul(q.y, p.z));
}

fn verify(public: u8[:], msg: u8[:], sig: u8[:]) -> bool {
    if public.len != 32 || sig.len != 64 { return false; }
    if !sc_below_l(sig[32..64]) { return false; }
    let d = ed_d();
    let a, aok = decode(public, d);
    let r, rok = decode(sig[..32], d);
    if !aok || !rok { return false; }
    let k_hash = h512_3(sig[..32], public, msg);
    let k = sc_to_bytes(sc_from64(k_hash));
    let left = pt_mul(base(), sig[32..64], d);
    let right = pt_add(r, pt_mul(a, k, d), d);
    return same_pt(left, right);
}
