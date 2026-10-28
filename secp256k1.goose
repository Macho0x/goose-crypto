// secp256k1 ECDSA. Field and scalar values are eight little-endian u32
// limbs. Private keys, digests, and signatures are big-endian.
// Addition and subtraction mask secret-dependent choices. Products reduce
// by the field prime or the group order. Generator multiplication uses a
// precomputed comb and skips zero digits, so it takes data-dependent time.
// Goose does not promise constant-time code.

import std;
import sha256;

namespace secp256k1;

struct Pt { x: u32[8], y: u32[8], z: u32[8] }

const ORDER_K: u32[5] = [0x2fc9bebf, 0x402da173, 0x50b75fc4, 0x45512319, 0x1];

fn prime() -> u32[8] {
    [0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
}

fn order() -> u32[8] {
    [0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff]
}

fn half_n() -> u32[8] {
    [0x681b20a0, 0xdfe92f46, 0x57a4501d, 0x5d576e73, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff]
}

fn zero() -> u32[8] { [0; 8] }
fn one() -> u32[8] { var r: u32[8] = [0; 8]; r[0] = 1; return r; }
fn seven() -> u32[8] { var r: u32[8] = [0; 8]; r[0] = 7; return r; }

fn ct_lt(a: u64, b: u64) -> u64 {
    let z = a - b;
    (z ^ ((a ^ b) & (b ^ z))) >> 63
}

fn zero_mask(a: u32[8]) -> u32 {
    var x: u64 = 0;
    for i in 0..8 { x |= a[i]; }
    let nz = (x | (0 - x)) >> 63;
    return (1 - nz) as! u32;
}

fn is_zero(a: u32[8]) -> bool { zero_mask(a) == 1 }

fn gte_mask_n(n: i64, limb_a: u32[:], limb_b: u32[:]) -> u32 {
    var gt: u64 = 0;
    var lt: u64 = 0;
    for i in 0..n {
        let j = n - 1 - i;
        let ai: u64 = limb_a[j];
        let bi: u64 = limb_b[j];
        let fresh = 1 - (gt | lt);
        gt |= ct_lt(bi, ai) & fresh;
        lt |= ct_lt(ai, bi) & fresh;
    }
    return (1 - lt) as! u32;
}

fn gte8(a: u32[8], b: u32[8]) -> bool { gte_mask_n(8, a, b) == 1 }

fn sub_limbs(a: u32[:], b: u32[:], r: u32[:]) {
    var borrow: u64 = 0;
    for i in 0..a.len {
        let bi = b[i] + borrow;
        let ai: u64 = a[i];
        let under = ct_lt(ai, bi);
        let plain = ai - bi;
        let wrapped = ai + 0x100000000 - bi;
        let m = 0 - under;
        r[i] = ((plain & ~m) | (wrapped & m)) as! u32;
        borrow = under;
    }
}

fn sub8(a: u32[8], b: u32[8]) -> u32[8] {
    var r: u32[8] = [0; 8];
    sub_limbs(a, b, r);
    return r;
}

fn sub9(a: u32[9], b: u32[9]) -> u32[9] {
    var r: u32[9] = [0; 9];
    sub_limbs(a, b, r);
    return r;
}

fn select_limbs(a: u32[:], b: u32[:], bit: u32, r: u32[:]) {
    let m: u32 = 0 - bit;
    for i in 0..a.len { r[i] = a[i] ^ ((a[i] ^ b[i]) & m); }
}

fn select8(a: u32[8], b: u32[8], bit: u32) -> u32[8] {
    var r = a;
    select_limbs(a, b, bit, r);
    return r;
}

fn select9(a: u32[9], b: u32[9], bit: u32) -> u32[9] {
    var r = a;
    select_limbs(a, b, bit, r);
    return r;
}

fn add_u64(w: u32[16]&, pos: i64, v: u64) {
    var i = pos;
    var c = v;
    while c != 0 {
        let s = w[i] + (c & 0xffffffff);
        w[i] = s as! u32;
        c = (c >> 32) + (s >> 32);
        i += 1;
    }
}

fn fold_field(w: u32[16]&) {
    var hi: u32[8] = [0; 8];
    for i in 0..8 {
        hi[i] = w[8 + i];
        w[8 + i] = 0;
    }
    var carry: u64 = 0;
    for i in 0..8 {
        let h: u64 = hi[i];
        let t = h * 977 + carry;
        let s = w[i] + (t & 0xffffffff);
        w[i] = s as! u32;
        carry = (t >> 32) + (s >> 32);
    }
    add_u64(w, 8, carry);
    carry = 0;
    for i in 0..8 {
        let cur: u64 = w[i + 1];
        let hip: u64 = hi[i];
        let s = cur + hip + carry;
        w[i + 1] = s as! u32;
        carry = s >> 32;
    }
    add_u64(w, 9, carry);
}

fn fold_order(w: u32[16]&) {
    var hi: u32[8] = [0; 8];
    for i in 0..8 {
        hi[i] = w[8 + i];
        w[8 + i] = 0;
    }
    for i in 0..8 {
        if hi[i] != 0 {
            var carry: u64 = 0;
            let h: u64 = hi[i];
            for j in 0..5 {
                let uv = w[i + j] + h * ORDER_K[j] + carry;
                w[i + j] = uv as! u32;
                carry = uv >> 32;
            }
            add_u64(w, i + 5, carry);
        }
    }
}

fn reduce_mod(w: u32[16], m: u32[8]) -> u32[8] {
    var out: u32[8] = [0; 8];
    for i in 0..8 { out[i] = w[i]; }
    for k in 0..2 {
        out = select8(out, sub8(out, m), gte_mask_n(8, out, m));
    }
    return out;
}

fn fe_reduce(src: u32[16]) -> u32[8] {
    var w = src;
    for k in 0..4 { fold_field(w); }
    return reduce_mod(w, prime());
}

fn sc_reduce(src: u32[16]) -> u32[8] {
    var w = src;
    for k in 0..4 { fold_order(w); }
    return reduce_mod(w, order());
}

fn fe_add(a: u32[8], b: u32[8]) -> u32[8] {
    var r: u32[9] = [0; 9];
    var c: u64 = 0;
    var p: u32[9] = [0; 9];
    let prime = prime();
    for i in 0..8 {
        let ai: u64 = a[i];
        let bi: u64 = b[i];
        let t = ai + bi + c;
        r[i] = t as! u32;
        c = t >> 32;
        p[i] = prime[i];
    }
    r[8] = c as! u32;
    let reduced = sub9(r, p);
    r = select9(r, reduced, gte_mask_n(9, r, p));
    var out: u32[8] = [0; 8];
    for i in 0..8 { out[i] = r[i]; }
    return out;
}

fn fe_sub(a: u32[8], b: u32[8]) -> u32[8] {
    let direct = sub8(a, b);
    let other = sub8(prime(), sub8(b, a));
    return select8(other, direct, gte_mask_n(8, a, b));
}

fn fe_mul(a: u32[8], b: u32[8]) -> u32[8] {
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
    return fe_reduce(w);
}

fn fe_sqr(a: u32[8]) -> u32[8] {
    var w: u32[16] = [0; 16];
    for i in 0..8 {
        let ai: u64 = a[i];
        for j in (i + 1)..8 {
            let aj: u64 = a[j];
            add_u64(w, i + j, ai * aj);
        }
    }
    var carry: u64 = 0;
    for i in 0..16 {
        let wide: u64 = w[i];
        let s = (wide << 1) | carry;
        w[i] = s as! u32;
        carry = s >> 32;
    }
    for i in 0..8 {
        let ai: u64 = a[i];
        add_u64(w, i + i, ai * ai);
    }
    return fe_reduce(w);
}

fn fe_pow(a: u32[8], e: u32[8]) -> u32[8] {
    var r = one();
    for step in 0..256 {
        r = fe_sqr(r);
        let i = 255 - step;
        if ((e[i / 32] >> (i % 32)) & 1) == 1 { r = fe_mul(r, a); }
    }
    return r;
}

fn fe_inv(a: u32[8]) -> u32[8] {
    fe_pow(a, [0xfffffc2d, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff])
}

fn sc_add(a: u32[8], b: u32[8]) -> u32[8] {
    var r: u32[9] = [0; 9];
    var c: u64 = 0;
    var n: u32[9] = [0; 9];
    let order = order();
    for i in 0..8 {
        let ai: u64 = a[i];
        let bi: u64 = b[i];
        let t = ai + bi + c;
        r[i] = t as! u32;
        c = t >> 32;
        n[i] = order[i];
    }
    r[8] = c as! u32;
    let reduced = sub9(r, n);
    r = select9(r, reduced, gte_mask_n(9, r, n));
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

fn sc_inv(a: u32[8]) -> u32[8] {
    let e: u32[8] = [0xd036413f, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff];
    var r = one();
    for step in 0..256 {
        r = sc_mul(r, r);
        let i = 255 - step;
        if ((e[i / 32] >> (i % 32)) & 1) == 1 { r = sc_mul(r, a); }
    }
    return r;
}

fn infinity() -> Pt { Pt { [0; 8], [0; 8], [0; 8] } }
fn is_inf(p: Pt) -> bool { is_zero(p.z) }

fn select_pt(a: Pt, b: Pt, bit: u32) -> Pt {
    Pt { select8(a.x, b.x, bit), select8(a.y, b.y, bit), select8(a.z, b.z, bit) }
}

fn base() -> Pt {
    Pt {
        [0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e],
        [0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77],
        one(),
    }
}

fn pt_dbl(p: Pt) -> Pt {
    let a = fe_sqr(p.x);
    let b = fe_sqr(p.y);
    let c = fe_sqr(b);
    let d = fe_add(fe_sub(fe_sub(fe_sqr(fe_add(p.x, b)), a), c), fe_sub(fe_sub(fe_sqr(fe_add(p.x, b)), a), c));
    let e = fe_add(fe_add(a, a), a);
    let f = fe_sqr(e);
    let x3 = fe_sub(f, fe_add(d, d));
    var c8 = c;
    c8 = fe_add(c8, c8);
    c8 = fe_add(c8, c8);
    c8 = fe_add(c8, c8);
    let y3 = fe_sub(fe_mul(e, fe_sub(d, x3)), c8);
    let z3 = fe_add(fe_mul(p.y, p.z), fe_mul(p.y, p.z));
    return select_pt(Pt { x3, y3, z3 }, p, zero_mask(p.z));
}

fn pt_add(p: Pt, q: Pt) -> Pt {
    let z1z1 = fe_sqr(p.z);
    let z2z2 = fe_sqr(q.z);
    let u1 = fe_mul(p.x, z2z2);
    let u2 = fe_mul(q.x, z1z1);
    let s1 = fe_mul(fe_mul(p.y, z2z2), q.z);
    let s2 = fe_mul(fe_mul(q.y, z1z1), p.z);
    let h = fe_sub(u2, u1);
    let rr = fe_sub(s2, s1);
    let i = fe_sqr(fe_add(h, h));
    let j = fe_mul(h, i);
    let r = fe_add(rr, rr);
    let v = fe_mul(u1, i);
    let x3 = fe_sub(fe_sub(fe_sqr(r), j), fe_add(v, v));
    let y3 = fe_sub(fe_mul(r, fe_sub(v, x3)), fe_add(fe_mul(s1, j), fe_mul(s1, j)));
    let zz = fe_sub(fe_sub(fe_sqr(fe_add(p.z, q.z)), z1z1), z2z2);
    let sum = Pt { x3, y3, fe_mul(zz, h) };
    let h0 = zero_mask(h);
    let r0 = zero_mask(rr);
    var out = select_pt(sum, pt_dbl(p), h0 & r0);
    out = select_pt(out, infinity(), h0 & (1 - r0));
    out = select_pt(out, q, zero_mask(p.z));
    return select_pt(out, p, zero_mask(q.z));
}

const COMB_X: u32[8][16] = [
    [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e],
    [0x42d0e6bd, 0x13b7e0e7, 0xdb0f5e53, 0xf774d163, 0x104d6ecb, 0x82a2147c, 0x243c4e25, 0x3322d401],
    [0x829d122a, 0xdca81127, 0x67e99549, 0x8f17f314, 0x6a8a9e73, 0x9b889085, 0x846dd99d, 0x583fdfd9],
    [0x9ec4c0da, 0x1b7b444c, 0x723ea335, 0xe88c5678, 0x981f162e, 0x9239c1ad, 0xf63b5f33, 0x8f68b9d2],
    [0x114cbf09, 0x63c5e885, 0x7be77e3e, 0x2f27ce93, 0xf54a3e33, 0xdaa6d12d, 0x3eff872c, 0x8b300e51],
    [0x075e9070, 0xba16ce6a, 0x9b5cfe37, 0xbc26893d, 0x9c510774, 0xe1ddadfe, 0xfe3ae2f4, 0x90922d88],
    [0x6ebdc96c, 0x1bcfa45c, 0x1c7584ba, 0xe400bc04, 0x74cf531f, 0x6395e20e, 0xc5131b30, 0x1edd0bb1],
    [0x2120e2b3, 0x7f3b58fa, 0x7f47f9aa, 0x7a58fdce, 0x4ce6e521, 0xe7be4ae3, 0x1f51bdba, 0xeaa649f2],
    [0x27bb4d71, 0xcf291a33, 0x33524832, 0x6caf7d6b, 0x766584ee, 0x6e0ee131, 0xd064c589, 0x160cb0f6],
    [0x1a9ee611, 0x3eef9e96, 0x9cc37faf, 0xfe4d7bf3, 0xb321d965, 0x462aa9b3, 0x208736c5, 0x1702da3e],
    [0xb188660a, 0xb40f85c7, 0x99bc3c36, 0xc5873c19, 0x7f33b54c, 0x3c7b4541, 0x1f8c9bf8, 0x4cd3a93c],
    [0x6658bb08, 0x9a9e0a72, 0xc589607b, 0xe23c5f2a, 0xf2bfb4c8, 0xa048ca14, 0xc62c2291, 0x4d9a0f89],
    [0x51f5cf67, 0x4333f0da, 0xf4f0d3cb, 0x6d3ea47c, 0xa05a831f, 0x442fda14, 0x016d3e81, 0x6a496013],
    [0x3ea01ea7, 0xb8f996f8, 0x7497bb15, 0xc0045d33, 0x6205647c, 0xc4749dc9, 0x0efd22c9, 0xd8946054],
    [0xbeb8b1e2, 0x8808ca5f, 0xea0dda76, 0x0262b204, 0xddeb356b, 0xb6fffffc, 0xfbb83870, 0x52de253a],
];

const COMB_Y: u32[8][16] = [
    [0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77],
    [0x6c28b2a0, 0x24f3a2e9, 0xa2873af6, 0x2805f63e, 0x4ddaf9b7, 0xbfb019bc, 0xe9664ef5, 0x56e70797],
    [0x63c4eac4, 0xf3c7719e, 0xb734b37a, 0xb44685a3, 0x572a47a6, 0x9f92d2d6, 0x2ff57d81, 0xabc6232f],
    [0x501fff82, 0xf23cbf79, 0x95510bfd, 0xbbea2cfe, 0xb6be215d, 0xde1d90c2, 0xba063986, 0x662a9f2d],
    [0xb3b10a39, 0x26c6ff28, 0x9aaf7169, 0x08f6a7aa, 0x6b8238ea, 0x446f0d46, 0x7f43c0cc, 0x1cec3067],
    [0x5c08824a, 0x653943cc, 0xfce8f4bc, 0x06d74475, 0x533c615d, 0x8d101fa7, 0x742108a9, 0x7b1903f6],
    [0xe358cf9e, 0xa117161b, 0x2724d11c, 0xe490d6f0, 0xee6dd8c9, 0xf75062f6, 0xfba373e4, 0x31e03b2b],
    [0xba5ad93d, 0xd47a5305, 0xf13f7e59, 0x01a6b965, 0x9879aa5a, 0xc69a80f8, 0x5bbbb03a, 0xbe3279ed],
    [0x17136e8d, 0x9d5de554, 0x1aab720e, 0xe3f2d468, 0xccf75cc2, 0xd1378b49, 0xc4ff16e1, 0x6920c375],
    [0x3a545ceb, 0xfba57bbf, 0x7ea858f5, 0x6dbcd766, 0x680d92f1, 0x088e897c, 0xbc626c80, 0x468c1fd8],
    [0x33099cb0, 0xf8dce380, 0x2edd2f33, 0x7a167dd6, 0x0ffe35b7, 0x576d8987, 0xc68ace5c, 0xd2de0386],
    [0x0f827294, 0x427b5f31, 0x9f2c35cd, 0x1ea7a8b5, 0x85a3c00f, 0x95442e56, 0x9b57975a, 0x8cb83121],
    [0xe52e0f48, 0xf647318c, 0x4a0d5ff1, 0x5ff3a66e, 0x61199ba8, 0x046ed81a, 0x3e79c23a, 0x578edf08],
    [0x12774ad5, 0x062dcb09, 0x8be06e3a, 0xcb13f310, 0x235de1a9, 0xca281d35, 0x69c3645c, 0xaf8a7412],
    [0x8f8d21ea, 0x961f40c0, 0x002f03ed, 0x89686278, 0x38e421ea, 0x0ff834d7, 0xd36fb8db, 0x3a270d6f],
];

fn bit(s: u32[8], i: i64) -> i64 {
    (s[i / 32] >> (i % 32)) & 1
}

fn mul_base(s: u32[8]) -> Pt {
    var acc = infinity();
    for step in 0..64 {
        let i = 63 - step;
        acc = pt_dbl(acc);
        let k = bit(s, i) | (bit(s, i + 64) << 1) | (bit(s, i + 128) << 2) | (bit(s, i + 192) << 3);
        if k != 0 { acc = pt_add(acc, Pt { COMB_X[k], COMB_Y[k], one() }); }
    }
    return acc;
}

fn mul_window(p: Pt, s: u32[8]) -> Pt {
    var tab: Pt[16];
    tab[0] = infinity();
    tab[1] = p;
    for i in 2..16 { tab[i] = pt_add(tab[i - 1], p); }
    var acc = infinity();
    for w in 0..64 {
        acc = pt_dbl(pt_dbl(pt_dbl(pt_dbl(acc))));
        let low = 252 - w * 4;
        let nib = bit(s, low) | (bit(s, low + 1) << 1) | (bit(s, low + 2) << 2) | (bit(s, low + 3) << 3);
        if nib != 0 { acc = pt_add(acc, tab[nib]); }
    }
    return acc;
}

fn pt_mul(p: Pt, s: u32[8]) -> Pt {
    let b = base();
    if p.x == b.x && p.y == b.y && p.z == b.z { return mul_base(s); }
    return mul_window(p, s);
}

fn affine(p: Pt) -> u32[8], u32[8], bool {
    if is_inf(p) { return zero(), zero(), false; }
    let zinv = fe_inv(p.z);
    let z2 = fe_sqr(zinv);
    return fe_mul(p.x, z2), fe_mul(p.y, fe_mul(z2, zinv)), true;
}

fn load_be(b: u8[:]) -> u32[8] {
    var s: u32[8] = [0; 8];
    for i in 0..8 {
        let j = (7 - i) * 4;
        let b0: u32 = b[j];
        let b1: u32 = b[j + 1];
        let b2: u32 = b[j + 2];
        let b3: u32 = b[j + 3];
        s[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }
    return s;
}

fn store_be(s: u32[8], out: u8[:]) {
    for i in 0..8 {
        let v = s[i];
        let j = (7 - i) * 4;
        out[j] = (v >> 24) as! u8;
        out[j + 1] = (v >> 16) as! u8;
        out[j + 2] = (v >> 8) as! u8;
        out[j + 3] = v as! u8;
    }
}

fn secret_ok(secret: u8[:]) -> u32[8], bool {
    if secret.len != 32 { return zero(), false; }
    let d = load_be(secret);
    if is_zero(d) || gte8(d, order()) { return zero(), false; }
    return d, true;
}

fn pubkey_compressed(secret: u8[:]) -> u8[33], bool {
    let d, ok = secret_ok(secret);
    if !ok { return [0; 33], false; }
    let x, y, ok2 = affine(pt_mul(base(), d));
    if !ok2 { return [0; 33], false; }
    var o: u8[33] = [2; 33];
    o[0] = (2 | (y[0] & 1)) as! u8;
    store_be(x, o[1..]);
    return o, true;
}

fn pubkey_uncompressed(secret: u8[:]) -> u8[65], bool {
    let d, ok = secret_ok(secret);
    if !ok { return [0; 65], false; }
    let x, y, ok2 = affine(pt_mul(base(), d));
    if !ok2 { return [0; 65], false; }
    var o: u8[65] = [0; 65];
    o[0] = 4;
    store_be(x, o[1..33]);
    store_be(y, o[33..]);
    return o, true;
}

fn on_curve(x: u32[8], y: u32[8]) -> bool {
    if gte8(x, prime()) || gte8(y, prime()) { return false; }
    let y2 = fe_sqr(y);
    let x3 = fe_add(fe_mul(fe_sqr(x), x), seven());
    return y2 == x3;
}

fn decompress(public: u8[:]) -> Pt, bool {
    if public.len == 65 && public[0] == 4 {
        let x = load_be(public[1..33]);
        let y = load_be(public[33..]);
        if !on_curve(x, y) { return infinity(), false; }
        return Pt { x, y, one() }, true;
    }
    if public.len != 33 || (public[0] != 2 && public[0] != 3) { return infinity(), false; }
    let x = load_be(public[1..]);
    if gte8(x, prime()) { return infinity(), false; }
    let y2 = fe_add(fe_mul(fe_sqr(x), x), seven());
    let exp: u32[8] = [0xbfffff0c, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff];
    let y = fe_pow(y2, exp);
    if fe_sqr(y) != y2 { return infinity(), false; }
    var yy = y;
    if ((y[0] & 1) == 1) != (public[0] == 3) { yy = fe_sub(zero(), y); }
    return Pt { x, yy, one() }, true;
}

fn bits2octets(h: u8[:]) -> u8[32] {
    var e = load_be(h);
    e = select8(e, sub8(e, order()), gte_mask_n(8, e, order()));
    var o: u8[32] = [0; 32];
    store_be(e, o);
    return o;
}

fn select_bytes(a: u8[32], b: u8[32], bit: u32) -> u8[32] {
    let m: u8 = (0 - bit) as! u8;
    var r = a;
    for i in 0..32 { r[i] = a[i] ^ ((a[i] ^ b[i]) & m); }
    return r;
}

fn nonce(secret: u8[:], digest: u8[:]) -> u8[32], bool {
    let h = bits2octets(digest);
    var v: u8[32] = [0x01; 32];
    var k: u8[32] = [0; 32];
    var buf: u8[97] = [0; 97];
    for i in 0..32 {
        buf[i] = v[i];
        buf[33 + i] = secret[i];
        buf[65 + i] = h[i];
    }
    buf[32] = 0;
    k = sha256::hmac(k, buf);
    v = sha256::hmac(k, v);
    for i in 0..32 { buf[i] = v[i]; }
    buf[32] = 1;
    k = sha256::hmac(k, buf);
    v = sha256::hmac(k, v);
    var chosen: u8[32] = [0; 32];
    var have: u32 = 0;
    for attempt in 0..8 {
        v = sha256::hmac(k, v);
        let cand = load_be(v);
        let ok = (1 - zero_mask(cand)) & (1 - gte_mask_n(8, cand, order()));
        let take = ok & (1 - have);
        chosen = select_bytes(chosen, v, take);
        have |= take;
        var retry: u8[33] = [0; 33];
        for i in 0..32 { retry[i] = v[i]; }
        k = sha256::hmac(k, retry);
        v = sha256::hmac(k, v);
    }
    return chosen, have == 1;
}

fn sign(secret: u8[:], digest: u8[:]) -> u8[64], bool, u8 {
    if digest.len != 32 { return [0; 64], false, 0; }
    let d, ok = secret_ok(secret);
    if !ok { return [0; 64], false, 0; }
    let kb, kok = nonce(secret, digest);
    if !kok { return [0; 64], false, 0; }
    let k = load_be(kb);
    let rx, ry, pok = affine(pt_mul(base(), k));
    if !pok { return [0; 64], false, 0; }
    let overflow = gte_mask_n(8, rx, order());
    var r = select8(rx, sub8(rx, order()), overflow);
    if is_zero(r) { return [0; 64], false, 0; }
    var e = load_be(digest);
    e = select8(e, sub8(e, order()), gte_mask_n(8, e, order()));
    var s = sc_mul(sc_inv(k), sc_add(e, sc_mul(r, d)));
    if is_zero(s) { return [0; 64], false, 0; }
    let gt_half = 1 - gte_mask_n(8, half_n(), s);
    s = select8(s, sub8(order(), s), gt_half);
    let parity = (ry[0] & 1) ^ gt_half;
    let recid: u32 = parity + overflow * 2;
    var out: u8[64] = [0; 64];
    store_be(r, out[..32]);
    store_be(s, out[32..]);
    return out, true, (27 + recid) as! u8;
}

fn verify(public: u8[:], digest: u8[:], sig: u8[:]) -> bool {
    if digest.len != 32 || sig.len != 64 { return false; }
    let q, ok = decompress(public);
    if !ok { return false; }
    let r = load_be(sig[..32]);
    let s = load_be(sig[32..]);
    if is_zero(r) || gte8(r, order()) || is_zero(s) || gte8(s, order()) { return false; }
    if !gte8(half_n(), s) { return false; }
    let w = sc_inv(s);
    var e = load_be(digest);
    if gte8(e, order()) { e = sub8(e, order()); }
    let p = pt_add(pt_mul(base(), sc_mul(e, w)), pt_mul(q, sc_mul(r, w)));
    let x, _, aok = affine(p);
    if !aok { return false; }
    var xr = x;
    if gte8(xr, order()) { xr = sub8(xr, order()); }
    return xr == r;
}

fn recover(digest: u8[:], sig: u8[:]) -> u8[65], bool {
    if digest.len != 32 || sig.len != 65 { return [0; 65], false; }
    if sig[64] < 27 || sig[64] > 30 { return [0; 65], false; }
    let r = load_be(sig[..32]);
    let s = load_be(sig[32..64]);
    if is_zero(r) || gte8(r, order()) || is_zero(s) || gte8(s, order()) { return [0; 65], false; }
    if !gte8(half_n(), s) { return [0; 65], false; }
    let rec = sig[64] - 27;
    var x = r;
    if (rec >> 1) == 1 {
        if gte8(r, sub8(prime(), order())) { return [0; 65], false; }
        x = fe_add(r, order());
    }
    var comp: u8[33] = [2; 33];
    if (rec & 1) == 1 { comp[0] = 3; }
    store_be(x, comp[1..]);
    let point, pok = decompress(comp);
    if !pok { return [0; 65], false; }
    var e = load_be(digest);
    if gte8(e, order()) { e = sub8(e, order()); }
    let w = sc_inv(r);
    let u1 = sc_mul(e, w);
    var neg = zero();
    if !is_zero(u1) { neg = sub8(order(), u1); }
    let q = pt_add(pt_mul(point, sc_mul(s, w)), pt_mul(base(), neg));
    let xq, yq, aok = affine(q);
    if !aok { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    out[0] = 4;
    store_be(xq, out[1..33]);
    store_be(yq, out[33..]);
    return out, true;
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
    var one: u8[32] = [0; 32];
    one[31] = 1;
    let pk, ok = pubkey_compressed(one);
    if !ok || !pk.eq_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") { return false; }
    var two: u8[32] = [0; 32];
    two[31] = 2;
    let pk2, ok2 = pubkey_compressed(two);
    if !ok2 || !pk2.eq_hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5") { return false; }
    var nm1: u8[32] = [0; 32];
    unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", nm1);
    let pkn, okn = pubkey_compressed(nm1);
    if !okn || !pkn.eq_hex("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") { return false; }
    var digest: u8[32] = [0; 32];
    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest);
    let sig, sok, v = sign(one, digest);
    if !sok || !sig.eq_hex("77c8d336572f6f466055b5f70f433851f8f535f6c4fc71133a6cfd71079d03b70ed9f5eb8aa5b266abac35d416c3207e7a538bf5f37649727d7a9823b1069577") { return false; }
    if !verify(pk, digest, sig) { return false; }
    var high: u8[64] = sig;
    store_be(sub8(order(), load_be(high[32..])), high[32..]);
    if verify(pk, digest, high) { return false; }
    let raw, rok = pubkey_uncompressed(one);
    if !rok || !verify(raw, digest, sig) { return false; }
    var full: u8[65] = [0; 65];
    for i in 0..64 { full[i] = sig[i]; }
    full[64] = v;
    let got, gok = recover(digest, full);
    if !gok || got != raw { return false; }
    var high65: u8[65] = [0; 65];
    for i in 0..64 { high65[i] = high[i]; }
    high65[64] = v;
    let _, hok = recover(digest, high65);
    if hok { return false; }
    full[64] = 26;
    let _, vok = recover(digest, full);
    if vok { return false; }
    sig[63] ^= 1;
    if verify(pk, digest, sig) { return false; }
    return true;
}

fn ::main() {
    if secp256k1::self_check() { print("secp256k1 ok"); } else { print("secp256k1 FAIL"); exit(1); }
}
