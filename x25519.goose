// X25519 (RFC 7748). Field elements are five 51-bit limbs, value
// sum l[i] * 2^(51*i) mod 2^255-19. scalarmult clamps the scalar the
// way the RFC specifies and ignores bit 255 of the u-coordinate.
// Carries and borrows run a fixed number of limbs. Goose does not promise
// the compiler preserves that.

import std;

namespace x25519;

const MASK: u64 = 0x7ffffffffffff;
const A24: u64 = 121665;

struct Fe { l: u64[5] }
struct W { lo: u64, hi: u64 }

fn fe_zero() -> Fe { Fe { [0; 5] } }

fn fe_one() -> Fe {
    var f = fe_zero();
    f.l[0] = 1;
    return f;
}

fn ct_lt(a: u64, b: u64) -> u64 {
    let z = a - b;
    (z ^ ((a ^ b) & (b ^ z))) >> 63
}

fn fe_carry(a: Fe) -> Fe {
    var r = a;
    for pass in 0..6 {
        var c: u64 = 0;
        for i in 0..5 {
            let v = r.l[i] + c;
            r.l[i] = v & MASK;
            c = v >> 51;
        }
        r.l[0] += c * 19;
    }
    return r;
}

fn fe_canonical(a: Fe) -> Fe {
    var r = fe_carry(a);
    var reduced: u64[5] = [0; 5];
    var c = r.l[0] + 19;
    reduced[0] = c & MASK;
    c = c >> 51;
    for i in 1..5 {
        c += r.l[i];
        reduced[i] = c & MASK;
        c = c >> 51;
    }
    let m: u64 = 0 - c;
    for i in 0..5 { r.l[i] = (r.l[i] & ~m) | (reduced[i] & m); }
    return r;
}

fn wadd(a: W, b: W) -> W {
    let lo = a.lo + b.lo;
    let c = ct_lt(lo, a.lo);
    W { lo, a.hi + b.hi + c }
}

fn mul64(a: u64, b: u64) -> W {
    let a0 = a & 0xffffffff;
    let a1 = a >> 32;
    let b0 = b & 0xffffffff;
    let b1 = b >> 32;
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 32) + (p01 & 0xffffffff) + (p10 & 0xffffffff);
    let lo = (p00 & 0xffffffff) | ((mid & 0xffffffff) << 32);
    let hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    W { lo, hi }
}

fn split51(w: W) -> u64, u64 {
    let low = w.lo & MASK;
    let carry = (w.lo >> 51) | (w.hi << 13);
    return low, carry;
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    var r = fe_zero();
    for i in 0..5 { r.l[i] = a.l[i] + b.l[i]; }
    return fe_carry(r);
}

fn limb_sub(ai: u64, bi: u64) -> u64, u64 {
    let under = ct_lt(ai, bi);
    let plain = ai - bi;
    let wrapped = ai + (MASK + 1) - bi;
    let m = 0 - under;
    return (plain & ~m) | (wrapped & m), under;
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    let a = fe_carry(a);
    let b = fe_carry(b);
    var r = fe_zero();
    var borrow: u64 = 0;
    for i in 0..5 {
        let limb, under = limb_sub(a.l[i], b.l[i] + borrow);
        r.l[i] = limb;
        borrow = under;
    }
    // A final borrow means the limb subtraction added 2^255. Subtract 19,
    // and if that borrow also runs off the top, subtract 19 once more.
    let limb, under = limb_sub(r.l[0], 19 * borrow);
    r.l[0] = limb;
    var br = under;
    for i in 1..5 {
        let limb, under = limb_sub(r.l[i], br);
        r.l[i] = limb;
        br = under;
    }
    r.l[0] -= 19 * br;
    return r;
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let a = fe_carry(a);
    let b = fe_carry(b);
    let a0 = a.l[0]; let a1 = a.l[1]; let a2 = a.l[2]; let a3 = a.l[3]; let a4 = a.l[4];
    let b0 = b.l[0]; let b1 = b.l[1] * 19; let b2 = b.l[2] * 19; let b3 = b.l[3] * 19; let b4 = b.l[4] * 19;
    let c0 = b.l[1]; let c2 = b.l[2]; let c3 = b.l[3]; let c4 = b.l[4];
    var t0 = mul64(a0, b0);
    t0 = wadd(t0, mul64(a1, b4));
    t0 = wadd(t0, mul64(a2, b3));
    t0 = wadd(t0, mul64(a3, b2));
    t0 = wadd(t0, mul64(a4, b1));
    var t1 = mul64(a0, c0);
    t1 = wadd(t1, mul64(a1, b0));
    t1 = wadd(t1, mul64(a2, b4));
    t1 = wadd(t1, mul64(a3, b3));
    t1 = wadd(t1, mul64(a4, b2));
    var t2 = mul64(a0, c2);
    t2 = wadd(t2, mul64(a1, c0));
    t2 = wadd(t2, mul64(a2, b0));
    t2 = wadd(t2, mul64(a3, b4));
    t2 = wadd(t2, mul64(a4, b3));
    var t3 = mul64(a0, c3);
    t3 = wadd(t3, mul64(a1, c2));
    t3 = wadd(t3, mul64(a2, c0));
    t3 = wadd(t3, mul64(a3, b0));
    t3 = wadd(t3, mul64(a4, b4));
    var t4 = mul64(a0, c4);
    t4 = wadd(t4, mul64(a1, c3));
    t4 = wadd(t4, mul64(a2, c2));
    t4 = wadd(t4, mul64(a3, c0));
    t4 = wadd(t4, mul64(a4, b0));
    let l0, k0 = split51(t0);
    let l1, k1 = split51(wadd(t1, W { k0, 0 }));
    let l2, k2 = split51(wadd(t2, W { k1, 0 }));
    let l3, k3 = split51(wadd(t3, W { k2, 0 }));
    let l4, k4 = split51(wadd(t4, W { k3, 0 }));
    var f = fe_zero();
    f.l[0] = l0 + k4 * 19;
    f.l[1] = l1;
    f.l[2] = l2;
    f.l[3] = l3;
    f.l[4] = l4;
    return fe_carry(f);
}

fn fe_sqr(a: Fe) -> Fe { fe_mul(a, a) }

fn fe_mul_small(a: Fe, n: u64) -> Fe {
    var b = fe_zero();
    b.l[0] = n;
    return fe_mul(a, b);
}

// a^(2^255-21) = a^(p-2).
fn fe_inv(a: Fe) -> Fe {
    var r = fe_one();
    for step in 0..255 {
        let i = 254 - step;
        r = fe_sqr(r);
        let bit = if i >= 8 { 1 } else { (0xeb >> i) & 1 };
        if bit == 1 { r = fe_mul(r, a); }
    }
    return r;
}

fn load64(b: u8[:], i: i64) -> u64 {
    var x: u64 = 0;
    for k in 0..8 { x |= (b[i + k] as u64) << (k * 8); }
    return x;
}

fn fe_from_bytes(b: u8[:]) -> Fe {
    let w0 = load64(b, 0);
    let w1 = load64(b, 8);
    let w2 = load64(b, 16);
    let w3 = load64(b, 24) & 0x7fffffffffffffff;
    var f = fe_zero();
    f.l[0] = w0 & MASK;
    f.l[1] = ((w0 >> 51) | ((w1 & 0x3fffffffff) << 13)) & MASK;
    f.l[2] = ((w1 >> 38) | ((w2 & 0x1ffffff) << 26)) & MASK;
    f.l[3] = ((w2 >> 25) | ((w3 & 0xfff) << 39)) & MASK;
    f.l[4] = (w3 >> 12) & MASK;
    return f;
}

fn fe_to_bytes(a: Fe) -> u8[32] {
    let f = fe_canonical(a);
    let w0 = f.l[0] | ((f.l[1] & 0x1fff) << 51);
    let w1 = (f.l[1] >> 13) | ((f.l[2] & 0x3ffffff) << 38);
    let w2 = (f.l[2] >> 26) | ((f.l[3] & 0x7fffffffff) << 25);
    let w3 = (f.l[3] >> 39) | (f.l[4] << 12);
    var o: u8[32] = [0; 32];
    let words: u64[4] = [w0, w1, w2, w3];
    for i in 0..4 {
        var x = words[i];
        for k in 0..8 {
            o[i * 8 + k] = x as! u8;
            x = x >> 8;
        }
    }
    return o;
}

fn fe_cswap(a: Fe&, b: Fe&, bit: u64) {
    let m: u64 = 0 - bit;
    for i in 0..5 {
        let t = m & (a.l[i] ^ b.l[i]);
        a.l[i] ^= t;
        b.l[i] ^= t;
    }
}

fn clamp(s: u8[32]&) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

fn scalar_bit(s: u8[:], i: i64) -> u64 {
    let byte: u64 = s[i / 8];
    (byte >> (i % 8)) & 1
}

fn scalarmult(scalar: u8[:], point: u8[:]) -> u8[32], bool {
    if scalar.len != 32 || point.len != 32 {
        return [0; 32], false;
    }
    var e: u8[32] = [0; 32];
    for i in 0..32 { e[i] = scalar[i]; }
    clamp(e);
    let x1 = fe_from_bytes(point);
    var x2 = fe_one();
    var z2 = fe_zero();
    var x3 = x1;
    var z3 = fe_one();
    var swap: u64 = 0;
    for step in 0..255 {
        let kt = scalar_bit(e, 254 - step);
        swap ^= kt;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = kt;
        let sum2 = fe_add(x2, z2);
        let aa = fe_sqr(sum2);
        let dif2 = fe_sub(x2, z2);
        let bb = fe_sqr(dif2);
        let ee = fe_sub(aa, bb);
        let sum3 = fe_add(x3, z3);
        let dif3 = fe_sub(x3, z3);
        let da = fe_mul(dif3, sum2);
        let cb = fe_mul(sum3, dif2);
        x3 = fe_sqr(fe_add(da, cb));
        z3 = fe_mul(x1, fe_sqr(fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(ee, fe_add(aa, fe_mul_small(ee, A24)));
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    return fe_to_bytes(fe_mul(x2, fe_inv(z2))), true;
}

fn base_point() -> u8[32] {
    var b: u8[32] = [0; 32];
    b[0] = 9;
    return b;
}

fn public_key(secret: u8[:]) -> u8[32], bool { return scalarmult(secret, base_point()); }

fn shared(secret: u8[:], peer: u8[:]) -> u8[32], bool {
    let out, ok = scalarmult(secret, peer);
    if !ok { return [0; 32], false; }
    // RFC 7748: a shared secret of all zeros is a degenerate result.
    for i in 0..32 {
        if out[i] != 0 { return out, true; }
    }
    return [0; 32], false;
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
    var n9: u8[32] = [0; 32];
    n9[0] = 9;
    let out, ok = scalarmult(n9, n9);
    if !ok || !out.eq_hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079") { return false; }
    var alice_s: u8[32] = [0; 32];
    var bob_s: u8[32] = [0; 32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice_s);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob_s);
    let alice_p, aok = public_key(alice_s);
    let bob_p, bok = public_key(bob_s);
    if !aok || !bok { return false; }
    if !alice_p.eq_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a") { return false; }
    if !bob_p.eq_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f") { return false; }
    let s1, ok1 = shared(alice_s, bob_p);
    let s2, ok2 = shared(bob_s, alice_p);
    if !ok1 || !ok2 || !s1.eq_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742") { return false; }
    if s1 != s2 { return false; }
    var zeros: u8[32] = [0; 32];
    let _, zok = shared(alice_s, zeros);
    if zok { return false; }
    let back = fe_to_bytes(fe_from_bytes(alice_p));
    if back != alice_p { return false; }
    return true;
}

fn ::main() {
    if x25519::self_check() { print("x25519 ok"); } else { print("x25519 FAIL"); exit(1); }
}
