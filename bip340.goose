// BIP-340 Schnorr signatures on secp256k1. Public keys and the nonce
// point are 32-byte x-only coordinates with even Y. A signature is
// x(R) || s. The nonce comes from the tagged hashes BIP0340/aux,
// BIP0340/nonce, and BIP0340/challenge.

import std;
import sha256;
import secp256k1;

namespace bip340;

fn tagged(tag: u8[:], a: u8[:], b: u8[:], c: u8[:]) -> u8[32] {
    let th = sha256::hash(tag);
    var st: sha256::Ctx = default<sha256::Ctx>();
    sha256::init(st);
    sha256::update(st, th);
    sha256::update(st, th);
    sha256::update(st, a);
    sha256::update(st, b);
    sha256::update(st, c);
    return sha256::finish(st);
}

fn mod_n(be: u8[:]) -> u32[8] {
    let x = secp256k1::load_be(be);
    let n = secp256k1::order();
    return secp256k1::select8(x, secp256k1::sub8(x, n), secp256k1::gte_mask_n(8, x, n));
}

fn negate_scalar(d: u32[8]) -> u32[8] { secp256k1::sub8(secp256k1::order(), d) }

fn xonly(p: secp256k1::Pt) -> u8[32], u32, bool {
    let x, y, ok = secp256k1::affine(p);
    if !ok { return [0; 32], 0, false; }
    var o: u8[32] = [0; 32];
    secp256k1::store_be(x, o);
    return o, y[0] & 1, true;
}

fn lift_x(pk: u8[:]) -> secp256k1::Pt, bool {
    if pk.len != 32 { return secp256k1::infinity(), false; }
    let x = secp256k1::load_be(pk);
    if secp256k1::gte8(x, secp256k1::prime()) { return secp256k1::infinity(), false; }
    let y2 = secp256k1::fe_add(secp256k1::fe_mul(secp256k1::fe_sqr(x), x), secp256k1::seven());
    let exp: u32[8] = [0xbfffff0c, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff];
    let y = secp256k1::fe_pow(y2, exp);
    if secp256k1::fe_sqr(y) != y2 { return secp256k1::infinity(), false; }
    var yy = y;
    if (y[0] & 1) == 1 { yy = secp256k1::fe_sub(secp256k1::zero(), y); }
    return secp256k1::Pt { x, yy, secp256k1::one() }, true;
}

fn negate(p: secp256k1::Pt) -> secp256k1::Pt {
    secp256k1::Pt { p.x, secp256k1::fe_sub(secp256k1::zero(), p.y), p.z }
}

fn public_key(secret: u8[:]) -> u8[32], bool {
    let d, ok = secp256k1::secret_ok(secret);
    if !ok { return [0; 32], false; }
    let px, _, pok = xonly(secp256k1::pt_mul(secp256k1::base(), d));
    if !pok { return [0; 32], false; }
    return px, true;
}

fn sign(secret: u8[:], msg: u8[:], aux: u8[:]) -> u8[64], bool {
    if secret.len != 32 || aux.len != 32 { return [0; 64], false; }
    let d0, ok = secp256k1::secret_ok(secret);
    if !ok { return [0; 64], false; }
    let px, odd, pok = xonly(secp256k1::pt_mul(secp256k1::base(), d0));
    if !pok { return [0; 64], false; }
    var d = d0;
    if odd == 1 { d = negate_scalar(d0); }
    var db: u8[32] = [0; 32];
    secp256k1::store_be(d, db);
    let auxh = tagged("BIP0340/aux", aux, aux[..0], aux[..0]);
    var t: u8[32] = [0; 32];
    for i in 0..32 { t[i] = db[i] ^ auxh[i]; }
    let k0 = mod_n(tagged("BIP0340/nonce", t, px, msg));
    if secp256k1::is_zero(k0) { return [0; 64], false; }
    let rx, rodd, rok = xonly(secp256k1::pt_mul(secp256k1::base(), k0));
    if !rok { return [0; 64], false; }
    var k = k0;
    if rodd == 1 { k = negate_scalar(k0); }
    let e = mod_n(tagged("BIP0340/challenge", rx, px, msg));
    let s = secp256k1::sc_add(k, secp256k1::sc_mul(e, d));
    var sig: u8[64] = [0; 64];
    for i in 0..32 { sig[i] = rx[i]; }
    secp256k1::store_be(s, sig[32..]);
    return sig, true;
}

fn verify(pk: u8[:], msg: u8[:], sig: u8[:]) -> bool {
    if pk.len != 32 || sig.len != 64 { return false; }
    let p, ok = lift_x(pk);
    if !ok { return false; }
    let r = secp256k1::load_be(sig[..32]);
    let s = secp256k1::load_be(sig[32..]);
    if secp256k1::gte8(r, secp256k1::prime()) || secp256k1::gte8(s, secp256k1::order()) { return false; }
    let e = mod_n(tagged("BIP0340/challenge", sig[..32], pk, msg));
    let point = secp256k1::pt_add(secp256k1::pt_mul(secp256k1::base(), s), negate(secp256k1::pt_mul(p, e)));
    let rx, odd, rok = xonly(point);
    if !rok || odd == 1 { return false; }
    for i in 0..32 { if rx[i] != sig[i] { return false; } }
    return true;
}
