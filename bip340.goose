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

fn load32(hex: u8[:]) -> u8[32] {
    var o: u8[32] = [0; 32];
    unhex(hex, o);
    return o;
}

fn self_check() -> bool {
    let sk0 = load32("0000000000000000000000000000000000000000000000000000000000000003");
    let aux0: u8[32] = [0; 32];
    let msg0: u8[32] = [0; 32];
    let pk0, ok0 = public_key(sk0);
    if !ok0 || !pk0.eq_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9") { return false; }
    let sig0, s0 = sign(sk0, msg0, aux0);
    if !s0 || !sig0.eq_hex("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0") { return false; }
    if !verify(pk0, msg0, sig0) { return false; }

    let sk1 = load32("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    let aux1 = load32("0000000000000000000000000000000000000000000000000000000000000001");
    let msg1 = load32("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
    let pk1, ok1 = public_key(sk1);
    if !ok1 || !pk1.eq_hex("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659") { return false; }
    let sig1, s1 = sign(sk1, msg1, aux1);
    if !s1 || !sig1.eq_hex("6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a") { return false; }
    if !verify(pk1, msg1, sig1) { return false; }

    let bad5 = load32("d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9");
    var rej5: u8[64] = [0; 64];
    unhex("00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", rej5);
    if verify(bad5, msg1, rej5) { return false; }
    var rej6: u8[64] = [0; 64];
    unhex("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", rej6);
    if verify(pk1, msg1, rej6) { return false; }
    var rej8: u8[64] = [0; 64];
    unhex("6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", rej8);
    if verify(pk1, msg1, rej8) { return false; }
    var rej12: u8[64] = [0; 64];
    unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", rej12);
    if verify(pk1, msg1, rej12) { return false; }
    var rej13: u8[64] = [0; 64];
    unhex("6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", rej13);
    if verify(pk1, msg1, rej13) { return false; }
    return true;
}

fn ::main() {
    if bip340::self_check() { print("bip340 ok"); } else { print("bip340 FAIL"); exit(1); }
}
