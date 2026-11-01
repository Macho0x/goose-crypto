import crypto from "..";
import crypto.x25519;

namespace x25519;

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
    var scalar: u8[32] = [0; 32];
    var point: u8[32] = [0; 32];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point);
    let once, ook = scalarmult(scalar, point);
    if !ook || !once.eq_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552") { return false; }
    var scalar2: u8[32] = [0; 32];
    var point2: u8[32] = [0; 32];
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar2);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", point2);
    let twice, tok = scalarmult(scalar2, point2);
    if !tok || !twice.eq_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957") { return false; }
    var k: u8[32] = [0; 32];
    var u: u8[32] = [0; 32];
    k[0] = 9;
    u[0] = 9;
    for i in 0..1000 {
        let next, iok = scalarmult(k, u);
        if !iok { return false; }
        u = k;
        k = next;
    }
    if !k.eq_hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51") { return false; }
    return true;
}

fn ::main() {
    if x25519::self_check() { print("x25519 ok"); } else { print("x25519 FAIL"); exit(1); }
}
