import crypto from "..";
import crypto.chacha20poly1305;

namespace chacha20poly1305;

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
