import crypto from "..";
import crypto.ed25519;

namespace ed25519;

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
    let d = ed_d();
    let bp = base();
    if !encode(bp).eq_hex("5866666666666666666666666666666666666666666666666666666666666666") { return false; }
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
    var seed3: u8[32] = [0; 32];
    unhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", seed3);
    let pk3, ok3 = public_key(seed3);
    if !ok3 || !pk3.eq_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025") { return false; }
    var msg3: u8[2] = [0; 2];
    unhex("af82", msg3);
    let sig3, sok3 = sign(seed3, msg3);
    if !sok3 || !sig3.eq_hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a") { return false; }
    if !verify(pk3, msg3, sig3) { return false; }
    return true;
}

fn ::main() {
    if ed25519::self_check() { print("ed25519 ok"); } else { print("ed25519 FAIL"); exit(1); }
}
