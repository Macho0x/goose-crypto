import crypto from "..";
import crypto.eip191;
import crypto.secp256k1;

namespace eip191;

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
    var secret: u8[32] = [0; 32];
    unhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", secret);
    let dig = digest("hello world");
    if !dig.eq_hex("d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68") { return false; }
    let sig, ok = sign(secret, "hello world");
    if !ok || !sig.eq_hex("0d5df3f9681b000a5b3a1d4252803318136714deba10c578f9b33718ad9c816e5520a6f19168136aa11e38d691d28a422bce4be3bf290fdb8efe45cdaefb20251c") { return false; }
    let pk, pok = secp256k1::pubkey_compressed(secret);
    if !pok || !verify(pk, "hello world", sig) { return false; }
    let raw, rok = secp256k1::pubkey_uncompressed(secret);
    if !rok || !verify(raw, "hello world", sig) { return false; }
    sig[64] = 26;
    if verify(pk, "hello world", sig) { return false; }
    return true;
}

fn ::main() {
    if eip191::self_check() { print("eip191 ok"); } else { print("eip191 FAIL"); exit(1); }
}
