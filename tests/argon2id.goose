import crypto from "..";
import crypto.argon2id;

namespace argon2id;

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

fn self_check() -> bool {
    var empty: u8[64] = [0; 64];
    blake2b("", empty);
    if !empty.eq_hex("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce") { return false; }
    var password: u8[32] = [0x01; 32];
    var salt: u8[16] = [0x02; 16];
    var secret: u8[8] = [0x03; 8];
    var ad: u8[12] = [0x04; 12];
    var tag: u8[32] = [0; 32];
    if !hash(password, salt, secret, ad, 32, 3, 4, tag) { return false; }
    return tag.eq_hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

fn ::main() {
    if argon2id::self_check() { print("argon2id ok"); } else { print("argon2id FAIL"); exit(1); }
}
