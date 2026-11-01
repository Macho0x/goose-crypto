import crypto from "..";
import crypto.ripemd160;

namespace ripemd160;

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
    if !hash("").eq_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31") { return false; }
    if !hash("abc").eq_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") { return false; }
    if !hash("abcdefghijklmnopqrstuvwxyz").eq_hex("f71c27109c692c1b56bbdceb5b9d2865b3708dbc") { return false; }
    let eighty = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    if !hash(eighty).eq_hex("9b752e45573d4b39f4dbd3323cab82bf63326bfb") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, "ab");
    update(c, "c");
    if !finish(c).eq_hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc") { return false; }
    var msg: u8[128] = ['a'; 128];
    let once = hash(msg);
    var shifted: u8[129] = [0; 129];
    for i in 0..128 { shifted[i + 1] = 'a'; }
    if hash(shifted[1..]) != once { return false; }
    for cut in [1, 55, 56, 63, 64, 65, 127] {
        var s: Ctx = default<Ctx>();
        init(s);
        update(s, msg[..cut]);
        update(s, msg[cut..]);
        if finish(s) != once { return false; }
    }
    return true;
}

fn ::main() {
    if ripemd160::self_check() { print("ripemd160 ok"); } else { print("ripemd160 FAIL"); exit(1); }
}
