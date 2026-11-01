import crypto from "..";
import crypto.sha256;

namespace sha256;

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
    if !hash("").eq_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") { return false; }
    if !hash("abc").eq_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") { return false; }
    let classic = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    if !hash(classic).eq_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") { return false; }
    var a1000: u8[1000] = ['a'; 1000];
    if !hash(a1000).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, a1000[..100]);
    update(c, a1000[100..700]);
    update(c, a1000[700..]);
    if !finish(c).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    for cut in 1..65 {
        var s: Ctx = default<Ctx>();
        init(s);
        update(s, a1000[..cut]);
        update(s, a1000[cut..]);
        if !finish(s).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    }
    var shifted: u8[1001] = [0; 1001];
    for i in 0..1000 { shifted[i + 1] = 'a'; }
    if !hash(shifted[1..]).eq_hex("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3") { return false; }
    if hash256("") != hash(hash("")) { return false; }
    if hash256("abc") != hash(hash("abc")) { return false; }
    if hash256(a1000) != hash(hash(a1000)) { return false; }
    let fox = "The quick brown fox jumps over the lazy dog";
    if !hmac("key", fox).eq_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") { return false; }
    var longk: u8[80] = ['k'; 80];
    if !hmac(longk, "data").eq_hex("db0b0964fe44311ab89fac8b72ed6f349c5b3bc574c92b87d92a3dbc5de20a8f") { return false; }
    var keyed = mac_start("key");
    var a = copy(keyed);
    var b = copy(keyed);
    mac_update(a, fox);
    mac_update(b, fox);
    if mac_finish(a) != mac_finish(b) { return false; }
    if !mac_finish(a).eq_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") { return false; }
    return true;
}

fn ::main() {
    if sha256::self_check() { print("sha256 ok"); } else { print("sha256 FAIL"); exit(1); }
}
