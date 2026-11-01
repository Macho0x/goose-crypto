import crypto from "..";
import crypto.sha512;

namespace sha512;

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
    if !hash("").eq_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") { return false; }
    if !hash("abc").eq_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") { return false; }
    let long = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    if !hash(long).eq_hex("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909") { return false; }
    var c: Ctx = default<Ctx>();
    init(c);
    update(c, "ab");
    update(c, "c");
    if !finish(c).eq_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") { return false; }
    var msg: u8[200] = ['a'; 200];
    let once = hash(msg);
    var shifted: u8[201] = [0; 201];
    for i in 0..200 { shifted[i + 1] = 'a'; }
    if hash(shifted[1..]) != once { return false; }
    for cut in [1, 111, 112, 127, 128, 129, 199] {
        var s: Ctx = default<Ctx>();
        init(s);
        update(s, msg[..cut]);
        update(s, msg[cut..]);
        if finish(s) != once { return false; }
    }
    var key: u8[20] = [0x0b; 20];
    if !hmac(key, "Hi There").eq_hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854") { return false; }
    if !hmac("Jefe", "what do ya want for nothing?").eq_hex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737") { return false; }
    return true;
}

fn ::main() {
    if sha512::self_check() { print("sha512 ok"); } else { print("sha512 FAIL"); exit(1); }
}
