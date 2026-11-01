import crypto from "..";
import crypto.btc_segwit;

namespace btc_segwit;

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

fn load_hex(hex: u8[:], out: u8[>..]&) -> bool {
    if hex.len % 2 != 0 { return false; }
    let n = hex.len / 2;
    out.resize(n, 0);
    for i in 0..n { out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]); }
    return true;
}

fn self_check() -> bool {
    var raw: u8[>..] = [];
    var script: u8[>..] = [];
    var amount: u8[>..] = [];
    var secret: u8[>..] = [];
    if !load_hex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000", raw) { return false; }
    if !load_hex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac", script) { return false; }
    if !load_hex("0046c32300000000", amount) { return false; }
    if !load_hex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9", secret) { return false; }
    let dig, ok = sighash(raw, script, amount, 1, 1);
    if !ok || !eq_hex(dig, "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670") { return false; }
    var der: u8[>..] = [];
    if !sign(secret, raw, script, amount, 1, 1, der) { return false; }
    if !eq_hex(der, "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01") { return false; }
    return true;
}

fn ::main() {
    if btc_segwit::self_check() { print("btc_segwit ok"); } else { print("btc_segwit FAIL"); exit(1); }
}
