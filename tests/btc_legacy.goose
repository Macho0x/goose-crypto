import crypto from "..";
import crypto.btc_legacy;

namespace btc_legacy;

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
    var all_tx: u8[>..] = [];
    var acp_tx: u8[>..] = [];
    var single_tx: u8[>..] = [];
    var acp_script: u8[>..] = [];
    if !load_hex("cf7bdc250249e22cbe23baf6b648328d31773ea0e771b3b76a48b4748d7fbd390e88a004d30000000003ac536a4ab8cce0e097136c90b2037f231b7fde2063017facd40ed4e5896da7ad00e9c71dd70ae600000000096a0063516352525365ffffffff01b71e3e00000000000300536a00000000", all_tx) { return false; }
    if !load_hex("4ddaa680026ec4d8060640304b86823f1ac760c260cef81d85bd847952863d629a3002b54b0200000008526365636a656aab65457861fc6c24bdc760c8b2e906b6656edaf9ed22b5f50e1fb29ec076ceadd9e8ebcb6b000000000152ffffffff033ff04f00000000000551526a00657a1d900300000000002153af040000000003006a6300000000", acp_tx) { return false; }
    if !load_hex("ab526a53acabab", acp_script) { return false; }
    if !load_hex("ff5400dd02fec5beb9a396e1cbedc82bedae09ed44bae60ba9bef2ff375a6858212478844b03000000025253ffffffff01e46c203577a79d1172db715e9cc6316b9cfc59b5e5e4d9199fef201c6f9f0f000000000900ab6552656a5165acffffffff02e8ce62040000000002515312ce3e00000000000251513f119316", single_tx) { return false; }
    let all_h, aok = sighash(all_tx, [], 1, 546970113);
    if !aok || !eq_hex(all_h, "5dafb920b336798020f551a730531ca12dd2262f882c3202f10a2755a15b816a") { return false; }
    let acp_h, cok = sighash(acp_tx, acp_script, 0, 1055317633);
    if !cok || !eq_hex(acp_h, "260b51392b87753cdea2fc9d9b04a4692554b37e911a372e4652ed6722b6217f") { return false; }
    let single_h, sok = sighash(single_tx, [], 0, 1541581667);
    if !sok || !eq_hex(single_h, "cd65fc057312fd175e12115be6022e048d126eb7bbdee0b081b3bbed7ea40d1e") { return false; }
    var secret: u8[32] = [0x11; 32];
    var der: u8[>..] = [];
    if !sign(secret, all_tx, [], 1, 546970113, der) { return false; }
    if !eq_hex(der, "304402205e840063271a46ab8ebba9bddab2bc345a2c757f24b3385678dc3505e490ab7402204a9de07a156ae501036fd67b21d19e547026d7be36cde5443627a0e8285d782001") { return false; }
    return true;
}

fn ::main() {
    if btc_legacy::self_check() { print("btc_legacy ok"); } else { print("btc_legacy FAIL"); exit(1); }
}
