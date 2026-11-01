import crypto from "..";
import crypto.bip322;
import crypto.bip340;
import crypto.btc_taproot;

namespace bip322;

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

fn check_tx(msg: u8[:], challenge: u8[:], spend_hex: u8[:], sign_hex: u8[:]) -> bool {
    var spend: u8[>..] = [];
    var sign: u8[>..] = [];
    build_spend(msg, challenge, spend);
    build_sign(spend, sign);
    return eq_hex(txid(spend), spend_hex) && eq_hex(txid(sign), sign_hex);
}

fn self_check() -> bool {
    var challenge: u8[>..] = [];
    var code: u8[>..] = [];
    var utf8: u8[>..] = [];
    var secret: u8[>..] = [];
    var tr_secret: u8[>..] = [];
    if !load_hex("00142b05d564e6a7a33c087f16e0f730d1440123799d", challenge) { return false; }
    if !load_hex("76a9142b05d564e6a7a33c087f16e0f730d1440123799d88ac", code) { return false; }
    if !load_hex("5554462d3820737570706f72743a20c3b6c3a4c3bcc3a9c3a0c3a820e6b58be8af95e69687e69cac20f09f9884", utf8) { return false; }
    if !load_hex("bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004", secret) { return false; }
    if !load_hex("4e9159a8a0f5f20606364cd9b23c1e6df363367c29a658ef4a881444afb0164e", tr_secret) { return false; }
    if !eq_hex(message_hash("Hello World"), "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a") { return false; }
    if !check_tx("", challenge, "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7", "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6") { return false; }
    if !check_tx("Hello World", challenge, "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b", "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf") { return false; }
    if !check_tx(utf8, challenge, "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0", "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586") { return false; }
    var pkh: u8[>..] = [];
    if !prove_p2pkh(secret, "Hello World", code, pkh) { return false; }
    if !eq_hex(pkh, "47304402207786329841c9bf2864ec6a5077238922c47dfeb83c87433b753cde5c04626cbd02202674714955886e28e63124fb567c46a48f0e38253fb64cbc3e0ed41f91e04ade012102c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872") { return false; }
    var wpkh: u8[>..] = [];
    if !prove_p2wpkh(secret, "Hello World", challenge, code, wpkh) { return false; }
    if !eq_hex(wpkh, "02483045022100ecf2ca796ab7dde538a26bfb09a6c487a7b3fff33f397db6a20eb9af77c0ee8c022062e67e44c8070f49c3a37f5940a8850842daf7cca35e6af61a6c7c91f1e1a1a3012102c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872") { return false; }
    let ipk, iok = bip340::public_key(tr_secret);
    if !iok { return false; }
    let q, _, qok = btc_taproot::tweak_public(ipk, []);
    if !qok { return false; }
    var tr_script: u8[34] = [0; 34];
    tr_script[0] = 0x51;
    tr_script[1] = 0x20;
    for i in 0..32 { tr_script[2 + i] = q[i]; }
    var spend: u8[>..] = [];
    var sign: u8[>..] = [];
    build_spend("No prefix fallback", tr_script, spend);
    build_sign(spend, sign);
    var amounts: u8[8] = [0; 8];
    var scripts: u8[>..] = [];
    append_cs(scripts, 34);
    append(scripts, tr_script);
    let dig, dok = btc_taproot::sighash(sign, amounts, scripts, 0, 0, 0, [], 0, 0);
    if !dok || !eq_hex(dig, "ba9488371fa8a87c8fbd559a91beba08be7db49960f20d1372d295307df576cd") { return false; }
    var pubsig: u8[>..] = [];
    if !load_hex("8960ec0e8f1600bdab5300661a565357055c85b9ce0cc0d4243ae2b6b65f3185f28338d7743637d8c8d498711a9e0a9f21b009c210f1c054490ef61eaf6d0fd1", pubsig) { return false; }
    if !bip340::verify(q, dig, pubsig) { return false; }
    var aux: u8[32] = [0; 32];
    var tr: u8[>..] = [];
    if !prove_p2tr(tr_secret, "No prefix fallback", aux, tr) { return false; }
    if tr.len != 66 || !bip340::verify(q, dig, tr[2..]) { return false; }
    return true;
}

fn ::main() {
    if bip322::self_check() { print("bip322 ok"); } else { print("bip322 FAIL"); exit(1); }
}
