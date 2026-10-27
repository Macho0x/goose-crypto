// Simple BIP-322 proofs. A tagged message hash goes into a virtual
// to_spend transaction, and to_sign spends that output to OP_RETURN.
// P2PKH uses the legacy sighash, P2WPKH uses BIP-143, and P2TR signs
// the key-path sighash with the tweaked key.

import std;
import sha256;
import secp256k1;
import bip340;
import btc_legacy;
import btc_segwit;
import btc_taproot;

namespace bip322;

fn append(out: u8[>..]&, src: u8[:]) {
    if src.len == 0 { return; }
    let n = out.len;
    out.resize(n + src.len, 0);
    for i in 0..src.len { out[n + i] = src[i]; }
}

fn append_byte(out: u8[>..]&, b: u8) {
    let n = out.len;
    out.resize(n + 1, 0);
    out[n] = b;
}

fn append_cs(out: u8[>..]&, n: i64) {
    if n < 253 {
        append_byte(out, n as! u8);
        return;
    }
    append_byte(out, 253);
    append_byte(out, n as! u8);
    append_byte(out, (n >> 8) as! u8);
}

fn zeros(out: u8[>..]&, n: i64) {
    let at = out.len;
    out.resize(at + n, 0);
}

fn message_hash(msg: u8[:]) -> u8[32] { bip340::tagged("BIP0322-signed-message", msg, msg[..0], msg[..0]) }

fn hash256(data: u8[:]) -> u8[32] { sha256::hash(sha256::hash(data)) }

fn txid(raw: u8[:]) -> u8[32] {
    let h = hash256(raw);
    var o: u8[32] = [0; 32];
    for i in 0..32 { o[i] = h[31 - i]; }
    return o;
}

fn build_spend(msg: u8[:], challenge: u8[:], out: u8[>..]&) {
    let mh = message_hash(msg);
    zeros(out, 4);
    append_byte(out, 1);
    zeros(out, 32);
    append_byte(out, 255);
    append_byte(out, 255);
    append_byte(out, 255);
    append_byte(out, 255);
    append_cs(out, 34);
    append_byte(out, 0);
    append_byte(out, 32);
    append(out, mh);
    zeros(out, 4);
    append_byte(out, 1);
    zeros(out, 8);
    append_cs(out, challenge.len);
    append(out, challenge);
    zeros(out, 4);
}

fn build_sign(spend: u8[:], out: u8[>..]&) {
    let prev = hash256(spend);
    zeros(out, 4);
    append_byte(out, 1);
    append(out, prev);
    zeros(out, 4);
    append_byte(out, 0);
    zeros(out, 4);
    append_byte(out, 1);
    zeros(out, 8);
    append_byte(out, 1);
    append_byte(out, 0x6a);
    zeros(out, 4);
}

fn prove_p2pkh(secret: u8[:], msg: u8[:], script: u8[:], out: u8[>..]&) -> bool {
    var spend: u8[>..] = [];
    var sign: u8[>..] = [];
    build_spend(msg, script, spend);
    build_sign(spend, sign);
    var der: u8[>..] = [];
    if !btc_legacy::sign(secret, sign, script, 0, 1, der) { return false; }
    let pk, ok = secp256k1::pubkey_compressed(secret);
    if !ok { return false; }
    append_cs(out, der.len);
    append(out, der);
    append_cs(out, 33);
    append(out, pk);
    return true;
}

fn prove_p2wpkh(secret: u8[:], msg: u8[:], challenge: u8[:], script_code: u8[:], out: u8[>..]&) -> bool {
    var spend: u8[>..] = [];
    var sign: u8[>..] = [];
    build_spend(msg, challenge, spend);
    build_sign(spend, sign);
    var amount: u8[8] = [0; 8];
    var der: u8[>..] = [];
    if !btc_segwit::sign(secret, sign, script_code, amount, 0, 1, der) { return false; }
    let pk, ok = secp256k1::pubkey_compressed(secret);
    if !ok { return false; }
    append_byte(out, 2);
    append_cs(out, der.len);
    append(out, der);
    append_byte(out, 33);
    append(out, pk);
    return true;
}

fn prove_p2tr(secret: u8[:], msg: u8[:], aux: u8[:], out: u8[>..]&) -> bool {
    let ipk, iok = bip340::public_key(secret);
    if !iok { return false; }
    let q, _, qok = btc_taproot::tweak_public(ipk, []);
    if !qok { return false; }
    var challenge: u8[34] = [0; 34];
    challenge[0] = 0x51;
    challenge[1] = 0x20;
    for i in 0..32 { challenge[2 + i] = q[i]; }
    var spend: u8[>..] = [];
    var sign: u8[>..] = [];
    build_spend(msg, challenge, spend);
    build_sign(spend, sign);
    var amounts: u8[8] = [0; 8];
    var scripts: u8[>..] = [];
    append_cs(scripts, 34);
    append(scripts, challenge);
    var sig: u8[>..] = [];
    if !btc_taproot::sign_key(secret, sign, amounts, scripts, 0, 0, [], aux, sig) { return false; }
    append_byte(out, 1);
    append_cs(out, sig.len);
    append(out, sig);
    return true;
}

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
