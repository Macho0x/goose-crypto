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

fn hash256(data: u8[:]) -> u8[32] { sha256::hash256(data) }

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
