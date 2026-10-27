// BIP-143 SegWit v0 sighash. The caller supplies scriptCode (P2WPKH or
// P2WSH) and the spent amount. The signature tail is strict DER.

import std;
import sha256;
import secp256k1;
import btc_legacy;

namespace btc_segwit;

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

fn append_u32(out: u8[>..]&, v: u32) {
    append_byte(out, v as! u8);
    append_byte(out, (v >> 8) as! u8);
    append_byte(out, (v >> 16) as! u8);
    append_byte(out, (v >> 24) as! u8);
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

fn read_cs(b: u8[:], at: i64) -> i64, i64, bool {
    if at >= b.len { return 0, at, false; }
    let n = b[at];
    if n < 253 { return n, at + 1, true; }
    if n == 253 {
        if at + 3 > b.len { return 0, at, false; }
        let b0: i64 = b[at + 1];
        let b1: i64 = b[at + 2];
        return b0 | (b1 << 8), at + 3, true;
    }
    return 0, at, false;
}

fn hash256(data: u8[:]) -> u8[32] { sha256::hash(sha256::hash(data)) }

fn zeros() -> u8[32] { return [0; 32]; }

fn sighash(raw: u8[:], script: u8[:], amount: u8[:], n_in: i64, hash_type: u32) -> u8[32], bool {
    if raw.len < 10 || amount.len != 8 || n_in < 0 { return [0; 32], false; }
    let n_in_count, at1, ok1 = read_cs(raw, 4);
    if !ok1 { return [0; 32], false; }
    var prevs: u8[>..] = [];
    var seqs: u8[>..] = [];
    var at = at1;
    for i in 0..n_in_count {
        if at + 36 > raw.len { return [0; 32], false; }
        append(prevs, raw[at..at + 36]);
        at += 36;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl + 4 > raw.len { return [0; 32], false; }
        at = at2 + sl;
        append(seqs, raw[at..at + 4]);
        at += 4;
    }
    let n_out, at3, ok3 = read_cs(raw, at);
    if !ok3 || n_in >= n_in_count { return [0; 32], false; }
    at = at3;
    var outs: u8[>..] = [];
    var olen: i64[>..] = [];
    var ostart: i64[>..] = [];
    for i in 0..n_out {
        let start = outs.len;
        if at + 8 > raw.len { return [0; 32], false; }
        append(outs, raw[at..at + 8]);
        at += 8;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl > raw.len { return [0; 32], false; }
        append_cs(outs, sl);
        append(outs, raw[at2..at2 + sl]);
        at = at2 + sl;
        let nlen = olen.len;
        olen.resize(nlen + 1, 0);
        ostart.resize(nlen + 1, 0);
        olen[nlen] = outs.len - start;
        ostart[nlen] = start;
    }
    if at + 4 != raw.len { return [0; 32], false; }
    let base = hash_type & 0x1f;
    let anyone = (hash_type & 0x80) != 0;
    var pre: u8[>..] = [];
    append(pre, raw[..4]);
    if anyone {
        append(pre, zeros());
    } else {
        append(pre, hash256(prevs));
    }
    if anyone || base == 2 || base == 3 {
        append(pre, zeros());
    } else {
        append(pre, hash256(seqs));
    }
    append(pre, prevs[n_in * 36..(n_in + 1) * 36]);
    append_cs(pre, script.len);
    append(pre, script);
    append(pre, amount);
    append(pre, seqs[n_in * 4..(n_in + 1) * 4]);
    if base == 2 || (base == 3 && n_in >= n_out) {
        append(pre, zeros());
    } else if base == 3 {
        append(pre, hash256(outs[ostart[n_in]..ostart[n_in] + olen[n_in]]));
    } else {
        append(pre, hash256(outs));
    }
    append(pre, raw[raw.len - 4..]);
    append_u32(pre, hash_type);
    return hash256(pre), true;
}

fn sign(secret: u8[:], raw: u8[:], script: u8[:], amount: u8[:], n_in: i64, hash_type: u32, out: u8[>..]&) -> bool {
    let dig, ok = sighash(raw, script, amount, n_in, hash_type);
    if !ok { return false; }
    let sig, sok, _ = secp256k1::sign(secret, dig);
    if !sok { return false; }
    return btc_legacy::encode_der(sig, hash_type, out);
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
