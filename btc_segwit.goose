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

fn hash256(data: u8[:]) -> u8[32] { sha256::hash256(data) }

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
