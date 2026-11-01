// Legacy Bitcoin sighash (SIGHASH_ALL, NONE, SINGLE, ANYONECANPAY) and
// strict DER encoding of the low-s ECDSA signature. The digest pinned
// below is the double SHA-256; Bitcoin Core prints that uint256 reversed.

import std;
import sha256;
import secp256k1;

namespace btc_legacy;

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
    if n == 254 {
        if at + 5 > b.len { return 0, at, false; }
        var v: i64 = 0;
        for i in 0..4 {
            let bi: i64 = b[at + 1 + i];
            v |= bi << (8 * i);
        }
        return v, at + 5, true;
    }
    if at + 9 > b.len { return 0, at, false; }
    var v: i64 = 0;
    for i in 0..8 {
        let bi: i64 = b[at + 1 + i];
        v |= bi << (8 * i);
    }
    return v, at + 9, true;
}

fn strip_codesep(script: u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < script.len {
        let op = script[i];
        i += 1;
        if op == 0xab { continue; }
        append_byte(out, op);
        var n: i64 = 0;
        var len_of_len = 0;
        if op >= 1 && op <= 75 {
            n = op;
        } else if op == 0x4c {
            len_of_len = 1;
        } else if op == 0x4d {
            len_of_len = 2;
        } else if op == 0x4e {
            len_of_len = 4;
        }
        if len_of_len > 0 {
            if i + len_of_len > script.len { return false; }
            n = 0;
            for k in 0..len_of_len {
                let bk: i64 = script[i + k];
                n |= bk << (8 * k);
            }
            append(out, script[i..i + len_of_len]);
            i += len_of_len;
        }
        if n < 0 || i + n > script.len { return false; }
        append(out, script[i..i + n]);
        i += n;
    }
    return true;
}

fn hash256(data: u8[:]) -> u8[32] { sha256::hash256(data) }

fn sighash(raw: u8[:], script: u8[:], n_in: i64, hash_type: u32) -> u8[32], bool {
    if raw.len < 10 || n_in < 0 { return [0; 32], false; }
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
    if !ok3 { return [0; 32], false; }
    at = at3;
    var vals: u8[>..] = [];
    var oscripts: u8[>..] = [];
    var olen: i64[>..] = [];
    for i in 0..n_out {
        if at + 8 > raw.len { return [0; 32], false; }
        append(vals, raw[at..at + 8]);
        at += 8;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl > raw.len { return [0; 32], false; }
        let nlen = olen.len;
        olen.resize(nlen + 1, 0);
        olen[nlen] = sl;
        append(oscripts, raw[at2..at2 + sl]);
        at = at2 + sl;
    }
    if at + 4 != raw.len { return [0; 32], false; }
    let base = hash_type & 0x1f;
    if n_in >= n_in_count || (base == 3 && n_in >= n_out) {
        var one: u8[32] = [0; 32];
        one[0] = 1;
        return one, true;
    }
    var code: u8[>..] = [];
    if !strip_codesep(script, code) { return [0; 32], false; }
    var pre: u8[>..] = [];
    append(pre, raw[..4]);
    let anyone = (hash_type & 0x80) != 0;
    var n_ser = n_in_count;
    if anyone { n_ser = 1; }
    append_cs(pre, n_ser);
    var first = 0;
    var last = n_in_count;
    if anyone {
        first = n_in;
        last = n_in + 1;
    }
    for i in first..last {
        append(pre, prevs[i * 36..(i + 1) * 36]);
        if i == n_in {
            append_cs(pre, code.len);
            append(pre, code);
        } else {
            append_byte(pre, 0);
        }
        if i != n_in && (base == 2 || base == 3) {
            append(pre, [0, 0, 0, 0]);
        } else {
            append(pre, seqs[i * 4..(i + 1) * 4]);
        }
    }
    var n_vout = n_out;
    if base == 2 { n_vout = 0; }
    if base == 3 { n_vout = n_in + 1; }
    append_cs(pre, n_vout);
    var off = 0;
    for i in 0..n_vout {
        if base == 3 && i < n_in {
            append(pre, [255, 255, 255, 255, 255, 255, 255, 255]);
            append_byte(pre, 0);
        } else {
            append(pre, vals[i * 8..(i + 1) * 8]);
            append_cs(pre, olen[i]);
            append(pre, oscripts[off..off + olen[i]]);
        }
        off += olen[i];
    }
    append(pre, raw[raw.len - 4..]);
    append_u32(pre, hash_type);
    return hash256(pre), true;
}

fn der_int(out: u8[>..]&, be: u8[:]) {
    var i = 0;
    while i < be.len - 1 && be[i] == 0 { i += 1; }
    let high = (be[i] & 0x80) != 0;
    var n = be.len - i;
    if high { n += 1; }
    append_byte(out, 2);
    append_byte(out, n as! u8);
    if high { append_byte(out, 0); }
    append(out, be[i..]);
}

fn encode_der(sig: u8[:], hash_type: u32, out: u8[>..]&) -> bool {
    if sig.len != 64 { return false; }
    var body: u8[>..] = [];
    der_int(body, sig[..32]);
    der_int(body, sig[32..]);
    append_byte(out, 0x30);
    append_byte(out, body.len as! u8);
    append(out, body);
    append_byte(out, hash_type as! u8);
    return true;
}

fn sign(secret: u8[:], raw: u8[:], script: u8[:], n_in: i64, hash_type: u32, out: u8[>..]&) -> bool {
    let dig, ok = sighash(raw, script, n_in, hash_type);
    if !ok { return false; }
    let sig, sok, _ = secp256k1::sign(secret, dig);
    if !sok { return false; }
    return encode_der(sig, hash_type, out);
}
