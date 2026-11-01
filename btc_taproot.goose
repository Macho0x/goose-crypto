// BIP-341 Taproot. Tagged TapTweak, TapLeaf, and TapBranch hashes, the
// epoch-0 sighash, a key-path spend of the tweaked key, and a script-path
// spend that signs an already-built tapleaf hash.

import std;
import sha256;
import secp256k1;
import bip340;

namespace btc_taproot;

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

fn tag(name: u8[:], a: u8[:], b: u8[:]) -> u8[32] { bip340::tagged(name, a, b, a[..0]) }

fn less(a: u8[:], b: u8[:]) -> bool {
    let n = a.len;
    if b.len < n { return false; }
    for i in 0..n {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    return false;
}

fn tapleaf(version: u8, script: u8[:]) -> u8[32] {
    var body: u8[>..] = [];
    append_byte(body, version);
    append_cs(body, script.len);
    append(body, script);
    return tag("TapLeaf", body, body[..0]);
}

fn tapbranch(a: u8[:], b: u8[:]) -> u8[32], bool {
    if a.len != 32 || b.len != 32 { return [0; 32], false; }
    if less(b, a) { return tag("TapBranch", b, a), true; }
    return tag("TapBranch", a, b), true;
}

fn tweak_bytes(pk: u8[:], merkle: u8[:]) -> u8[32], bool {
    if pk.len != 32 { return [0; 32], false; }
    return tag("TapTweak", pk, merkle), true;
}

fn tweak_public(pk: u8[:], merkle: u8[:]) -> u8[32], u8, bool {
    let tb, ok = tweak_bytes(pk, merkle);
    if !ok { return [0; 32], 0, false; }
    let t = secp256k1::load_be(tb);
    if secp256k1::gte8(t, secp256k1::order()) { return [0; 32], 0, false; }
    let p, pok = bip340::lift_x(pk);
    if !pok { return [0; 32], 0, false; }
    let x, odd, qok = bip340::xonly(secp256k1::pt_add(p, secp256k1::pt_mul(secp256k1::base(), t)));
    if !qok { return [0; 32], 0, false; }
    return x, odd as! u8, true;
}

fn tweak_secret(secret: u8[:], merkle: u8[:]) -> u8[32], bool {
    let d0, ok = secp256k1::secret_ok(secret);
    if !ok { return [0; 32], false; }
    let px, odd, pok = bip340::xonly(secp256k1::pt_mul(secp256k1::base(), d0));
    if !pok { return [0; 32], false; }
    var d = d0;
    if odd == 1 { d = bip340::negate_scalar(d0); }
    let tb, tok = tweak_bytes(px, merkle);
    if !tok { return [0; 32], false; }
    let t = secp256k1::load_be(tb);
    if secp256k1::gte8(t, secp256k1::order()) { return [0; 32], false; }
    let sum = secp256k1::sc_add(d, t);
    if secp256k1::is_zero(sum) { return [0; 32], false; }
    var o: u8[32] = [0; 32];
    secp256k1::store_be(sum, o);
    return o, true;
}

fn scripts_ok(scripts: u8[:], n: i64) -> bool {
    var at = 0;
    for i in 0..n {
        let sl, at2, ok = read_cs(scripts, at);
        if !ok || at2 + sl > scripts.len { return false; }
        at = at2 + sl;
    }
    return at == scripts.len;
}

fn script_span(scripts: u8[:], index: i64) -> i64, i64, bool {
    var at = 0;
    for i in 0..index + 1 {
        let sl, at2, ok = read_cs(scripts, at);
        if !ok || at2 + sl > scripts.len { return 0, 0, false; }
        if i == index { return at, at2 + sl - at, true; }
        at = at2 + sl;
    }
    return 0, 0, false;
}

fn hash_type_ok(ht: u8) -> bool {
    return ht == 0 || ht == 1 || ht == 2 || ht == 3 || ht == 0x81 || ht == 0x82 || ht == 0x83;
}

fn sigmsg(raw: u8[:], amounts: u8[:], scripts: u8[:], n_in: i64, hash_type: u8, ext: u8, leaf: u8[:], key_version: u8, codesep: u32, msg: u8[>..]&) -> bool {
    if !hash_type_ok(hash_type) || ext > 1 || n_in < 0 || raw.len < 10 { return false; }
    if ext == 1 && leaf.len != 32 { return false; }
    let n_vin, at1, ok1 = read_cs(raw, 4);
    if !ok1 || amounts.len != n_vin * 8 || !scripts_ok(scripts, n_vin) { return false; }
    var prevs: u8[>..] = [];
    var seqs: u8[>..] = [];
    var at = at1;
    for i in 0..n_vin {
        if at + 36 > raw.len { return false; }
        append(prevs, raw[at..at + 36]);
        at += 36;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl + 4 > raw.len { return false; }
        at = at2 + sl;
        append(seqs, raw[at..at + 4]);
        at += 4;
    }
    let n_out, at3, ok3 = read_cs(raw, at);
    if !ok3 || n_in >= n_vin { return false; }
    at = at3;
    var outs: u8[>..] = [];
    var olen: i64[>..] = [];
    var ostart: i64[>..] = [];
    for i in 0..n_out {
        let start = at;
        if at + 8 > raw.len { return false; }
        at += 8;
        let sl, at2, ok = read_cs(raw, at);
        if !ok || at2 + sl > raw.len { return false; }
        at = at2 + sl;
        let nlen = olen.len;
        olen.resize(nlen + 1, 0);
        ostart.resize(nlen + 1, 0);
        ostart[nlen] = outs.len;
        append(outs, raw[start..at]);
        olen[nlen] = outs.len - ostart[nlen];
    }
    if at + 4 != raw.len { return false; }
    let base = hash_type & 3;
    if base == 3 && n_in >= n_out { return false; }
    let anyone = (hash_type & 0x80) != 0;
    append_byte(msg, 0);
    append_byte(msg, hash_type);
    append(msg, raw[..4]);
    append(msg, raw[raw.len - 4..]);
    if !anyone {
        append(msg, sha256::hash(prevs));
        append(msg, sha256::hash(amounts));
        append(msg, sha256::hash(scripts));
        append(msg, sha256::hash(seqs));
    }
    if base != 2 && base != 3 { append(msg, sha256::hash(outs)); }
    var spend: u8 = 0;
    if ext == 1 { spend = 2; }
    append_byte(msg, spend);
    if anyone {
        append(msg, prevs[n_in * 36..(n_in + 1) * 36]);
        append(msg, amounts[n_in * 8..(n_in + 1) * 8]);
        let ss, sl, sok = script_span(scripts, n_in);
        if !sok { return false; }
        append(msg, scripts[ss..ss + sl]);
        append(msg, seqs[n_in * 4..(n_in + 1) * 4]);
    } else {
        append_u32(msg, n_in as! u32);
    }
    if base == 3 { append(msg, sha256::hash(outs[ostart[n_in]..ostart[n_in] + olen[n_in]])); }
    if ext == 1 {
        append(msg, leaf);
        append_byte(msg, key_version);
        append_u32(msg, codesep);
    }
    return true;
}

fn sighash(raw: u8[:], amounts: u8[:], scripts: u8[:], n_in: i64, hash_type: u8, ext: u8, leaf: u8[:], key_version: u8, codesep: u32) -> u8[32], bool {
    var msg: u8[>..] = [];
    if !sigmsg(raw, amounts, scripts, n_in, hash_type, ext, leaf, key_version, codesep, msg) { return [0; 32], false; }
    return tag("TapSighash", msg, msg[..0]), true;
}

fn sign_key(secret: u8[:], raw: u8[:], amounts: u8[:], scripts: u8[:], n_in: i64, hash_type: u8, merkle: u8[:], aux: u8[:], out: u8[>..]&) -> bool {
    let tweaked, ok = tweak_secret(secret, merkle);
    if !ok { return false; }
    let dig, dok = sighash(raw, amounts, scripts, n_in, hash_type, 0, [], 0, 0);
    if !dok { return false; }
    let sig, sok = bip340::sign(tweaked, dig, aux);
    if !sok { return false; }
    append(out, sig);
    if hash_type != 0 { append_byte(out, hash_type); }
    return true;
}

fn sign_script(secret: u8[:], raw: u8[:], amounts: u8[:], scripts: u8[:], n_in: i64, hash_type: u8, leaf: u8[:], key_version: u8, codesep: u32, aux: u8[:], out: u8[>..]&) -> bool {
    let dig, dok = sighash(raw, amounts, scripts, n_in, hash_type, 1, leaf, key_version, codesep);
    if !dok { return false; }
    let sig, sok = bip340::sign(secret, dig, aux);
    if !sok { return false; }
    append(out, sig);
    if hash_type != 0 { append_byte(out, hash_type); }
    return true;
}
