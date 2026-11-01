// Solana messages signed with Ed25519. Legacy and v0 transactions use
// compact-u16 lengths. A v0 message starts with 0x80 and ends with
// address-table lookups. Off-chain messages start with the 16-byte
// "\xffsolana offchain" domain from the current message spec.

import std;
import blake3;
import ed25519;

namespace solana;

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

fn append_cu16(out: u8[>..]&, n: i64) {
    var v = n;
    while true {
        let e = v & 0x7f;
        v = v >> 7;
        if v == 0 {
            append_byte(out, e as! u8);
            return;
        }
        append_byte(out, (e | 0x80) as! u8);
    }
}

fn push_key(out: u8[>..]&, first: u8) {
    append_byte(out, first);
    let n = out.len;
    out.resize(n + 31, 0);
}

fn begin(out: u8[>..]&, versioned: bool, required: u8, ro_signed: u8, ro_unsigned: u8, n_keys: i64) {
    if versioned { append_byte(out, 0x80); }
    append_byte(out, required);
    append_byte(out, ro_signed);
    append_byte(out, ro_unsigned);
    append_cu16(out, n_keys);
}

fn end_keys(out: u8[>..]&, recenthash: u8[:], n_ix: i64) {
    append(out, recenthash);
    append_cu16(out, n_ix);
}

fn push_ix(out: u8[>..]&, program: u8, accounts: u8[:], data: u8[:]) {
    append_byte(out, program);
    append_cu16(out, accounts.len);
    append(out, accounts);
    append_cu16(out, data.len);
    append(out, data);
}

fn begin_lookups(out: u8[>..]&, n: i64) { append_cu16(out, n); }

fn push_lookup(out: u8[>..]&, table: u8[:], writable: u8[:], readonly: u8[:]) {
    append(out, table);
    append_cu16(out, writable.len);
    append(out, writable);
    append_cu16(out, readonly.len);
    append(out, readonly);
}

fn offchain(format: u8, message: u8[:], out: u8[>..]&) {
    append(out, "\xffsolana offchain");
    append_byte(out, 0);
    append_byte(out, format);
    append_byte(out, message.len as! u8);
    append_byte(out, (message.len >> 8) as! u8);
    append(out, message);
}

fn sign(seed: u8[:], message: u8[:]) -> u8[64], bool { return ed25519::sign(seed, message); }
