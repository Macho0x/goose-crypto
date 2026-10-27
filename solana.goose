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

fn signed_ok(seed: u8[:], message: u8[:]) -> bool {
    let pk, pok = ed25519::public_key(seed);
    if !pok { return false; }
    let sig, sok = sign(seed, message);
    if !sok || !ed25519::verify(pk, message, sig) { return false; }
    sig[0] ^= 1;
    return !ed25519::verify(pk, message, sig);
}

fn self_check() -> bool {
    var cu: u8[>..] = [];
    append_cu16(cu, 128);
    if !eq_hex(cu, "8001") { return false; }
    var recent: u8[32] = [0; 32];
    var legacy: u8[>..] = [];
    begin(legacy, false, 2, 1, 3, 6);
    push_key(legacy, 4);
    push_key(legacy, 6);
    push_key(legacy, 3);
    push_key(legacy, 1);
    push_key(legacy, 2);
    push_key(legacy, 5);
    end_keys(legacy, recent, 4);
    var z4: u8[4] = [0; 4];
    push_ix(legacy, 3, [2], z4);
    push_ix(legacy, 3, [0], z4);
    push_ix(legacy, 4, [5], z4);
    push_ix(legacy, 4, [1], z4);
    var tagged: u8[>..] = [];
    append(tagged, "solana-tx-message-v1");
    append(tagged, legacy);
    if !eq_hex(blake3::hash(tagged), "607364cf524fa2c83a76c182fdacaf13137822dd716596464d5a2a02383927de") { return false; }
    var seed: u8[>..] = [];
    if !load_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed) { return false; }
    if !signed_ok(seed, legacy) { return false; }
    let payer, pok = ed25519::public_key(seed);
    if !pok || !eq_hex(payer, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a") { return false; }
    var memo: u8[>..] = [];
    if !load_hex("054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d", memo) { return false; }
    var note: u8[>..] = [];
    begin(note, false, 1, 0, 1, 2);
    append(note, payer);
    append(note, memo);
    end_keys(note, recent, 1);
    push_ix(note, 1, [0], "hello");
    if !signed_ok(seed, note) { return false; }
    var table: u8[32] = [0; 32];
    for i in 0..32 { table[i] = i as! u8; }
    var v0: u8[>..] = [];
    begin(v0, true, 1, 0, 1, 2);
    append(v0, payer);
    append(v0, memo);
    end_keys(v0, recent, 1);
    push_ix(v0, 1, [0], "hello");
    begin_lookups(v0, 1);
    push_lookup(v0, table, [0], [1, 2]);
    if !eq_hex(v0, "8001000102d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d0000000000000000000000000000000000000000000000000000000000000000010101000568656c6c6f01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0100020102") { return false; }
    if !signed_ok(seed, v0) { return false; }
    var off: u8[>..] = [];
    offchain(0, "Test Message", off);
    if !eq_hex(off, "ff736f6c616e61206f6666636861696e00000c0054657374204d657373616765") { return false; }
    if !signed_ok(seed, off) { return false; }
    return true;
}

fn ::main() {
    if solana::self_check() { print("solana ok"); } else { print("solana FAIL"); exit(1); }
}
