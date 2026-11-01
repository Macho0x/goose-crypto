import crypto from "..";
import crypto.solana;
import crypto.blake3;
import crypto.ed25519;

namespace solana;

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
