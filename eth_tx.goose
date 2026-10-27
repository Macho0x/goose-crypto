// Ethereum transaction signing hashes. One RLP writer covers legacy
// transactions, EIP-155, and typed transactions 0x01, 0x02, 0x03, 0x04.
// An EIP-7702 authorization is the 0x05 payload. Blob sidecars are not
// encoded: type 0x03 hashes the versioned hashes only. Typed y-parity is
// 0 or 1. Legacy v is 27 or 28, or chainId * 2 + 35 + recid under EIP-155.

import std;
import keccak256;
import secp256k1;

namespace eth_tx;

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

fn rlp_head(out: u8[>..]&, base: i64, n: i64) {
    if n < 56 {
        append_byte(out, (base + n) as! u8);
        return;
    }
    var be: u8[8] = [0; 8];
    var v = n;
    var c = 0;
    while v > 0 {
        be[7 - c] = (v & 255) as! u8;
        v = v >> 8;
        c += 1;
    }
    append_byte(out, (base + 55 + c) as! u8);
    append(out, be[8 - c..]);
}

fn rlp_bytes(out: u8[>..]&, data: u8[:]) {
    if data.len == 1 && data[0] < 0x80 {
        append_byte(out, data[0]);
        return;
    }
    rlp_head(out, 0x80, data.len);
    append(out, data);
}

fn rlp_u64(out: u8[>..]&, n: u64) {
    if n == 0 {
        rlp_bytes(out, []);
        return;
    }
    var tmp: u8[8] = [0; 8];
    var v = n;
    var i = 8;
    while v > 0 {
        i -= 1;
        tmp[i] = v as! u8;
        v = v >> 8;
    }
    rlp_bytes(out, tmp[i..]);
}

fn rlp_int(out: u8[>..]&, src: u8[:]) {
    var i = 0;
    while i < src.len && src[i] == 0 { i += 1; }
    rlp_bytes(out, src[i..]);
}

fn rlp_list(out: u8[>..]&, payload: u8[:]) {
    rlp_head(out, 0xc0, payload.len);
    append(out, payload);
}

fn hash_legacy(list: u8[:]) -> u8[32] { keccak256::hash(list) }

fn hash_typed(ty: u8, list: u8[:]) -> u8[32] {
    var b: u8[>..] = [];
    append_byte(b, ty);
    append(b, list);
    return keccak256::hash(b);
}

fn sign_hash(secret: u8[:], dig: u8[:]) -> u8[65], bool {
    let sig, ok, v = secp256k1::sign(secret, dig);
    if !ok || v < 27 || v > 28 { return [0; 65], false; }
    var out: u8[65] = [0; 65];
    for i in 0..64 { out[i] = sig[i]; }
    out[64] = v;
    return out, true;
}

fn eip155_v(chain_id: u64, v: u8) -> u64 { chain_id * 2 + 35 + (v - 27) }

fn nibble(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn eq_hex(got: u8[:], hex: u8[:]) -> bool {
    if got.len * 2 != hex.len { return false; }
    for i in 0..got.len {
        let hv = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
        if got[i] != hv { return false; }
    }
    return true;
}

fn unhex(hex: u8[:], out: u8[:]) {
    for i in 0..out.len { out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]); }
}

fn append_access(out: u8[>..]&, addr: u8[:], slot: u8[:]) {
    var keys: u8[>..] = [];
    rlp_bytes(keys, slot);
    var keylist: u8[>..] = [];
    rlp_list(keylist, keys);
    var item: u8[>..] = [];
    rlp_bytes(item, addr);
    append(item, keylist);
    var itemlist: u8[>..] = [];
    rlp_list(itemlist, item);
    var al: u8[>..] = [];
    rlp_list(al, itemlist);
    append(out, al);
}

fn append_empty_list(out: u8[>..]&) {
    var e: u8[>..] = [];
    var l: u8[>..] = [];
    rlp_list(l, e);
    append(out, l);
}

fn wrap(payload: u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    rlp_list(out, payload);
    return out;
}

fn self_check() -> bool {
    var to1: u8[20] = [0; 20];
    var to2: u8[20] = [0; 20];
    var acc: u8[20] = [0; 20];
    var auth_to: u8[20] = [0; 20];
    var slot: u8[32] = [0; 32];
    var data: u8[6] = [0; 6];
    var data4: u8[4] = [0; 4];
    var vh: u8[32] = [0; 32];
    var secret: u8[32] = [0; 32];
    var secret2: u8[32] = [0; 32];
    unhex("f0109fc8df283027b6285cc889f5aa624eac1f55", to1);
    unhex("09616c3d61b3331fc4109a9e41a8bdb7d9776609", to2);
    unhex("0000000000000000000000000000000000000001", acc);
    unhex("5ce9454909639d2d17a3f753ce7d93fa0b9ab12e", auth_to);
    unhex("0100000000000000000000000000000000000000000000000000000000000000", slot);
    unhex("616263646566", data);
    unhex("252dba42", data4);
    unhex("010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014", vh);
    unhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", secret);
    for i in 0..32 { secret2[i] = 0xaa; }

    var leg: u8[>..] = [];
    rlp_u64(leg, 0);
    rlp_u64(leg, 0xd55698372431);
    rlp_u64(leg, 0x1e8480);
    rlp_bytes(leg, to1);
    rlp_u64(leg, 0x3b9aca00);
    rlp_bytes(leg, []);
    rlp_u64(leg, 1337);
    rlp_u64(leg, 0);
    rlp_u64(leg, 0);
    let leg_list = wrap(leg);
    if !hash_legacy(leg_list).eq_hex("707e8a9c04307913a1b4460dcafbe0b379e5a64fd3a5dfab1a5ab837a5346a08") { return false; }

    var bare: u8[>..] = [];
    rlp_u64(bare, 0);
    rlp_u64(bare, 0xd55698372431);
    rlp_u64(bare, 0x1e8480);
    rlp_bytes(bare, to1);
    rlp_u64(bare, 0x3b9aca00);
    rlp_bytes(bare, []);
    let bare_list = wrap(bare);
    if !hash_legacy(bare_list).eq_hex("4a1b248a77d82640e1bb1e855a73e56649b78da87861417574fb2a040e15ca0e") { return false; }

    var t2: u8[>..] = [];
    rlp_u64(t2, 1337);
    rlp_u64(t2, 34);
    rlp_u64(t2, 0x77359400);
    rlp_u64(t2, 0x77359400);
    rlp_u64(t2, 100000);
    rlp_bytes(t2, to2);
    rlp_u64(t2, 0x5af3107a4000);
    rlp_bytes(t2, data);
    append_access(t2, acc, slot);
    let t2_list = wrap(t2);
    if !hash_typed(2, t2_list).eq_hex("f9d9fb14a72d4ddc843330cc31437f54a5982deced79ec0e7594fefe75369607") { return false; }

    var t1: u8[>..] = [];
    rlp_u64(t1, 1337);
    rlp_u64(t1, 34);
    rlp_u64(t1, 1000000000);
    rlp_u64(t1, 100000);
    rlp_bytes(t1, to2);
    rlp_u64(t1, 0x5af3107a4000);
    rlp_bytes(t1, data);
    append_access(t1, acc, slot);
    let t1_list = wrap(t1);
    if !hash_typed(1, t1_list).eq_hex("8de4f33b0313518b37aaed6c3282cba12320e08a709506b1cc45bf829d34dfaa") { return false; }

    var t3: u8[>..] = [];
    rlp_u64(t3, 1337);
    rlp_u64(t3, 34);
    rlp_u64(t3, 0x77359400);
    rlp_u64(t3, 0x77359400);
    rlp_u64(t3, 100000);
    rlp_bytes(t3, to2);
    rlp_u64(t3, 0x5af3107a4000);
    rlp_bytes(t3, data);
    append_access(t3, acc, slot);
    rlp_u64(t3, 0x77359400);
    var hashes: u8[>..] = [];
    rlp_bytes(hashes, vh);
    var hashlist: u8[>..] = [];
    rlp_list(hashlist, hashes);
    append(t3, hashlist);
    let t3_list = wrap(t3);
    if !hash_typed(3, t3_list).eq_hex("f626cf5eb491c35cd2f7ed36c841f1ec4472964dc661d85f7d6188e80f33b34c") { return false; }

    var auth: u8[>..] = [];
    rlp_u64(auth, 1337);
    rlp_bytes(auth, auth_to);
    rlp_u64(auth, 1);
    let auth_list = wrap(auth);
    if !hash_typed(5, auth_list).eq_hex("9026f77ed6740d6d08f0cdc0591a86b2232700020a816718fbf760785e9ca2f2") { return false; }

    var ar: u8[32] = [0; 32];
    var asg: u8[32] = [0; 32];
    unhex("735375048fc96b87390b5a11c411fc57245d8e55038bf49e659d048a0d1a3f87", ar);
    unhex("7f4b3db448845cb217812f23c6b345e99f2d21c44ec10e93a8f0398141674171", asg);
    var t4: u8[>..] = [];
    rlp_u64(t4, 1337);
    rlp_u64(t4, 0);
    rlp_u64(t4, 0x77359400);
    rlp_u64(t4, 0x77359400);
    rlp_u64(t4, 100000);
    rlp_bytes(t4, to2);
    rlp_u64(t4, 0);
    rlp_bytes(t4, data4);
    append_empty_list(t4);
    var one: u8[>..] = [];
    rlp_u64(one, 1337);
    rlp_bytes(one, auth_to);
    rlp_u64(one, 1);
    rlp_u64(one, 0);
    rlp_int(one, ar);
    rlp_int(one, asg);
    var one_list: u8[>..] = [];
    rlp_list(one_list, one);
    var alist: u8[>..] = [];
    rlp_list(alist, one_list);
    append(t4, alist);
    let t4_list = wrap(t4);
    if !hash_typed(4, t4_list).eq_hex("aff5dd5b3a1de0d8e5fe43108ff4ff0f8a25893ca3db7bb5e9e373a04c4b0442") { return false; }

    let sig, ok = sign_hash(secret, hash_legacy(leg_list));
    if !ok { return false; }
    var signed_leg: u8[>..] = [];
    rlp_u64(signed_leg, 0);
    rlp_u64(signed_leg, 0xd55698372431);
    rlp_u64(signed_leg, 0x1e8480);
    rlp_bytes(signed_leg, to1);
    rlp_u64(signed_leg, 0x3b9aca00);
    rlp_bytes(signed_leg, []);
    rlp_u64(signed_leg, eip155_v(1337, sig[64]));
    rlp_int(signed_leg, sig[..32]);
    rlp_int(signed_leg, sig[32..64]);
    let raw_leg = wrap(signed_leg);
    if !raw_leg.eq_hex("f86c8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080820a95a01a777e59c2d0a306100b47a8fa5c282fcd83bd27a3e8231b8ef06557dc59f3efa04e3008ddb9d39f498ebaab16e3bd94c1b0961b7cefea6e0c5dbfb886c0bfdb52") { return false; }

    let sig2, ok2 = sign_hash(secret, hash_typed(2, t2_list));
    if !ok2 { return false; }
    rlp_u64(t2, sig2[64] - 27);
    rlp_int(t2, sig2[..32]);
    rlp_int(t2, sig2[32..64]);
    var raw2: u8[>..] = [];
    append_byte(raw2, 2);
    var t2s = wrap(t2);
    append(raw2, t2s);
    if !raw2.eq_hex("02f8b28205392284773594008477359400830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107a400086616263646566f838f7940000000000000000000000000000000000000001e1a0010000000000000000000000000000000000000000000000000000000000000001a06c38b2e120203461c37a7b1a90955f9fe12a44c2de898b2a6ba859567d4e2861a0027b9e7869127b2046f0e34c37ef06df68a3f397430c7a9bf757ff31d58b85d5") { return false; }

    let sig3, ok3 = sign_hash(secret2, hash_typed(5, auth_list));
    if !ok3 || sig3[64] != 27 || !sig3[..64].eq_hex("735375048fc96b87390b5a11c411fc57245d8e55038bf49e659d048a0d1a3f877f4b3db448845cb217812f23c6b345e99f2d21c44ec10e93a8f0398141674171") { return false; }
    let sig4, ok4 = sign_hash(secret2, hash_typed(4, t4_list));
    if !ok4 || sig4[64] != 27 || !sig4[..64].eq_hex("03df7bf9b159102517af620ce9628e6e410fb4e344401fbc751d1a08ecdf1421211891d57b39127b3543100711f0b414e2859e14725b7dfcafe954b17ce8762a") { return false; }
    let sig5, ok5 = sign_hash(secret, hash_typed(3, t3_list));
    if !ok5 || sig5[64] != 28 || !sig5[..64].eq_hex("1fa8cdf1749d48b9e42449322eef29b8d8ee5ee42c796657d480488be1a88f86142eef79fae43607842a3a8028892fd10f08dad5a459d70df3991f8f3fc2f2a1") { return false; }
    return true;
}

fn ::main() {
    if eth_tx::self_check() { print("eth_tx ok"); } else { print("eth_tx FAIL"); exit(1); }
}
