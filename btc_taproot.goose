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
    var amounts: u8[>..] = [];
    var scripts: u8[>..] = [];
    if !load_hex("02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d", raw) { return false; }
    if !load_hex("00b1081900000000808f891b000000008015861100000000006e0a1e0000000080098d250000000080d287160000000000e80d2800000000804c8b2000000000002b0c2300000000", amounts) { return false; }
    if !load_hex("22512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343225120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea31976a914751e76e8199196d454941c45d1b3a323f1433bd688ac225120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e22512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc217836051600147dd65592d0ab2fe0d0257d571abf032cd9db93dc22512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831225120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df522512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", scripts) { return false; }
    var msg: u8[>..] = [];
    if !sigmsg(raw, amounts, scripts, 0, 3, 0, [], 0, 0, msg) { return false; }
    if !eq_hex(msg, "0003020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e0000000000d0418f0e9a36245b9a50ec87f8bf5be5bcae434337b87139c3a5b1f56e33cba0") { return false; }
    let dig, dok = sighash(raw, amounts, scripts, 0, 3, 0, [], 0, 0);
    if !dok || !eq_hex(dig, "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555") { return false; }
    let acp, aok = sighash(raw, amounts, scripts, 1, 131, 0, [], 0, 0);
    if !aok || !eq_hex(acp, "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d") { return false; }
    var leaf_script: u8[>..] = [];
    if !load_hex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac", leaf_script) { return false; }
    if !eq_hex(tapleaf(192, leaf_script), "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21") { return false; }
    var left_script: u8[>..] = [];
    var right_script: u8[>..] = [];
    if !load_hex("20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac", left_script) { return false; }
    if !load_hex("06424950333431", right_script) { return false; }
    let branch, bok = tapbranch(tapleaf(192, left_script), tapleaf(250, right_script));
    if !bok || !eq_hex(branch, "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef") { return false; }
    var ipk: u8[>..] = [];
    if !load_hex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", ipk) { return false; }
    let tw, tok = tweak_bytes(ipk, []);
    if !tok || !eq_hex(tw, "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70") { return false; }
    let out_pk, _, pok = tweak_public(ipk, []);
    if !pok || !eq_hex(out_pk, "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343") { return false; }
    var secret: u8[>..] = [];
    if !load_hex("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa", secret) { return false; }
    let tsec, sok = tweak_secret(secret, []);
    if !sok || !eq_hex(tsec, "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9") { return false; }
    var aux: u8[32] = [0; 32];
    var wit: u8[>..] = [];
    if !sign_key(secret, raw, amounts, scripts, 0, 3, [], aux, wit) { return false; }
    if !eq_hex(wit, "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03") { return false; }
    let leaf = tapleaf(192, leaf_script);
    let sdig, sdok = sighash(raw, amounts, scripts, 0, 3, 1, leaf, 0, 0xffffffff);
    if !sdok || !eq_hex(sdig, "b31f228a306d5e2049631224a3f25e1c437a255ea7731aa4c6e3b32b97cf02a0") { return false; }
    var ssig: u8[>..] = [];
    if !sign_script(secret, raw, amounts, scripts, 0, 3, leaf, 0, 0xffffffff, aux, ssig) { return false; }
    if ssig.len != 65 { return false; }
    let pk, pkok = bip340::public_key(secret);
    if !pkok || !bip340::verify(pk, sdig, ssig[..64]) { return false; }
    return true;
}

fn ::main() {
    if btc_taproot::self_check() { print("btc_taproot ok"); } else { print("btc_taproot FAIL"); exit(1); }
}
