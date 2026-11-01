import crypto from "..";
import crypto.btc_taproot;
import crypto.bip340;

namespace btc_taproot;

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
