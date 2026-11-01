import crypto from "..";
import crypto.blake3;

namespace blake3;

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

fn pattern(n: i64) -> u8[2048] {
    var b: u8[2048] = [0; 2048];
    for i in 0..n { b[i] = (i % 251) as! u8; }
    return b;
}

fn self_check() -> bool {
    if !hash("").eq_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262") { return false; }
    var x: u8[64] = [0; 64];
    xof("", x);
    if !x.eq_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a") { return false; }
    let key = "whats the Elvish word for friend";
    let ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    if !keyed(key, "").eq_hex("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26") { return false; }
    if !derive_key(ctx, "").eq_hex("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d") { return false; }
    let p = pattern(2048);
    if !hash(p[..1]).eq_hex("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213") { return false; }
    if !hash(p[..1024]).eq_hex("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7") { return false; }
    if !hash(p[..1025]).eq_hex("d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444") { return false; }
    if !hash(p[..2048]).eq_hex("e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a") { return false; }
    if !keyed(key, p[..1024]).eq_hex("75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4") { return false; }
    if !derive_key(ctx, p[..1024]).eq_hex("7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706") { return false; }
    var h: Hasher = default<Hasher>();
    init(h);
    update(h, p[..100]);
    update(h, p[100..1024]);
    var out: u8[32] = [0; 32];
    finalize(h, out);
    if !out.eq_hex("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7") { return false; }
    return true;
}

fn ::main() {
    if blake3::self_check() { print("blake3 ok"); } else { print("blake3 FAIL"); exit(1); }
}
