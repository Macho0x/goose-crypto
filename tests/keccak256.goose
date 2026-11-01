import crypto from "..";
import crypto.keccak256;

namespace keccak256;

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

fn self_check() -> bool {
    if !hash("").eq_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") { return false; }
    if !hash("abc").eq_hex("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45") { return false; }
    var a136: u8[136] = ['a'; 136];
    if !hash(a136).eq_hex("a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e") { return false; }
    var a137: u8[137] = ['a'; 137];
    if !hash(a137).eq_hex("d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39") { return false; }
    var seq: u8[200] = [0; 200];
    for i in 0..200 { seq[i] = i as! u8; }
    if !hash(seq).eq_hex("bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890") { return false; }
    var shifted: u8[201] = [0; 201];
    for i in 0..200 { shifted[i + 1] = seq[i]; }
    if hash(shifted[1..]) != hash(seq) { return false; }
    for cut in [135, 136, 137] {
        var c: Ctx = default<Ctx>();
        update(c, seq[..cut]);
        update(c, seq[cut..]);
        if finish(c) != hash(seq) { return false; }
    }
    return true;
}

fn ::main() {
    if keccak256::self_check() { print("keccak256 ok"); } else { print("keccak256 FAIL"); exit(1); }
}
