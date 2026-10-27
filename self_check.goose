// One pass over every module's published vector.

import os;
import sha256;
import keccak256;
import blake3;
import chacha20poly1305;
import x25519;
import ed25519;
import secp256k1;
import argon2id;
import eip712;
import eip191;
import eth_tx;
import bip340;
import btc_legacy;
import btc_segwit;
import btc_taproot;
import bip322;
import solana;

fn go(name: u8[:], ok: bool) -> bool {
    var line: u8[>..] = [];
    format(line, name);
    if ok { format(line, " ok\n"); } else { format(line, " FAIL\n"); }
    write_stdout(line);
    return ok;
}

fn ::main() {
    var all = true;
    if !go("sha256", sha256::self_check()) { all = false; }
    if !go("keccak256", keccak256::self_check()) { all = false; }
    if !go("blake3", blake3::self_check()) { all = false; }
    if !go("chacha20poly1305", chacha20poly1305::self_check()) { all = false; }
    if !go("x25519", x25519::self_check()) { all = false; }
    if !go("ed25519", ed25519::self_check()) { all = false; }
    if !go("secp256k1", secp256k1::self_check()) { all = false; }
    if !go("argon2id", argon2id::self_check()) { all = false; }
    if !go("eip712", eip712::self_check()) { all = false; }
    if !go("eip191", eip191::self_check()) { all = false; }
    if !go("eth_tx", eth_tx::self_check()) { all = false; }
    if !go("bip340", bip340::self_check()) { all = false; }
    if !go("btc_legacy", btc_legacy::self_check()) { all = false; }
    if !go("btc_segwit", btc_segwit::self_check()) { all = false; }
    if !go("btc_taproot", btc_taproot::self_check()) { all = false; }
    if !go("bip322", bip322::self_check()) { all = false; }
    if !go("solana", solana::self_check()) { all = false; }
    if !all { exit(1); }
    write_stdout("crypto ok\n");
}
