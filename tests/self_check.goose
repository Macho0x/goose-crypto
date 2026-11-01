import crypto from "..";
import crypto.sha256;
import .sha256;
import crypto.sha512;
import .sha512;
import crypto.ripemd160;
import .ripemd160;
import crypto.hkdf;
import .hkdf;
import crypto.keccak256;
import .keccak256;
import crypto.blake3;
import .blake3;
import crypto.chacha20poly1305;
import .chacha20poly1305;
import crypto.x25519;
import .x25519;
import crypto.ed25519;
import .ed25519;
import crypto.secp256k1;
import .secp256k1;
import crypto.argon2id;
import .argon2id;
import crypto.bip340;
import .bip340;

import os;

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
    if !go("sha512", sha512::self_check()) { all = false; }
    if !go("ripemd160", ripemd160::self_check()) { all = false; }
    if !go("hkdf", hkdf::self_check()) { all = false; }
    if !go("keccak256", keccak256::self_check()) { all = false; }
    if !go("blake3", blake3::self_check()) { all = false; }
    if !go("chacha20poly1305", chacha20poly1305::self_check()) { all = false; }
    if !go("x25519", x25519::self_check()) { all = false; }
    if !go("ed25519", ed25519::self_check()) { all = false; }
    if !go("secp256k1", secp256k1::self_check()) { all = false; }
    if !go("argon2id", argon2id::self_check()) { all = false; }
    if !go("bip340", bip340::self_check()) { all = false; }
    if !all { exit(1); }
    write_stdout("crypto ok\n");
}
