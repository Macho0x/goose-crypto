// Times the primitive operations. One untimed batch, then batches until the
// window elapses. The first result byte is added into a sink printed at the
// end, so a later compiler pass cannot delete the call.
// ponytail: a fixed window, not a sampled harness. Rows under a microsecond
// move from run to run; lengthen the window before trusting them.

import os;
import sha256;
import keccak256;
import blake3;
import chacha20poly1305;
import x25519;
import ed25519;
import secp256k1;
import argon2id;
import bip340;
import eip191;

var secret: u8[32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
var buf32: u8[32] = [0x11; 32];
var buf4k: u8[4096] = [0x61; 4096];
var dig: u8[32] = [0x42; 32];
var live: u8[32] = [0x42; 32];
var aux: u8[32] = [0; 32];
var nonce: u8[12] = [9; 12];
var pw: u8[32] = [0x01; 32];
var salt: u8[16] = [0x02; 16];
var asecret: u8[8] = [0x03; 8];
var ad: u8[12] = [0x04; 12];
var secp_pk: u8[33] = [0; 33];
var secp_sig: u8[64] = [0; 64];
var ed_pub: u8[32] = [0; 32];
var ed_sig: u8[64] = [0; 64];
var bip_pk: u8[32] = [0; 32];
var bip_sig: u8[64] = [0; 64];
var sealed: u8[>..] = [];

fn copy_at(dst: u8[:], src: u8[:]) {
    for i in 0..src.len { dst[i] = src[i]; }
}

fn mark(b: u8, ok: bool) -> u64 {
    if !ok { return 0; }
    let v: u64 = b;
    return v + 1;
}

fn time_batch<F>(batch: i64, ms: i64) -> i64, u64 {
    var sink: u64 = 0;
    var k = 0;
    while k < batch {
        sink += F();
        k += 1;
    }
    var n: i64 = 0;
    var dt: i64 = 0;
    let end = clock_ns() + ms * 1000000;
    while true {
        let t0 = clock_ns();
        k = 0;
        while k < batch {
            sink += F();
            k += 1;
        }
        dt += clock_ns() - t0;
        n += batch;
        if clock_ns() >= end { break; }
    }
    return dt / n, sink;
}

fn row<F>(name: u8[:], batch: i64, ms: i64) -> u64 {
    let ns, part = time_batch(batch, ms, F);
    var line: u8[>..] = [];
    format(line, name);
    while line.len < 28 { line.push(' '); }
    format_int(line, ns, 10, 12, ' ');
    format(line, "\n");
    write_stdout(line);
    return part;
}

fn sha32() -> u64 {
    buf32[0] += 1;
    let d = sha256::hash(buf32);
    return mark(d[0], true);
}

fn sha4k() -> u64 {
    buf4k[0] += 1;
    let d = sha256::hash(buf4k);
    return mark(d[0], true);
}

fn kec0() -> u64 {
    let d = keccak256::hash("");
    return mark(d[0], true);
}

fn kec32() -> u64 {
    buf32[0] += 1;
    let d = keccak256::hash(buf32);
    return mark(d[0], true);
}

fn kec4k() -> u64 {
    buf4k[0] += 1;
    let d = keccak256::hash(buf4k);
    return mark(d[0], true);
}

fn blake32() -> u64 {
    buf32[0] += 1;
    let d = blake3::hash(buf32);
    return mark(d[0], true);
}

fn blake4k() -> u64 {
    buf4k[0] += 1;
    let d = blake3::hash(buf4k);
    return mark(d[0], true);
}

fn chacha32() -> u64 {
    sealed.resize(0, 0);
    let ok = chacha20poly1305::seal(secret, nonce, "", buf32, sealed);
    if !ok || sealed.len == 0 { return 0; }
    return mark(sealed[0], true);
}

fn x_pub() -> u64 {
    let out, ok = x25519::public_key(secret);
    return mark(out[0], ok);
}

fn ed_sign() -> u64 {
    live[0] += 1;
    let sig, ok = ed25519::sign(secret, live);
    return mark(sig[0], ok);
}

fn ed_verify() -> u64 {
    return mark(1, ed25519::verify(ed_pub, dig, ed_sig));
}

fn secp_sign() -> u64 {
    live[0] += 1;
    let sig, ok, _ = secp256k1::sign(secret, live);
    return mark(sig[0], ok);
}

fn secp_verify() -> u64 {
    return mark(1, secp256k1::verify(secp_pk, dig, secp_sig));
}

fn bip_sign() -> u64 {
    live[0] += 1;
    let sig, ok = bip340::sign(secret, live, aux);
    return mark(sig[0], ok);
}

fn bip_verify() -> u64 {
    return mark(1, bip340::verify(bip_pk, dig, bip_sig));
}

fn personal() -> u64 {
    let sig, ok = eip191::sign(secret, "hello world");
    return mark(sig[64], ok);
}

fn argon() -> u64 {
    var tag: u8[32] = [0; 32];
    let ok = argon2id::hash(pw, salt, asecret, ad, 32, 3, 4, tag);
    return mark(tag[0], ok);
}

fn ready() -> bool {
    let empty = keccak256::hash("");
    if !keccak256::eq_hex(empty, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") {
        return false;
    }
    let pk, pok = secp256k1::pubkey_compressed(secret);
    if !pok { return false; }
    copy_at(secp_pk, pk);
    let sig, ok, _ = secp256k1::sign(secret, dig);
    if !ok || !secp256k1::verify(secp_pk, dig, sig) { return false; }
    copy_at(secp_sig, sig);
    let ep, eok = ed25519::public_key(secret);
    if !eok { return false; }
    copy_at(ed_pub, ep);
    let es, esok = ed25519::sign(secret, dig);
    if !esok || !ed25519::verify(ed_pub, dig, es) { return false; }
    copy_at(ed_sig, es);
    let bp, bok = bip340::public_key(secret);
    if !bok { return false; }
    copy_at(bip_pk, bp);
    let bs, bsok = bip340::sign(secret, dig, aux);
    if !bsok || !bip340::verify(bip_pk, dig, bs) { return false; }
    copy_at(bip_sig, bs);
    let ps, pok2 = eip191::sign(secret, "hello world");
    if !pok2 { return false; }
    let upk, uok = secp256k1::pubkey_uncompressed(secret);
    if !uok || !eip191::verify(upk, "hello world", ps) { return false; }
    var tag: u8[32] = [0; 32];
    if !argon2id::hash(pw, salt, asecret, ad, 32, 3, 4, tag) { return false; }
    if !argon2id::eq_hex(tag, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659") {
        return false;
    }
    return chacha32() != 0;
}

fn ::main() {
    if !ready() { print("bench FAIL"); exit(1); }
    write_stdout("operation                       ns/call\n");
    var sink: u64 = 0;
    sink += row("sha256 32B", 64, 250, sha32);
    sink += row("sha256 4KB", 16, 250, sha4k);
    sink += row("keccak256 empty", 64, 250, kec0);
    sink += row("keccak256 32B", 64, 250, kec32);
    sink += row("keccak256 4KB", 16, 250, kec4k);
    sink += row("blake3 32B", 64, 250, blake32);
    sink += row("blake3 4KB", 16, 250, blake4k);
    sink += row("chacha20poly1305 seal 32B", 16, 250, chacha32);
    sink += row("x25519 public", 1, 400, x_pub);
    sink += row("ed25519 sign", 1, 400, ed_sign);
    sink += row("ed25519 verify", 1, 400, ed_verify);
    sink += row("secp256k1 sign", 1, 2000, secp_sign);
    sink += row("secp256k1 verify", 1, 2000, secp_verify);
    sink += row("bip340 sign", 1, 2000, bip_sign);
    sink += row("bip340 verify", 1, 2000, bip_verify);
    sink += row("eip191 personal_sign", 1, 2000, personal);
    sink += row("argon2id 32KiB t=3 p=4", 1, 400, argon);
    var tail: u8[>..] = [];
    format(tail, "sink ");
    format(tail, sink);
    format(tail, "\n");
    write_stdout(tail);
}
