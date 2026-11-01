// HKDF-SHA256 (RFC 5869). extract returns a 32-byte PRK.
// expand writes L bytes into the caller buffer, L from 1 to 255 * 32.
// An empty salt is 32 zero bytes.

import std;
import sha256;

namespace hkdf;

fn extract(salt: u8[:], ikm: u8[:]) -> u8[32] {
    if salt.len != 0 { return sha256::hmac(salt, ikm); }
    var z: u8[32] = [0; 32];
    return sha256::hmac(z, ikm);
}

fn expand(prk: u8[:], info: u8[:], out: u8[:]) -> bool {
    if out.len == 0 || out.len > 255 * 32 { return false; }
    let key = sha256::mac_start(prk);
    var prev: u8[32] = [0; 32];
    var done = 0;
    var n = 1;
    var ctr: u8[1] = [0; 1];
    while done < out.len {
        var m = copy(key);
        if n > 1 { sha256::mac_update(m, prev); }
        sha256::mac_update(m, info);
        ctr[0] = n as u8;
        sha256::mac_update(m, ctr);
        let tag = sha256::mac_finish(m);
        var take = 32;
        if done + take > out.len { take = out.len - done; }
        for i in 0..take { out[done + i] = tag[i]; }
        prev = tag;
        done += take;
        n += 1;
    }
    return true;
}
