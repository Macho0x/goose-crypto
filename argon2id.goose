// Argon2id (RFC 9106), version 0x13. Memory is one block per KiB.
// Variable-time. Not safe against timing side channels.

import std;

namespace argon2id;

const IV: u64[8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const SIG: u8[192] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
];

struct B2 {
    h: u64[8],
    t0: u64,
    t1: u64,
    buf: u8[128],
    n: i64,
    outlen: i64,
}

fn rotr(x: u64, n: u64) -> u64 { (x >> n) | (x << (64 - n)) }

fn load64(b: u8[:], i: i64) -> u64 {
    var x: u64 = 0;
    for k in 0..8 {
        let byte: u64 = b[i + k];
        x |= byte << (k * 8);
    }
    return x;
}

fn store64(out: u8[:], at: i64, v: u64) {
    for k in 0..8 { out[at + k] = (v >> (k * 8)) as! u8; }
}

fn store32(out: u8[:], at: i64, v: u32) {
    out[at] = v as! u8;
    out[at + 1] = (v >> 8) as! u8;
    out[at + 2] = (v >> 16) as! u8;
    out[at + 3] = (v >> 24) as! u8;
}

fn sig_at(r: i64, i: i64) -> i64 {
    let k: i64 = SIG[r * 16 + i];
    return k;
}

fn b2_init(outlen: i64) -> B2 {
    var c: B2 = default<B2>();
    for i in 0..8 { c.h[i] = IV[i]; }
    c.h[0] ^= (outlen as u64) | 0x01010000;
    c.outlen = outlen;
    return c;
}

fn b2g(v: u64[16]&, a: i64, b: i64, c: i64, d: i64, x: u64, y: u64) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 63);
}

fn b2_compress(c: B2&, buf: u8[:], last: bool) {
    var m: u64[16] = [0; 16];
    for i in 0..16 { m[i] = load64(buf, i * 8); }
    var v: u64[16] = [0; 16];
    for i in 0..8 { v[i] = c.h[i]; v[i + 8] = IV[i]; }
    v[12] ^= c.t0;
    v[13] ^= c.t1;
    if last {
        let zero: u64 = 0;
        let flag = zero - 1;
        v[14] ^= flag;
    }
    for r in 0..12 {
        b2g(v, 0, 4, 8, 12, m[sig_at(r, 0)], m[sig_at(r, 1)]);
        b2g(v, 1, 5, 9, 13, m[sig_at(r, 2)], m[sig_at(r, 3)]);
        b2g(v, 2, 6, 10, 14, m[sig_at(r, 4)], m[sig_at(r, 5)]);
        b2g(v, 3, 7, 11, 15, m[sig_at(r, 6)], m[sig_at(r, 7)]);
        b2g(v, 0, 5, 10, 15, m[sig_at(r, 8)], m[sig_at(r, 9)]);
        b2g(v, 1, 6, 11, 12, m[sig_at(r, 10)], m[sig_at(r, 11)]);
        b2g(v, 2, 7, 8, 13, m[sig_at(r, 12)], m[sig_at(r, 13)]);
        b2g(v, 3, 4, 9, 14, m[sig_at(r, 14)], m[sig_at(r, 15)]);
    }
    for i in 0..8 { c.h[i] ^= v[i] ^ v[i + 8]; }
}

fn b2_add(c: B2&, n: u64) {
    let prev = c.t0;
    c.t0 += n;
    if c.t0 < prev { c.t1 += 1; }
}

fn b2_update(c: B2&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        if c.n == 128 {
            b2_add(c, 128);
            b2_compress(c, c.buf, false);
            c.n = 0;
        }
        let space = 128 - c.n;
        var take = data.len - off;
        if take > space { take = space; }
        if c.n + take == 128 && off + take < data.len {
            for i in 0..take { c.buf[c.n + i] = data[off + i]; }
            b2_add(c, 128);
            b2_compress(c, c.buf, false);
            c.n = 0;
        } else {
            for i in 0..take { c.buf[c.n + i] = data[off + i]; }
            c.n += take;
        }
        off += take;
    }
}

fn b2_final(c: B2&, out: u8[:]) {
    b2_add(c, c.n as u64);
    for i in c.n..128 { c.buf[i] = 0; }
    b2_compress(c, c.buf, true);
    var full: u8[64] = [0; 64];
    for i in 0..8 { store64(full, i * 8, c.h[i]); }
    for i in 0..c.outlen { out[i] = full[i]; }
}

fn blake2b(data: u8[:], out: u8[:]) {
    var c = b2_init(out.len);
    b2_update(c, data);
    b2_final(c, out);
}

fn blake2b_long(input: u8[:], out: u8[:]) {
    var lenb: u8[4] = [0; 4];
    store32(lenb, 0, out.len as! u32);
    if out.len <= 64 {
        var c = b2_init(out.len);
        b2_update(c, lenb);
        b2_update(c, input);
        b2_final(c, out);
        return;
    }
    var first: u8[64] = [0; 64];
    var c = b2_init(64);
    b2_update(c, lenb);
    b2_update(c, input);
    b2_final(c, first);
    for i in 0..32 { out[i] = first[i]; }
    var produced = 32;
    var left = out.len - 32;
    while left > 64 {
        var next: u8[64] = [0; 64];
        blake2b(first, next);
        first = next;
        for i in 0..32 { out[produced + i] = first[i]; }
        produced += 32;
        left -= 32;
    }
    blake2b(first, out[produced..produced + left]);
}

fn fblamka(x: u64, y: u64) -> u64 {
    let m: u64 = 0xffffffff;
    let xy = (x & m) * (y & m);
    return x + y + xy + xy;
}

fn gb(v: u64[16]&, a: i64, b: i64, c: i64, d: i64) {
    v[a] = fblamka(v[a], v[b]);
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = fblamka(v[c], v[d]);
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = fblamka(v[a], v[b]);
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = fblamka(v[c], v[d]);
    v[b] = rotr(v[b] ^ v[c], 63);
}

fn blamka(v: u64[16]&) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

fn permute(r: u64[128]&) {
    for row in 0..8 {
        var v: u64[16] = [0; 16];
        for j in 0..16 { v[j] = r[row * 16 + j]; }
        blamka(v);
        for j in 0..16 { r[row * 16 + j] = v[j]; }
    }
    for col in 0..8 {
        var v: u64[16] = [0; 16];
        for j in 0..8 {
            v[j * 2] = r[2 * col + 16 * j];
            v[j * 2 + 1] = r[2 * col + 16 * j + 1];
        }
        blamka(v);
        for j in 0..8 {
            r[2 * col + 16 * j] = v[j * 2];
            r[2 * col + 16 * j + 1] = v[j * 2 + 1];
        }
    }
}

fn fill_block(prev: u64[:], refb: u64[:], next: u64[:], with_xor: bool) {
    var r: u64[128] = [0; 128];
    var tmp: u64[128] = [0; 128];
    for i in 0..128 {
        r[i] = refb[i] ^ prev[i];
        tmp[i] = r[i];
        if with_xor { tmp[i] ^= next[i]; }
    }
    permute(r);
    for i in 0..128 { next[i] = tmp[i] ^ r[i]; }
}

fn fill_local(prev: u64[128], refb: u64[128], with_xor_from: u64[128], with_xor: bool) -> u64[128] {
    var next: u64[128] = [0; 128];
    if with_xor { next = with_xor_from; }
    fill_block(prev, refb, next, with_xor);
    return next;
}

fn next_addresses(input: u64[128]&, addr: u64[128]&) {
    input[6] += 1;
    var zero: u64[128] = [0; 128];
    let mid = fill_local(zero, input, zero, false);
    addr = fill_local(zero, mid, zero, false);
}

fn index_alpha(pass: u32, slice: u32, index: u32, lane_length: u32, segment: u32, pseudo: u32, same: bool) -> u32 {
    var area: u32 = 0;
    if pass == 0 {
        if slice == 0 {
            area = index - 1;
        } else if same {
            area = slice * segment + index - 1;
        } else if index == 0 {
            area = slice * segment - 1;
        } else {
            area = slice * segment;
        }
    } else if same {
        area = lane_length - segment + index - 1;
    } else if index == 0 {
        area = lane_length - segment - 1;
    } else {
        area = lane_length - segment;
    }
    let pr: u64 = pseudo;
    let rel = (pr * pr) >> 32;
    let area64: u64 = area;
    let base: u32 = area - 1;
    var rel_pos: u64 = base;
    rel_pos -= (area64 * rel) >> 32;
    var start: u64 = 0;
    if pass != 0 && slice != 3 { start = (slice + 1) * segment; }
    return ((start + rel_pos) % lane_length) as! u32;
}

fn word(mem: u64[:], blk: i64, i: i64) -> u64 { mem[blk * 128 + i] }

fn put_word(mem: u64[>..]&, blk: i64, i: i64, v: u64) { mem[blk * 128 + i] = v; }

fn compress_into(mem: u64[>..]&, prev: i64, refb: i64, curr: i64, with_xor: bool) {
    var p: u64[128] = [0; 128];
    var r: u64[128] = [0; 128];
    var n: u64[128] = [0; 128];
    for i in 0..128 {
        p[i] = word(mem, prev, i);
        r[i] = word(mem, refb, i);
        if with_xor { n[i] = word(mem, curr, i); }
    }
    fill_block(p, r, n, with_xor);
    for i in 0..128 { put_word(mem, curr, i, n[i]); }
}

fn fill_segment(mem: u64[>..]&, lane_length: i64, segment: i64, lanes: i64, passes: i64, blocks: i64, pass: i64, slice: i64, lane: i64) {
    let independent = pass == 0 && slice < 2;
    var input: u64[128] = [0; 128];
    var addr: u64[128] = [0; 128];
    if independent {
        input[0] = pass as u64;
        input[1] = lane as u64;
        input[2] = slice as u64;
        input[3] = blocks as u64;
        input[4] = passes as u64;
        input[5] = 2;
    }
    var start = 0;
    if pass == 0 && slice == 0 {
        start = 2;
        if independent { next_addresses(input, addr); }
    }
    var curr = lane * lane_length + slice * segment + start;
    var prev = curr - 1;
    if curr % lane_length == 0 { prev = curr + lane_length - 1; }
    for i in start..segment {
        if curr % lane_length == 1 { prev = curr - 1; }
        var pseudo: u64 = 0;
        if independent {
            if i % 128 == 0 { next_addresses(input, addr); }
            pseudo = addr[i % 128];
        } else {
            pseudo = word(mem, prev, 0);
        }
        let lanes32 = lanes as! u32;
        var ref_lane: u32 = ((pseudo >> 32) as! u32) % lanes32;
        if pass == 0 && slice == 0 { ref_lane = lane as! u32; }
        let ref_index = index_alpha(pass as! u32, slice as! u32, i as! u32, lane_length as! u32, segment as! u32, pseudo as! u32, ref_lane == lane as! u32);
        compress_into(mem, prev, ref_lane * lane_length + ref_index, curr, pass != 0);
        curr += 1;
        prev += 1;
    }
}

fn h0(password: u8[:], salt: u8[:], secret: u8[:], ad: u8[:], m_kib: u32, passes: u32, lanes: u32, outlen: u32) -> u8[64] {
    var c = b2_init(64);
    var w: u8[4] = [0; 4];
    store32(w, 0, lanes); b2_update(c, w);
    store32(w, 0, outlen); b2_update(c, w);
    store32(w, 0, m_kib); b2_update(c, w);
    store32(w, 0, passes); b2_update(c, w);
    store32(w, 0, 0x13); b2_update(c, w);
    store32(w, 0, 2); b2_update(c, w);
    store32(w, 0, password.len as! u32); b2_update(c, w);
    b2_update(c, password);
    store32(w, 0, salt.len as! u32); b2_update(c, w);
    b2_update(c, salt);
    store32(w, 0, secret.len as! u32); b2_update(c, w);
    b2_update(c, secret);
    store32(w, 0, ad.len as! u32); b2_update(c, w);
    b2_update(c, ad);
    var out: u8[64] = [0; 64];
    b2_final(c, out);
    return out;
}

fn load_block(mem: u64[>..]&, blk: i64, bytes: u8[:]) {
    for i in 0..128 { put_word(mem, blk, i, load64(bytes, i * 8)); }
}

// m_kib below 8*lanes is raised to that minimum, matching the reference.
fn hash(password: u8[:], salt: u8[:], secret: u8[:], ad: u8[:], m_kib: i64, passes: i64, lanes: i64, out: u8[:]) -> bool {
    if salt.len < 8 || out.len < 4 || passes < 1 || lanes < 1 { return false; }
    if m_kib > 0xffffffff || passes > 0xffffffff || lanes > 0xffffffff || out.len > 0xffffffff { return false; }
    var blocks = m_kib;
    let minimum = 8 * lanes;
    if blocks < minimum { blocks = minimum; }
    let segment = blocks / (lanes * 4);
    blocks = segment * lanes * 4;
    let lane_length = segment * 4;
    var mem: u64[>..] = [];
    mem.resize(blocks * 128, 0);
    let dig = h0(password, salt, secret, ad, m_kib as! u32, passes as! u32, lanes as! u32, out.len as! u32);
    for lane in 0..lanes {
        var seed: u8[72] = [0; 72];
        for i in 0..64 { seed[i] = dig[i]; }
        store32(seed, 64, 0);
        store32(seed, 68, lane as! u32);
        var raw: u8[1024] = [0; 1024];
        blake2b_long(seed, raw);
        load_block(mem, lane * lane_length, raw);
        store32(seed, 64, 1);
        blake2b_long(seed, raw);
        load_block(mem, lane * lane_length + 1, raw);
    }
    for pass in 0..passes {
        for slice in 0..4 {
            for lane in 0..lanes {
                fill_segment(mem, lane_length, segment, lanes, passes, blocks, pass, slice, lane);
            }
        }
    }
    var acc: u64[128] = [0; 128];
    for i in 0..128 { acc[i] = word(mem, lane_length - 1, i); }
    for lane in 1..lanes {
        let b = lane * lane_length + lane_length - 1;
        for i in 0..128 { acc[i] ^= word(mem, b, i); }
    }
    var raw: u8[1024] = [0; 1024];
    for i in 0..128 { store64(raw, i * 8, acc[i]); }
    blake2b_long(raw, out);
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

fn self_check() -> bool {
    var empty: u8[64] = [0; 64];
    blake2b("", empty);
    if !empty.eq_hex("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce") { return false; }
    var password: u8[32] = [0x01; 32];
    var salt: u8[16] = [0x02; 16];
    var secret: u8[8] = [0x03; 8];
    var ad: u8[12] = [0x04; 12];
    var tag: u8[32] = [0; 32];
    if !hash(password, salt, secret, ad, 32, 3, 4, tag) { return false; }
    return tag.eq_hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

fn ::main() {
    if argon2id::self_check() { print("argon2id ok"); } else { print("argon2id FAIL"); exit(1); }
}
