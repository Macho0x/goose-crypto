// BLAKE3 (the BLAKE3 spec, reference algorithm). One-shot hash, keyed
// hash, key derivation, and extendable output. Chunks are 1024 bytes
// and the tree is the spec's CV stack.

import std;

namespace blake3;

const OUT = 32;
const BLOCK = 64;
const CHUNK = 1024;

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED: u32 = 16;
const DERIVE_CONTEXT: u32 = 32;
const DERIVE_MATERIAL: u32 = 64;

const IV: u32[8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct Hasher {
    cv: u32[8],
    counter: u64,
    buf: u8[BLOCK],
    buf_len: i64,
    blocks_done: i64,
    key: u32[8],
    stack: u32[8][54],
    stack_len: i64,
    flags: u32,
}

fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

inline fn g(st: u32[16]&, a: i64, b: i64, c: i64, d: i64, mx: u32, my: u32) {
    st[a] = st[a] + st[b] + mx;
    st[d] = rotr(st[d] ^ st[a], 16);
    st[c] = st[c] + st[d];
    st[b] = rotr(st[b] ^ st[c], 12);
    st[a] = st[a] + st[b] + my;
    st[d] = rotr(st[d] ^ st[a], 8);
    st[c] = st[c] + st[d];
    st[b] = rotr(st[b] ^ st[c], 7);
}

fn compress(cv: u32[8], msg: u32[16], counter: u64, buf_len: u32, flags: u32) -> u32[16] {
    var st: u32[16] = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        (counter & 0xffffffff) as! u32, (counter >> 32) as u32,
        buf_len, flags,
    ];
    var m = msg;
    g(st, 0, 4, 8, 12, m[0], m[1]);
    g(st, 1, 5, 9, 13, m[2], m[3]);
    g(st, 2, 6, 10, 14, m[4], m[5]);
    g(st, 3, 7, 11, 15, m[6], m[7]);
    g(st, 0, 5, 10, 15, m[8], m[9]);
    g(st, 1, 6, 11, 12, m[10], m[11]);
    g(st, 2, 7, 8, 13, m[12], m[13]);
    g(st, 3, 4, 9, 14, m[14], m[15]);
    g(st, 0, 4, 8, 12, m[2], m[6]);
    g(st, 1, 5, 9, 13, m[3], m[10]);
    g(st, 2, 6, 10, 14, m[7], m[0]);
    g(st, 3, 7, 11, 15, m[4], m[13]);
    g(st, 0, 5, 10, 15, m[1], m[11]);
    g(st, 1, 6, 11, 12, m[12], m[5]);
    g(st, 2, 7, 8, 13, m[9], m[14]);
    g(st, 3, 4, 9, 14, m[15], m[8]);
    g(st, 0, 4, 8, 12, m[3], m[4]);
    g(st, 1, 5, 9, 13, m[10], m[12]);
    g(st, 2, 6, 10, 14, m[13], m[2]);
    g(st, 3, 7, 11, 15, m[7], m[14]);
    g(st, 0, 5, 10, 15, m[6], m[5]);
    g(st, 1, 6, 11, 12, m[9], m[0]);
    g(st, 2, 7, 8, 13, m[11], m[15]);
    g(st, 3, 4, 9, 14, m[8], m[1]);
    g(st, 0, 4, 8, 12, m[10], m[7]);
    g(st, 1, 5, 9, 13, m[12], m[9]);
    g(st, 2, 6, 10, 14, m[14], m[3]);
    g(st, 3, 7, 11, 15, m[13], m[15]);
    g(st, 0, 5, 10, 15, m[4], m[0]);
    g(st, 1, 6, 11, 12, m[11], m[2]);
    g(st, 2, 7, 8, 13, m[5], m[8]);
    g(st, 3, 4, 9, 14, m[1], m[6]);
    g(st, 0, 4, 8, 12, m[12], m[13]);
    g(st, 1, 5, 9, 13, m[9], m[11]);
    g(st, 2, 6, 10, 14, m[15], m[10]);
    g(st, 3, 7, 11, 15, m[14], m[8]);
    g(st, 0, 5, 10, 15, m[7], m[2]);
    g(st, 1, 6, 11, 12, m[5], m[3]);
    g(st, 2, 7, 8, 13, m[0], m[1]);
    g(st, 3, 4, 9, 14, m[6], m[4]);
    g(st, 0, 4, 8, 12, m[9], m[14]);
    g(st, 1, 5, 9, 13, m[11], m[5]);
    g(st, 2, 6, 10, 14, m[8], m[12]);
    g(st, 3, 7, 11, 15, m[15], m[1]);
    g(st, 0, 5, 10, 15, m[13], m[3]);
    g(st, 1, 6, 11, 12, m[0], m[10]);
    g(st, 2, 7, 8, 13, m[2], m[6]);
    g(st, 3, 4, 9, 14, m[4], m[7]);
    g(st, 0, 4, 8, 12, m[11], m[15]);
    g(st, 1, 5, 9, 13, m[5], m[0]);
    g(st, 2, 6, 10, 14, m[1], m[9]);
    g(st, 3, 7, 11, 15, m[8], m[6]);
    g(st, 0, 5, 10, 15, m[14], m[10]);
    g(st, 1, 6, 11, 12, m[2], m[12]);
    g(st, 2, 7, 8, 13, m[3], m[4]);
    g(st, 3, 4, 9, 14, m[7], m[13]);
    for i in 0..8 {
        st[i] ^= st[i + 8];
        st[i + 8] ^= cv[i];
    }
    return st;
}

fn first8(wide: u32[16]) -> u32[8] {
    var cv: u32[8] = [0; 8];
    for i in 0..8 { cv[i] = wide[i]; }
    return cv;
}

fn load_words(bytes: u8[:], n: i64, words: u32[16]&) {
    assert(n <= 16);
    assert(bytes.len >= n * 4);
    for i in 0..n {
        let c = bytes[i * 4..i * 4 + 4];
        words[i] = c[0] | (c[1] as u32) << 8 | (c[2] as u32) << 16 | (c[3] as u32) << 24;
    }
}

fn load8(bytes: u8[:]) -> u32[8] {
    var words: u32[16] = [0; 16];
    load_words(bytes, 8, words);
    return first8(words);
}

fn store_le(words: u32[16], out: u8[:], at: i64, n: i64) {
    var produced = 0;
    var i = 0;
    while i < 16 && produced < n {
        let w = words[i];
        var b = 0;
        while b < 4 && produced < n {
            out[at + produced] = (w >> (b * 8)) as! u8;
            produced += 1;
            b += 1;
        }
        i += 1;
    }
}

fn chunk_len(h: Hasher&) -> i64 { BLOCK * h.blocks_done + h.buf_len }

fn start_flag(h: Hasher&) -> u32 {
    if h.blocks_done == 0 { CHUNK_START } else { 0 }
}

fn reset_chunk(h: Hasher&, counter: u64) {
    for i in 0..8 { h.cv[i] = h.key[i]; }
    h.counter = counter;
    h.buf_len = 0;
    h.blocks_done = 0;
}

fn init_raw(h: Hasher&, key: u32[8], flags: u32) {
    for i in 0..8 { h.key[i] = key[i]; }
    h.flags = flags;
    h.stack_len = 0;
    reset_chunk(h, 0);
}

fn init(h: Hasher&) { init_raw(h, IV, 0); }

fn init_keyed(h: Hasher&, key: u8[:]) {
    assert(key.len == 32);
    init_raw(h, load8(key), KEYED);
}

fn parent_words(left: u32[8], right: u32[8]) -> u32[16] {
    var words: u32[16] = [0; 16];
    for i in 0..8 {
        words[i] = left[i];
        words[i + 8] = right[i];
    }
    return words;
}

fn parent_cv(left: u32[8], right: u32[8], key: u32[8], flags: u32) -> u32[8] {
    first8(compress(key, parent_words(left, right), 0, BLOCK, PARENT | flags))
}

fn add_cv(h: Hasher&, new_cv: u32[8], total: u64) {
    var cv = new_cv;
    var n = total;
    while n & 1 == 0 {
        h.stack_len -= 1;
        cv = parent_cv(h.stack[h.stack_len], cv, h.key, h.flags);
        n = n >> 1;
    }
    h.stack[h.stack_len] = cv;
    h.stack_len += 1;
}

fn chunk_update(h: Hasher&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        if h.buf_len == BLOCK {
            var words: u32[16] = [0; 16];
            load_words(h.buf, 16, words);
            let wide = compress(h.cv, words, h.counter, BLOCK, h.flags | start_flag(h));
            h.cv = first8(wide);
            h.blocks_done += 1;
            h.buf_len = 0;
        }
        let space = BLOCK - h.buf_len;
        var take = data.len - off;
        if take > space { take = space; }
        for i in 0..take { h.buf[h.buf_len + i] = data[off + i]; }
        h.buf_len += take;
        off += take;
    }
}

fn update(h: Hasher&, data: u8[:]) {
    var off = 0;
    while off < data.len {
        if chunk_len(h) == CHUNK {
            var words: u32[16] = [0; 16];
            load_words(h.buf, 16, words);
            let flags = h.flags | start_flag(h) | CHUNK_END;
            let cv = first8(compress(h.cv, words, h.counter, h.buf_len as u32, flags));
            let total = h.counter + 1;
            add_cv(h, cv, total);
            reset_chunk(h, total);
        }
        let space = CHUNK - chunk_len(h);
        var take = data.len - off;
        if take > space { take = space; }
        chunk_update(h, data[off..off + take]);
        off += take;
    }
}

struct Node {
    cv: u32[8],
    words: u32[16],
    counter: u64,
    buf_len: u32,
    flags: u32,
}

fn chunk_node(h: Hasher&) -> Node {
    if h.buf_len < BLOCK {
        for i in h.buf_len..BLOCK { h.buf[i] = 0; }
    }
    var words: u32[16] = [0; 16];
    load_words(h.buf, 16, words);
    return Node { h.cv, words, h.counter, h.buf_len as u32, h.flags | start_flag(h) | CHUNK_END };
}

fn parent_node(left: u32[8], right: u32[8], key: u32[8], flags: u32) -> Node {
    Node { key, parent_words(left, right), 0, BLOCK, PARENT | flags }
}

fn node_cv(n: Node&) -> u32[8] {
    first8(compress(n.cv, n.words, n.counter, n.buf_len, n.flags))
}

fn root_bytes(n: Node&, out: u8[:]) {
    var at = 0;
    var ctr: u64 = 0;
    while at < out.len {
        let wide = compress(n.cv, n.words, ctr, n.buf_len, n.flags | ROOT);
        var nleft = out.len - at;
        if nleft > 64 { nleft = 64; }
        store_le(wide, out, at, nleft);
        at += nleft;
        ctr += 1;
    }
}

fn finalize(h: Hasher&, out: u8[:]) {
    var node = chunk_node(h);
    var left = h.stack_len;
    while left > 0 {
        left -= 1;
        node = parent_node(h.stack[left], node_cv(node), h.key, h.flags);
    }
    root_bytes(node, out);
}

fn init_derive(h: Hasher&, context: u8[:]) {
    var ch: Hasher = default<Hasher>();
    init_raw(ch, IV, DERIVE_CONTEXT);
    update(ch, context);
    var key: u8[32] = [0; 32];
    finalize(ch, key);
    init_keyed(h, key);
    h.flags = DERIVE_MATERIAL;
}

fn store8(words: u32[16], out: u8[:]) {
    for i in 0..8 {
        let w = words[i];
        out[i * 4] = w as! u8;
        out[i * 4 + 1] = (w >> 8) as! u8;
        out[i * 4 + 2] = (w >> 16) as! u8;
        out[i * 4 + 3] = (w >> 24) as! u8;
    }
}

// One chunk has no parent CV. The 54-slot stack stays out of this path.
fn hash_chunk(data: u8[:]) -> u8[32] {
    var cv: u32[8] = IV;
    var off = 0;
    while data.len - off > BLOCK {
        var words: u32[16] = [0; 16];
        load_words(data[off..off + BLOCK], 16, words);
        let flags: u32 = if off == 0 { CHUNK_START } else { 0 };
        cv = first8(compress(cv, words, 0, BLOCK, flags));
        off += BLOCK;
    }
    var buf: u8[BLOCK] = [0; BLOCK];
    let tail = data.len - off;
    for i in 0..tail { buf[i] = data[off + i]; }
    var last: u32[16] = [0; 16];
    load_words(buf, 16, last);
    var flags: u32 = CHUNK_END | ROOT;
    if off == 0 { flags |= CHUNK_START; }
    let wide = compress(cv, last, 0, tail as u32, flags);
    var out: u8[32] = [0; 32];
    store8(wide, out);
    return out;
}

fn hash(data: u8[:]) -> u8[32] {
    if data.len <= CHUNK { return hash_chunk(data); }
    var h: Hasher = default<Hasher>();
    init(h);
    update(h, data);
    var out: u8[32] = [0; 32];
    finalize(h, out);
    return out;
}

fn keyed(key: u8[:], data: u8[:]) -> u8[32] {
    var h: Hasher = default<Hasher>();
    init_keyed(h, key);
    update(h, data);
    var out: u8[32] = [0; 32];
    finalize(h, out);
    return out;
}

fn derive_key(context: u8[:], material: u8[:]) -> u8[32] {
    var h: Hasher = default<Hasher>();
    init_derive(h, context);
    update(h, material);
    var out: u8[32] = [0; 32];
    finalize(h, out);
    return out;
}

fn xof(data: u8[:], out: u8[:]) {
    var h: Hasher = default<Hasher>();
    init(h);
    update(h, data);
    finalize(h, out);
}
