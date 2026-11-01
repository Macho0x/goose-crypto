import crypto from "..";
import crypto.eip712;
import crypto.secp256k1;

namespace eip712;

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

fn unhex(hex: u8[:], out: u8[:]) {
    for i in 0..out.len { out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]); }
}

fn self_check() -> bool {
    let person_t = word_hash("Person(string name,address wallet)");
    let mail_t = word_hash("Mail(Person from,Person to,string contents)Person(string name,address wallet)");
    let domain_t = word_hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    var cow: u8[20] = [0; 20];
    var bob: u8[20] = [0; 20];
    var contract: u8[20] = [0; 20];
    unhex("cd2a3d9f938e13cd947ec05abc7fe734df8dd826", cow);
    unhex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", bob);
    unhex("cccccccccccccccccccccccccccccccccccccccc", contract);
    let cow_w, cok = word_address(cow);
    let bob_w, bok = word_address(bob);
    let con_w, kon = word_address(contract);
    var chain_src: u8[1] = [0];
    chain_src[0] = 1;
    let chain, xok = word_uint(chain_src);
    if !cok || !bok || !kon || !xok { return false; }
    var person: u8[96] = [0; 96];
    write_at(person, 0, person_t);
    write_at(person, 32, word_hash("Cow"));
    write_at(person, 64, cow_w);
    let from_h, fok = hash_encoded(person);
    write_at(person, 32, word_hash("Bob"));
    write_at(person, 64, bob_w);
    let to_h, tok = hash_encoded(person);
    var mail: u8[128] = [0; 128];
    write_at(mail, 0, mail_t);
    write_at(mail, 32, from_h);
    write_at(mail, 64, to_h);
    write_at(mail, 96, word_hash("Hello, Bob!"));
    let msg, mok = hash_encoded(mail);
    var dom: u8[160] = [0; 160];
    write_at(dom, 0, domain_t);
    write_at(dom, 32, word_hash("Ether Mail"));
    write_at(dom, 64, word_hash("1"));
    write_at(dom, 96, chain);
    write_at(dom, 128, con_w);
    let sep, sok = hash_encoded(dom);
    if !fok || !tok || !mok || !sok { return false; }
    let dig, dok = digest(sep, msg);
    if !dok { return false; }
    var secret: u8[32] = [0; 32];
    unhex("c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4", secret);
    let raw, pok = secp256k1::pubkey_uncompressed(secret);
    if !pok { return false; }
    var xy: u8[64] = [0; 64];
    for i in 0..64 { xy[i] = raw[i + 1]; }
    if !word_hash(xy)[12..].eq_hex("cd2a3d9f938e13cd947ec05abc7fe734df8dd826") { return false; }
    let sig, sigok = sign(secret, sep, msg);
    if !sigok || !sig.eq_hex("4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c") { return false; }
    let rec, rok = secp256k1::recover(dig, sig);
    if !rok || rec != raw { return false; }
    let pk, pkok = secp256k1::pubkey_compressed(secret);
    if !pkok || !verify(pk, sep, msg, sig) { return false; }
    sig[64] = 26;
    if verify(pk, sep, msg, sig) { return false; }
    var minus: u8[1] = [0];
    minus[0] = 255;
    let neg, nok = word_int(minus);
    if !nok || neg[0] != 255 || neg[31] != 255 { return false; }
    return true;
}

fn ::main() {
    if eip712::self_check() { print("eip712 ok"); } else { print("eip712 FAIL"); exit(1); }
}
