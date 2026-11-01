import crypto from "..";
import crypto.bip340;

namespace bip340;

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

fn load32(hex: u8[:]) -> u8[32] {
    var o: u8[32] = [0; 32];
    unhex(hex, o);
    return o;
}

fn self_check() -> bool {
    let sk0 = load32("0000000000000000000000000000000000000000000000000000000000000003");
    let aux0: u8[32] = [0; 32];
    let msg0: u8[32] = [0; 32];
    let pk0, ok0 = public_key(sk0);
    if !ok0 || !pk0.eq_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9") { return false; }
    let sig0, s0 = sign(sk0, msg0, aux0);
    if !s0 || !sig0.eq_hex("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0") { return false; }
    if !verify(pk0, msg0, sig0) { return false; }

    let sk1 = load32("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    let aux1 = load32("0000000000000000000000000000000000000000000000000000000000000001");
    let msg1 = load32("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
    let pk1, ok1 = public_key(sk1);
    if !ok1 || !pk1.eq_hex("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659") { return false; }
    let sig1, s1 = sign(sk1, msg1, aux1);
    if !s1 || !sig1.eq_hex("6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a") { return false; }
    if !verify(pk1, msg1, sig1) { return false; }

    let bad5 = load32("d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9");
    var rej5: u8[64] = [0; 64];
    unhex("00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", rej5);
    if verify(bad5, msg1, rej5) { return false; }
    var rej6: u8[64] = [0; 64];
    unhex("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", rej6);
    if verify(pk1, msg1, rej6) { return false; }
    var rej8: u8[64] = [0; 64];
    unhex("6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", rej8);
    if verify(pk1, msg1, rej8) { return false; }
    var rej12: u8[64] = [0; 64];
    unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", rej12);
    if verify(pk1, msg1, rej12) { return false; }
    var rej13: u8[64] = [0; 64];
    unhex("6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", rej13);
    if verify(pk1, msg1, rej13) { return false; }

    let sk2 = load32("c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9");
    let aux2 = load32("c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906");
    let msg2 = load32("7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c");
    let pk2, ok2 = public_key(sk2);
    if !ok2 || !pk2.eq_hex("dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8") { return false; }
    let sig2, s2 = sign(sk2, msg2, aux2);
    if !s2 || !sig2.eq_hex("5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7") { return false; }
    if !verify(pk2, msg2, sig2) { return false; }

    let sk3 = load32("0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710");
    var aux3: u8[32] = [0xff; 32];
    var msg3: u8[32] = [0xff; 32];
    let pk3, ok3 = public_key(sk3);
    if !ok3 || !pk3.eq_hex("25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517") { return false; }
    let sig3, s3 = sign(sk3, msg3, aux3);
    if !s3 || !sig3.eq_hex("7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3") { return false; }
    if !verify(pk3, msg3, sig3) { return false; }

    let pk4 = load32("d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9");
    let msg4 = load32("4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703");
    var sig4: u8[64] = [0; 64];
    unhex("00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", sig4);
    if !verify(pk4, msg4, sig4) { return false; }

    var inf9: u8[64] = [0; 64];
    unhex("0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051", inf9);
    if verify(pk1, msg1, inf9) { return false; }
    var inf10: u8[64] = [0; 64];
    unhex("00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197", inf10);
    if verify(pk1, msg1, inf10) { return false; }
    let over = load32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");
    var sig14: u8[64] = [0; 64];
    unhex("6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", sig14);
    if verify(over, msg1, sig14) { return false; }

    let sk15 = load32("0340034003400340034003400340034003400340034003400340034003400340");
    let aux15: u8[32] = [0; 32];
    let pk15, ok15 = public_key(sk15);
    if !ok15 || !pk15.eq_hex("778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117") { return false; }
    let sig15, s15 = sign(sk15, "", aux15);
    if !s15 || !sig15.eq_hex("71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63") { return false; }
    if !verify(pk15, "", sig15) { return false; }
    var oneb: u8[1] = [0x11];
    let sig16, s16 = sign(sk15, oneb, aux15);
    if !s16 || !sig16.eq_hex("08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf") { return false; }
    if !verify(pk15, oneb, sig16) { return false; }
    return true;
}

fn ::main() {
    if bip340::self_check() { print("bip340 ok"); } else { print("bip340 FAIL"); exit(1); }
}
