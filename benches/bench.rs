#![feature(test)]
extern crate test;
//extern crate secp256k1;
//extern crate secp256k1_test;
extern crate rand;
#[macro_use]
extern crate arrayref;

use test::Bencher;
//use secp256k1::{sign, SecretKey, Message, PublicKey, Signature};
//use secp256k1_test::{Secp256k1, Message as SecpMessage};
use rand::thread_rng;
use digital_signature::{sign, new, key_gen, PrivateKey, CommonParameters};
// maybe at one point we should write full name due to many signatures/benches with similar functions

//#[bench]
//fn bench_sign_message(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let message = Message::parse(&[5u8; 32]);
//    let (secp_privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap(); //works if use this; gives 51us
//    let seckey = SecretKey::parse(array_ref!(secp_privkey, 0, 32)).unwrap(); //works if use this; gives 22ns
//
//    b.iter(|| {
//        let _ = sign(&message, &seckey); //having removed .unwrap(), this works; gives 103us; if not, gives below error
//    });
//}

#[bench]
fn bench_sign_message_libsecp256k1(b: &mut Bencher) {
    let mut common_parameter = new();
    let message = "hello world";
    let (_, private_key) = key_gen(&mut common_parameter);
    b.iter(|| {
        let _ = sign(&message, &private_key);
    });
}

//
////below are LIBSECP256K1-RS PUBLIC KEY BENCHES
//
//#[bench]
//fn bench_public_key_parse(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
//    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
//    assert!(pubkey_arr.len() == 65);
//    let mut pubkey_a = [0u8; 65];
//    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
//    b.iter(|| {
//        let _pubkey = PublicKey::parse(&pubkey_a).unwrap();
//    });
//}
//
//#[bench]
//fn bench_public_key_serialize(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
//    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
//    assert!(pubkey_arr.len() == 65);
//    let mut pubkey_a = [0u8; 65];
//    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
//    let pubkey = PublicKey::parse(&pubkey_a).unwrap();
//    b.iter(|| {
//        let _serialized = pubkey.serialize();
//    });
//}
//
//#[bench]
//fn bench_public_key_serialize_compressed(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
//    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
//    assert!(pubkey_arr.len() == 65);
//    let mut pubkey_a = [0u8; 65];
//    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
//    let pubkey = PublicKey::parse(&pubkey_a).unwrap();
//    b.iter(|| {
//        let _serialized = pubkey.serialize_compressed();
//    });
//}
//
////below are LIBSECP256K1-RS SIGNATURE BENCHES
//
//#[bench]
//fn bench_signature_parse(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let message_arr = [5u8; 32];
//    let (privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
//    let message = SecpMessage::from_slice(&message_arr).unwrap();
//    let signature = secp256k1.sign(&message, &privkey).unwrap();
//    let signature_arr = signature.serialize_compact(&secp256k1);
//    assert!(signature_arr.len() == 64);
//    let mut signature_a = [0u8; 64];
//    signature_a.copy_from_slice(&signature_arr[0..64]);
//
//    b.iter(|| {
//        let _signature = Signature::parse(&signature_a);
//    });
//}
//
//#[bench]
//fn bench_signature_serialize(b: &mut Bencher) {
//    let secp256k1 = Secp256k1::new();
//    let message_arr = [5u8; 32];
//    let (privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
//    let message = SecpMessage::from_slice(&message_arr).unwrap();
//    let signature = secp256k1.sign(&message, &privkey).unwrap();
//    let signature_arr = signature.serialize_compact(&secp256k1);
//    assert!(signature_arr.len() == 64);
//    let mut signature_a = [0u8; 64];
//    signature_a.copy_from_slice(&signature_arr[0..64]);
//    let signature = Signature::parse(&signature_a);
//
//    b.iter(|| {
//        let _serialized = signature.serialize();
//    });
//}
