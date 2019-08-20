#![feature(test)]

//below are LIBSECP256K1-RS extern crates
extern crate test;
extern crate secp256k1;
extern crate secp256k1_test;
extern crate rand;
#[macro_use]
extern crate arrayref;
//below are THRESHOLD_CRYPTO extern crates


//below are LIBSECP256K1-RS uses
use test::Bencher;
use secp256k1::{sign, SecretKey, Message, PublicKey, Signature};
use secp256k1_test::{Secp256k1, Message as SecpMessage};
use rand::thread_rng;
//below are THRESHOLD_CRYPTO uses



//below are THRESHOLD_CRYPTO BENCHES




//below are LIBSECP256K1-RS SIGNING BENCHES

#[bench]
fn bench_sign_message(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let message = Message::parse(&[5u8; 32]);
    let (secp_privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap(); //works if use this; gives 51us
    // also, wtf is this syntax on the LHS?? putting it in println doesn't work but putting the RHS in works
    let seckey = SecretKey::parse(array_ref!(secp_privkey, 0, 32)).unwrap(); //works if use this; gives 22ns
//    println!("{:?}", secp256k1.generate_keypair(&mut thread_rng()).unwrap());
//    println!("{:?}", seckey);
//    println!("{:?}", sign(&message, &seckey));

    b.iter(|| {
        let _ = sign(&message, &seckey); //having removed .unwrap(), this works; gives 103us; if not, gives below error
    });
}

//below are LIBSECP256K1-RS PUBLIC KEY BENCHES

#[bench]
fn bench_public_key_parse(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
    assert!(pubkey_arr.len() == 65);
    let mut pubkey_a = [0u8; 65];
    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
    b.iter(|| {
        let _pubkey = PublicKey::parse(&pubkey_a).unwrap();
    });
}

#[bench]
fn bench_public_key_serialize(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
    assert!(pubkey_arr.len() == 65);
    let mut pubkey_a = [0u8; 65];
    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
    let pubkey = PublicKey::parse(&pubkey_a).unwrap();
    b.iter(|| {
        let _serialized = pubkey.serialize();
    });
}

#[bench]
fn bench_public_key_serialize_compressed(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let (_, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
    assert!(pubkey_arr.len() == 65);
    let mut pubkey_a = [0u8; 65];
    pubkey_a[0..65].copy_from_slice(&pubkey_arr[0..65]);
    let pubkey = PublicKey::parse(&pubkey_a).unwrap();
    b.iter(|| {
        let _serialized = pubkey.serialize_compressed();
    });
}

//below are LIBSECP256K1-RS SIGNATURE BENCHES

#[bench]
fn bench_signature_parse(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let message_arr = [5u8; 32];
    let (privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
    let message = SecpMessage::from_slice(&message_arr).unwrap();
    let signature = secp256k1.sign(&message, &privkey).unwrap();
    let signature_arr = signature.serialize_compact(&secp256k1);
    assert!(signature_arr.len() == 64);
    let mut signature_a = [0u8; 64];
    signature_a.copy_from_slice(&signature_arr[0..64]);

    b.iter(|| {
        let _signature = Signature::parse(&signature_a);
    });
}

#[bench]
fn bench_signature_serialize(b: &mut Bencher) {
    let secp256k1 = Secp256k1::new();
    let message_arr = [5u8; 32];
    let (privkey, _) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
    let message = SecpMessage::from_slice(&message_arr).unwrap();
    let signature = secp256k1.sign(&message, &privkey).unwrap();
    let signature_arr = signature.serialize_compact(&secp256k1);
    assert!(signature_arr.len() == 64);
    let mut signature_a = [0u8; 64];
    signature_a.copy_from_slice(&signature_arr[0..64]);
    let signature = Signature::parse(&signature_a);

    b.iter(|| {
        let _serialized = signature.serialize();
    });
}