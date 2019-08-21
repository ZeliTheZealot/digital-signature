#![feature(test)]

//below are LIBSECP256K1-RS extern crates
extern crate test;
extern crate secp256k1;
extern crate secp256k1_test;
extern crate rand;
#[macro_use]
extern crate arrayref;
//below are THRESHOLD_CRYPTO extern crates
//there are no THRESHOLD_CRYPTO extern crates

//below are LIBSECP256K1-RS uses
use test::Bencher;
use secp256k1::{sign, SecretKey, Message, PublicKey, Signature};
use secp256k1_test::{Secp256k1, Message as SecpMessage};
use rand::thread_rng;
////below are THRESHOLD_CRYPTO uses
//use criterion::{criterion_group, criterion_main, Criterion};
//use threshold_crypto::poly::Poly;
//use threshold_crypto::Fr;


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

//below are THRESHOLD_CRYPTO BENCHES
//
//const TEST_DEGREES: [usize; 4] = [5, 10, 20, 40];
//const TEST_THRESHOLDS: [usize; 4] = [5, 10, 20, 40];
//const RNG_SEED: [u8; 16] = *b"0123456789abcdef";
//
//mod poly_benches {
//    use super::*;
//    use rand::SeedableRng;
//    use rand04_compat::RngExt;
//    use rand_xorshift::XorShiftRng;
//    //use rand_xorshift::rand_core::SeedableRng; //trying this due to compiler hint
//
//    /// Benchmarks multiplication of two polynomials.
//    fn multiplication(c: &mut Criterion) {
//        let mut rng = XorShiftRng::from_seed(RNG_SEED);
//        c.bench_function_over_inputs(
//            "Polynomial multiplication",
//            move |b, &&deg| {
//                let rand_factors = || {
//                    let lhs = Poly::random(deg, &mut rng);
//                    let rhs = Poly::random(deg, &mut rng);
//                    (lhs, rhs)
//                };
//                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs * &rhs)
//            },
//            &TEST_DEGREES,
//        );
//    }
//
//    /// Benchmarks subtraction of two polynomials
//    fn subtraction(c: &mut Criterion) {
//        let mut rng = XorShiftRng::from_seed(RNG_SEED);
//        c.bench_function_over_inputs(
//            "Polynomial subtraction",
//            move |b, &&deg| {
//                let rand_factors = || {
//                    let lhs = Poly::random(deg, &mut rng);
//                    let rhs = Poly::random(deg, &mut rng);
//                    (lhs, rhs)
//                };
//                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs - &rhs)
//            },
//            &TEST_DEGREES,
//        );
//    }
//
//    /// Benchmarks addition of two polynomials
//    fn addition(c: &mut Criterion) {
//        let mut rng = XorShiftRng::from_seed(RNG_SEED);
//        c.bench_function_over_inputs(
//            "Polynomial addition",
//            move |b, &&deg| {
//                let rand_factors = || {
//                    let lhs = Poly::random(deg, &mut rng);
//                    let rhs = Poly::random(deg, &mut rng);
//                    (lhs, rhs)
//                };
//                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs + &rhs)
//            },
//            &TEST_DEGREES,
//        );
//    }
//
//    /// Benchmarks Lagrange interpolation for a polynomial.
//    fn interpolate(c: &mut Criterion) {
//        let mut rng = XorShiftRng::from_seed(RNG_SEED);
//        c.bench_function_over_inputs(
//            "Polynomial interpolation",
//            move |b, &&deg| {
//                let mut gen_tuple = |i: usize| (i, rng.gen04::<Fr>());
//                let rand_samples = move || (0..=deg).map(&mut gen_tuple).collect::<Vec<_>>();
//                b.iter_with_setup(rand_samples, Poly::interpolate)
//            },
//            &TEST_DEGREES,
//        );
//    }
//
//    criterion_group! {
//        name = poly_benches;
//        config = Criterion::default();
//        targets = multiplication, interpolate, addition, subtraction,
//    }
//}
//
//mod public_key_set_benches {
//    use super::*;
//    use rand::SeedableRng;
//    use rand_xorshift::XorShiftRng;
//    use std::collections::BTreeMap;
//    use threshold_crypto::SecretKeySet;
//
//    /// Benchmarks combining signatures
//    fn combine_signatures(c: &mut Criterion) {
//        let mut rng = XorShiftRng::from_seed(RNG_SEED);
//        let msg = "Test message";
//        c.bench_function_over_inputs(
//            "Combine Signatures",
//            move |b, &&threshold| {
//                let sk_set = SecretKeySet::random(threshold, &mut rng);
//                let pk_set = sk_set.public_keys();
//                let mut sig_parts: Vec<usize> = (0..=threshold).collect();
//                let pieces: &mut [usize] = &mut sig_parts;
//                let sigs: BTreeMap<_, _> = pieces
//                    .iter()
//                    .map(|&i| {
//                        let sig = sk_set.secret_key_share(i).sign(msg);
//                        (i, sig)
//                    })
//                    .collect();
//                b.iter(|| {
//                    pk_set
//                        .combine_signatures(&sigs)
//                        .expect("could not combine signatures");
//                })
//            },
//            &TEST_THRESHOLDS,
//        );
//    }
//
//    criterion_group! {
//        name = public_key_set_benches;
//        config = Criterion::default();
//        targets = combine_signatures,
//    }
//}
//
//criterion_main!(
//    poly_benches::poly_benches,
//    public_key_set_benches::public_key_set_benches
//);
