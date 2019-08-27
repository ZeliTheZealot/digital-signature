#![feature(test)]
extern crate test;
extern crate rand;
extern crate arrayref;

use test::Bencher;

#[bench]
fn bench_sign_message_libsecp256k1(b: &mut Bencher) {
    let mut common_parameter = digital_signature::common::ecdsa::initialize();
    let message = "hello world";
    let (_, private_key) = digital_signature::common::ecdsa::key_gen(&mut common_parameter);
    b.iter(|| {
        let _ = digital_signature::common::ecdsa::sign(&message, &private_key);
    });
}
