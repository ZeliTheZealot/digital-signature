//below are LIBSECP256K1-RS extern crates
extern crate secp256k1;
#![no_std]
extern crate hmac_drbg;
extern crate typenum;
extern crate digest;
extern crate sha2;
extern crate rand;
#[macro_use]
extern crate arrayref;

//below are LIBSECP256K1-RS uses
//use secp256k1::{sign, SecretKey, Message, PublicKey, Signature};
//use secp256k1_test::{Secp256k1, Message as SecpMessage};
//use rand::thread_rng;

//example usage:
// use secp256k1::{sign, SecretKey, Message, PublicKey, Signature};
// just type secp256k1::sign, secp256k1::SecretKey etc

struct MyMessage {
    my_message: String
}

struct MyPrivateKey {
    my_private_key: u256,
}

struct MyPublicKey {
    my_public_key: u320,
}

struct MySignature {
    my_signature: u512,
}

struct MyRecoveryId {
    my_recovery_id: u8,
}


///converts a MyMessage type to the Message type in the secp256k1 library.
///note: Message, Scalar, r, s are all public, so we can actually do this.
///note: Scalar is a 256-bit value (8 u32s).
fn my_message_to_message(my_message: &MyMessage) -> secp256k1::Message {

}

fn my_private_key_to_private_key(my_private_key: &MyPrivateKey) -> secp256k1::SecretKey {

}

fn my_signature_to_signature(my_signature: &MySignature) -> secp256k1::Signature {

}

fn my_public_key_to_public_key(my_public_key: &MyPublicKey) -> secp256k1::PublicKey {

}

fn my_recovery_id_to_recovery_id(my_recovery_id: &MyRecoveryId) -> secp256k1::RecoveryId {

}

///Sign a message using the private key and returns UNCONVERTED signature and recovery id.
pub fn signing(my_message: &MyMessage, my_private_key: &MyPrivateKey) -> Result<(secp256k1::Signature, secp256k1::RecoveryId), secp256k1::Error> {
    let &lib_message = my_message_to_message(my_message);
    let &lib_private_key = my_private_key_to_private_key(my_private_key);
    return secp256k1::sign(lib_message, lib_private_key);
}

///Check that the signature is a valid message signed by public key.
pub fn verifying(my_message: &MyMessage, my_signature: &MySignature, my_public_key: &MyPublicKey) -> bool {
    let &lib_message = my_message_to_message(my_message);
    let &lib_signature = my_signature_to_signature(my_signature);
    let &lib_public_key = my_public_key_to_public_key(my_public_key);
    secp256k1::verify(lib_message, lib_signature, lib_public_key)
}

///Recover UNCONVERTED public key from a signed message.
pub fn recovering(my_message: &MyMessage, my_signature: &MySignature, my_recovery_id: &MyRecoverId) -> Result<secp256k1::PublicKey, secp256k1::Error> {
    let &lib_message = my_message_to_message(my_message);
    let &lib_signature = my_signature_to_signature(my_signature);
    let &lib_recover_id = my_recovery_id_to_recovery_id(my_recovery_id);
    secp256k1::recover(lib_message, lib_signature, lib_recover_id)
}