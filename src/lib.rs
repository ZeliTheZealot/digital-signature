//below are LIBSECP256K1-RS extern crates
extern crate secp256k1;
extern crate hmac_drbg;
extern crate typenum;
extern crate digest;
extern crate sha2;
extern crate rand;
#[macro_use]
extern crate arrayref;
extern crate secp256k1_test;
extern crate generic_array; 

use rand::ThreadRng;
use rand::thread_rng;
use secp256k1_test::ffi::secp256k1_context_clone;
use sha2::{Sha256, Digest};
use byteorder::{BigEndian, ReadBytesExt};
use std::convert::From;
use generic_array::GenericArray;

pub struct SignatureError(String);

pub struct CommonParameters {
    secp256k1: secp256k1_test::Secp256k1,
    rng: ThreadRng,
}

pub struct PrivateKey {
    private_key: secp256k1::SecretKey,
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    public_key: secp256k1::PublicKey,
}

pub struct Signature {
    signature: secp256k1::Signature,
}

//make an constructor for Signature

pub struct RecoveryId {
    recovery_id: secp256k1::RecoveryId,
}

pub struct Error {
    error: secp256k1::Error,
}

//pub struct TheirMessage {
//    their_message: secp256k1::Message, // this is a scalar of [u32; 8]
//}

//impl From<GenericArray<u8>> for TheirMessage {
//    fn from(input: GenericArray<u8>) -> Self {
//        TheirMessage{their_message: input}
//    }
//}

pub fn sha256hash(message: &str) -> secp256k1::Message {
    let mut hasher = Sha256::default();
    let byte_message = message.as_bytes();
    hasher.input(byte_message);
    let output = hasher.result(); //a 32 byte-string literal
    //let correct_type_output = TheirMessage::from(output); //
    // go to get a use case for the functiion on the RHS
    let mut their_message_converted = [0u8; 32];
    for i in 0..32 {
        their_message_converted[i] = output[i];
    }
    secp256k1::Message::parse(&their_message_converted)
}


pub fn new() -> CommonParameters {
    let secp256k1 = secp256k1_test::Secp256k1::new();
    CommonParameters{secp256k1, rng: thread_rng()} // shorthand
}

pub fn key_gen(common_parameter: &mut CommonParameters) -> (PublicKey, PrivateKey) {
    let (private_key_from_test, _) = common_parameter.secp256k1.generate_keypair(
        &mut common_parameter.rng).unwrap();
    let private_key = secp256k1::SecretKey::parse(
        array_ref!(private_key_from_test, 0, 32)).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&private_key);
    (PublicKey{public_key }, PrivateKey{private_key })
    //shorthand for (PublicKey{public_key : public_key}, PrivateKey{private_key : private_key})
}

pub fn sign(message: &str, private_key: &PrivateKey) -> (Signature, RecoveryId) {
    //let their_message = secp256k1::Message::parse(&[5u8; 32]); //placeholder for now
    let their_message = sha256hash(&message);
    let result = secp256k1::sign(
        &their_message, &private_key.private_key);
    match result {
        Ok((signature, recovery_id)) => (
            Signature{signature }, RecoveryId{recovery_id }), //similar shorthand
        Err(error_enum) => panic!("signing error"),
    }
}

pub fn verify(message: &str, signature: &Signature, public_key: &PublicKey) -> bool {
    //let their_message= secp256k1::Message::parse(&[5u8; 32]); //placeholder for now
    let their_message = sha256hash(&message);
    secp256k1::verify(&their_message, &signature.signature, &public_key.public_key)
}

pub fn recover(message: &str, signature: &Signature, recovery_id: &RecoveryId) -> PublicKey {
    //let their_message= secp256k1::Message::parse(&[5u8; 32]); //placeholder for now
    let their_message = sha256hash(&message);
    let result = secp256k1::recover(
        &their_message, &signature.signature, &recovery_id.recovery_id);
    match result {
        Ok(public_key) => PublicKey{public_key },
        Err(error_enum) => panic!("recovering error"),
    }
}


//
/////Sign a message using the private key and returns signature and recovery id.
//pub fn signing(message: &str, private_key: &PrivateKey, common_parameter: &CommonParameters) -> Result<(Signature, RecoveryId), SignatureError> {
////    let lib_message = my_message_to_message(&my_message);
////    let lib_private_key = my_private_key_to_private_key(&my_private_key);
////    let their_result = secp256k1::sign(&lib_message, &lib_private_key);
////    let my_signature =
//
//    // need to convert message (str) to their type.
//    let message_arr = [5u8; 32];
//    let message = SecpMessage::from_slice(&message_arr).unwrap();
//    let result = common_parameter.secp256k1.sign(&message, &private_key.private_key);
//
//    match result {
//        Ok(signature) => Ok(), //put the constructor here
//        Err(error_enum) => Err(ERROR_ENUM_TO_STRING(error_enum)), //make a map to do this
//    }
//}
//
/////Check that the signature is a valid message signed by public key.
//pub fn verifying(my_message: &MyMessage, my_signature: &MySignature, my_public_key: &MyPublicKey) -> bool {
//    let lib_message = my_message_to_message(&my_message);
//    let lib_signature = my_signature_to_signature(&my_signature);
//    let lib_public_key = my_public_key_to_public_key(&my_public_key);
//    secp256k1::verify(&lib_message, &lib_signature, &lib_public_key)
//}
//
/////Recover UNCONVERTED public key from a signed message.
//pub fn recovering(my_message: &MyMessage, my_signature: &MySignature, my_recovery_id: &MyRecoverId) -> Result<secp256k1::PublicKey, secp256k1::Error> {
//    let lib_message = my_message_to_message(&my_message);
//    let lib_signature = my_signature_to_signature(&my_signature);
//    let lib_recovery_id = my_recovery_id_to_recovery_id(&my_recovery_id);
//    let their_result = secp256k1::recover(&lib_message, &lib_signature, &lib_recovery_id);
//    match their_result {
//        Ok(secp256k1::PublicKey) => Ok(my_public_key),
//        Err(secp256k1::e) => Err(e.unwrap()), //not sure of this syntax
//    }
//}

























