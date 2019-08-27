//! This crate wraps libsecp256k1. The message is a str and we use Sha256 for hashing.
//!
//! # Example
//!
//! Creating a signature on a message is simple.
//!
//! First, we need to initialise the crate and generate the key-pair which include the public key
//! and the private key.
//!
//! ```
//! use digital_signature::common::ecdsa::*;
//! fn main() {
//! let mut common_parameter = initialize();
//! let (public_key, private_key) = key_gen(&mut common_parameter);
//! }
//! ```
//!
//! We can now use the private key to sign our message str.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameter = initialize();
//! # let (public_key, private_key) = key_gen(&mut common_parameter);
//! let message = "hello world";
//! let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! # }
//! ```
//!
//! To verify that the signature is valid for our message, we use the public key.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameter = initialize();
//! # let (public_key, private_key) = key_gen(&mut common_parameter);
//! # let message = "hello world";
//! # let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! assert!(verify(&message, &signature, &public_key));
//! # }
//! ```
//!
//! Finally, we can recover the public key using the message and the output of the
//! signing function.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameter = initialize();
//! # let (public_key, private_key) = key_gen(&mut common_parameter);
//! # let message = "hello world";
//! # let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! # assert!(verify(&message, &signature, &public_key));
//! assert_eq!(recover(&message, &signature, &recovery_id).unwrap(), public_key);
//! # }
//! ```

extern crate secp256k1;
extern crate hmac_drbg;
extern crate typenum;
extern crate digest;
extern crate sha2;
extern crate rand;
extern crate secp256k1_test;
extern crate generic_array;

use rand::ThreadRng;
use rand::thread_rng;
use sha2::{Sha256, Digest};

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

pub struct RecoveryId {
    recovery_id: secp256k1::RecoveryId,
}

fn to_error(error_enum: secp256k1::Error) -> Error {
    let result = match error_enum {
        secp256k1::Error::InvalidSignature=> "InvalidSignature",
        secp256k1::Error::InvalidPublicKey=> "InvalidPublicKey",
        secp256k1::Error::InvalidSecretKey=> "InvalidSecretKey",
        secp256k1::Error::InvalidRecoveryId=> "InvalidRecoveryId",
        secp256k1::Error::InvalidMessage=> "InvalidMessage",
        secp256k1::Error::InvalidInputLength=> "InvalidInputLength",
        secp256k1::Error::TweakOutOfRange=> "TweakOutOfRange",
    };
    Error(result.to_string())
}

#[derive(Debug)]
pub struct Error(String);

pub fn sha256hash(message: &str) -> secp256k1::Message {
    let mut hasher = Sha256::default();
    let byte_message = message.as_bytes();
    hasher.input(byte_message);
    let output = hasher.result();
    let mut their_message_converted = [0u8; 32];
    for i in 0..32 {
        their_message_converted[i] = output[i];
    }
    secp256k1::Message::parse(&their_message_converted)
}

pub fn initialize() -> CommonParameters {
    let secp256k1 = secp256k1_test::Secp256k1::new();
    CommonParameters{secp256k1, rng: thread_rng()}
}

pub fn key_gen(common_parameter: &mut CommonParameters) -> (PublicKey, PrivateKey) {
    let (private_key_from_test, _) = common_parameter.secp256k1.generate_keypair(
        &mut common_parameter.rng).unwrap();
    let private_key = secp256k1::SecretKey::parse(
        array_ref!(private_key_from_test, 0, 32)).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&private_key);
    (PublicKey{public_key}, PrivateKey{private_key})
}

pub fn sign(message: &str, private_key: &PrivateKey) -> Result<(Signature, RecoveryId), Error> {
    let their_message = sha256hash(&message);
    let result = secp256k1::sign(
        &their_message, &private_key.private_key);
    match result {
        Ok((signature, recovery_id)) => Ok(
            (Signature{signature}, RecoveryId{recovery_id})),
        Err(error_enum) => Err(to_error(error_enum)),
    }
}

pub fn verify(message: &str, signature: &Signature, public_key: &PublicKey) -> bool {
    let their_message = sha256hash(&message);
    secp256k1::verify(&their_message, &signature.signature, &public_key.public_key)
}

pub fn recover(message: &str, signature: &Signature,
               recovery_id: &RecoveryId) -> Result<PublicKey, Error> {
    let their_message = sha256hash(&message);
    let result = secp256k1::recover(
        &their_message, &signature.signature, &recovery_id.recovery_id);
    match result {
        Ok(public_key) => Ok(PublicKey{public_key}),
        Err(error_enum) => Err(to_error(error_enum)),
    }
}

#[test]
fn test_sign_and_verify() {
    let mut common_parameter = initialize();
    let message = "hello world";
    let (public_key, private_key) = key_gen(&mut common_parameter);
    let (signature, _) = sign(&message, &private_key).unwrap();
    assert!(verify(&message, &signature, &public_key));
}

#[test]
fn test_recover_public_key() {
    let mut common_parameter = initialize();
    let message = "hello world";
    let (public_key, private_key) = key_gen(&mut common_parameter);
    let (signature, recovery_id) = sign(&message, &private_key).unwrap();
    assert_eq!(recover(&message, &signature, &recovery_id).unwrap(), public_key);
}
