//////below are LIBSECP256K1-RS extern crates
////extern crate secp256k1;
////extern crate secp256k1_test;
//extern crate rand;
////extern crate clear_on_drop;
//
////below are LIBSECP256K1-RS uses
////use secp256k1::*;
////use secp256k1::curve::*;
////use secp256k1_test::{Secp256k1, Error as SecpError, Message as SecpMessage, RecoverableSignature as SecpRecoverableSignature, RecoveryId as SecpRecoveryId, Signature as SecpSignature};
////use secp256k1_test::ecdh::{SharedSecret as SecpSharedSecret};
////use secp256k1_test::key;
//use rand::thread_rng;
//use digital_signature::{sign, new, key_gen, PrivateKey, CommonParameters};
////
//
//#[test]
//fn test_verify_libsecp256k1() {
//    let mut common_parameter = digital_signature::new();
//    let message = "hello world";
//    let (public_key, private_key) = digital_signature::key_gen(
//        &mut common_parameter);
//    let (signature, recovery_id) = digital_signature::sign(
//        &message, &private_key);
//    assert!(digital_signature::verify(
//        &message, &signature, &public_key));
//}
//
//#[test]
//fn test_recover_libsecp256k1() {
//    let mut common_parameter = digital_signature::new();
//    let message = "hello world";
//    let (public_key, private_key) = digital_signature::key_gen(
//        &mut common_parameter);
//    let (signature, recovery_id) = digital_signature::sign(
//        &message, &private_key);
//    assert_eq!(digital_signature::recover(
//        &message, &signature, &recovery_id), public_key);
//}
//
////#[test]
////fn test_sign_verify() {
////    let secp256k1 = Secp256k1::new();
////
////    let message_arr = [6u8; 32];
////    let (secp_privkey, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
////
////    let secp_message = SecpMessage::from_slice(&message_arr).unwrap();
////    let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
////    assert_eq!(pubkey_arr.len(), 65);
////    let mut pubkey_a = [0u8; 65];
////    for i in 0..65 {
////        pubkey_a[i] = pubkey_arr[i];
////    }
////    let pubkey = PublicKey::parse(&pubkey_a).unwrap();
////    let mut seckey_a = [0u8; 32];
////    for i in 0..32 {
////        seckey_a[i] = secp_privkey[i];
////    }
////    let seckey = SecretKey::parse(&seckey_a).unwrap();
////    let message = Message::parse(&message_arr);
////
////    let (sig, recid) = sign(&message, &seckey);
////
////    // Self verify
////    assert!(verify(&message, &sig, &pubkey));
////
////    // Self recover
////    let recovered_pubkey = recover(&message, &sig, &recid).unwrap();
////    let rpa = recovered_pubkey.serialize();
////    let opa = pubkey.serialize();
////    let rpr: &[u8] = &rpa;
////    let opr: &[u8] = &opa;
////    assert_eq!(rpr, opr);
////
////    let signature_a = sig.serialize();
////    let secp_recid = SecpRecoveryId::from_i32(recid.into()).unwrap();
////    let secp_rec_signature = SecpRecoverableSignature::from_compact(&secp256k1, &signature_a, secp_recid).unwrap();
////    let secp_signature = SecpSignature::from_compact(&secp256k1, &signature_a).unwrap();
////
////    // External verify
////    secp256k1.verify(&secp_message, &secp_signature, &secp_pubkey).unwrap();
////
////    // External recover
////    let recovered_pubkey = secp256k1.recover(&secp_message, &secp_rec_signature).unwrap();
////    let rpa = recovered_pubkey.serialize_vec(&secp256k1, false);
////    let rpr: &[u8] = &rpa;
////    assert_eq!(rpr, opr);
////}
////
////#[test]
////fn test_failing_sign_verify() {
////    let seckey_a: [u8; 32] = [169, 195, 92, 103, 2, 159, 75, 46, 158, 79, 249, 49, 208, 28, 48, 210, 5, 47, 136, 77, 21, 51, 224, 54, 213, 165, 90, 122, 233, 199, 0, 248];
////    let seckey = SecretKey::parse(&seckey_a).unwrap();
////    let pubkey = PublicKey::from_secret_key(&seckey);
////    let message_arr = [6u8; 32];
////    let message = Message::parse(&message_arr);
////
////    let (sig, recid) = sign(&message, &seckey);
////    let tmp: u8 = recid.into();
////    assert_eq!(tmp, 1u8);
////
////    let recovered_pubkey = recover(&message, &sig, &recid).unwrap();
////    let rpa = recovered_pubkey.serialize();
////    let opa = pubkey.serialize();
////    let rpr: &[u8] = &rpa;
////    let opr: &[u8] = &opa;
////    assert_eq!(rpr, opr);
////}
////
////#[test]
////fn test_pubkey_combine() {
////    let pk1 = PublicKey::parse(&[4, 126, 60, 36, 91, 73, 177, 194, 111, 11, 3, 99, 246, 204, 86, 122, 109, 85, 28, 43, 169, 243, 35, 76, 152, 90, 76, 241, 17, 108, 232, 215, 115, 15, 19, 23, 164, 151, 43, 28, 44, 59, 141, 167, 134, 112, 105, 251, 15, 193, 183, 224, 238, 154, 204, 230, 163, 216, 235, 112, 77, 239, 98, 135, 132]).unwrap();
////    let pk2 = PublicKey::parse(&[4, 40, 127, 167, 223, 38, 53, 6, 223, 67, 83, 204, 60, 226, 227, 107, 231, 172, 34, 3, 187, 79, 112, 167, 0, 217, 118, 69, 218, 189, 208, 150, 190, 54, 186, 220, 95, 80, 220, 183, 202, 117, 160, 18, 84, 245, 181, 23, 32, 51, 73, 178, 173, 92, 118, 92, 122, 83, 49, 54, 195, 194, 16, 229, 39]).unwrap();
////    let cpk = PublicKey::parse(&[4, 101, 166, 20, 152, 34, 76, 121, 113, 139, 80, 13, 92, 122, 96, 38, 194, 205, 149, 93, 19, 147, 132, 195, 173, 42, 86, 26, 221, 170, 127, 180, 168, 145, 21, 75, 45, 248, 90, 114, 118, 62, 196, 194, 143, 245, 204, 184, 16, 175, 202, 175, 228, 207, 112, 219, 94, 237, 75, 105, 186, 56, 102, 46, 147]).unwrap();
////
////    assert_eq!(PublicKey::combine(&[pk1, pk2]).unwrap(), cpk);
////}