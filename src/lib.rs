#![feature(slice_pattern)]
//! elgamal_wasm
//! This is a third part for elgamal security algorithm
//! used for generating public keys for elgamal systems and etc.
mod elgamal;
pub use crate::elgamal::*;
pub mod generic;
pub mod utils;

use crate::generic::PublicKey;
use num_bigint::{BigInt, BigUint};
use std::fmt;

impl fmt::Display for PublicKey<BigInt> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {}, {})", self.p, self.g, self.h)
    }
}

/// trait for printing some struct
pub trait KeyFormat {
    fn from_hex_str(key_str: &str) -> Self;
}

impl KeyFormat for PublicKey<BigInt> {
    /// generate public_key from special string
    /// # Example
    /// ~~~
    /// use elgamal_wasm::generic::PublicKey;
    /// use elgamal_wasm::KeyFormat;
    /// use num_bigint::BigInt;
    /// let pub_key:PublicKey<BigInt> = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
    /// ~~~
    #[inline]
    fn from_hex_str(key_str: &str) -> PublicKey<BigInt> {
        let keys: Vec<_> = key_str.split(", ").collect();
        let p =
            BigInt::from(BigUint::parse_bytes(keys[0].replace("0x", "").as_bytes(), 16).unwrap());
        let g =
            BigInt::from(BigUint::parse_bytes(keys[1].replace("0x", "").as_bytes(), 16).unwrap());
        let h =
            BigInt::from(BigUint::parse_bytes(keys[2].replace("0x", "").as_bytes(), 16).unwrap());
        let bit_length = keys[3].parse::<u32>().unwrap();
        PublicKey {
            p,
            g,
            h,
            bit_length,
        }
    }
}

/// Rust generator is not yet stable, use self-defined generator trait.
pub trait KeyGenerator {
    const CONFIDENCE: u32;
    /// Use current data slices as seed and generate a new public key.
    fn yield_pubkey(&self, bit_length: u32) -> Self;
}

impl KeyGenerator for RawPublicKey {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let pubkey_int = PublicKey::<BigInt>::from_raw(self.clone());
        let seed = pubkey_int.yield_seed_slice();
        // NOTE: confidence is hard coded as 32.
        let new_key = elgamal::generate_pub_key(&seed, bit_length, Self::CONFIDENCE).0;
        new_key.to_raw()
    }
}

impl KeyGenerator for PublicKey<BigInt> {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let seed = self.yield_seed_slice();
        elgamal::generate_pub_key(&seed, bit_length, Self::CONFIDENCE).0
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use crate::generic::{Encryption, PublicKey};
    use crate::*;
    use crate::{KeyGenerator, RawKey, RawPublicKey};
    use codec::{Decode, Encode};
    use num_bigint::BigInt;
    use num_traits::Num;
    use rand_core::RngCore;

    const SEED: [u32; 8] = [
        3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852, 30899,
    ];

    #[test]
    fn test_encode_raw_pub_key() {
        // test serialization and deserialization of public keys.
        let pubkey = PublicKey::<BigInt>::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let raw_key = pubkey.clone().to_raw();
        let encoded = raw_key.encode();
        let decoded = RawPublicKey::decode(&mut encoded.as_slice()).unwrap();
        let new_key = PublicKey::<BigInt>::from_raw(decoded);
        assert_eq!(format!("{}", pubkey), format!("{}", new_key));
    }

    #[test]
    fn test_string_to_vec_u32() {
        let num_str = "833050814021254693158343911234888353695402778102174580258852673738983005";
        let big_num = BigInt::from_str_radix(&num_str, 10).unwrap();
        let num_vec = big_num.to_u32_digits().1;
        assert_eq!(SEED.len(), num_vec.len());
        assert_eq!(SEED[0], num_vec[0]);
    }

    #[test]
    fn test_rng() {
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&SEED);
        let random_result = rng.next_u32();
        assert_eq!(3706558615, random_result);
    }

    #[test]
    fn test_public_key_generation() {
        let public_key_result = generate_pub_key(&SEED, 20, 32);
        let pubkey = public_key_result.0;
        assert_eq!("(754739, 8182, 405406)".to_owned(), format!("{}", pubkey));
        // yield a new key from existing key.
        let new_key = pubkey.yield_pubkey(32);
        assert_eq!(
            "(3934240439, 1414000972, 1414000971)".to_owned(),
            format!("{}", new_key)
        );
    }

    #[test]
    fn test_encrypt() {
        let pubkey = PublicKey::<BigInt>::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&SEED);
        let msg = String::from("message");
        let result = msg.encrypt(&pubkey, &mut rng);
        assert_eq!(
            "1954317782 623638905 1 1335914958 1954317782 1931457661 1 1068518055 ", result,
            "Encrypt result is not correct!"
        );
    }
}
