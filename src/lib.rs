#![feature(slice_pattern)]
//! elgamal_wasm
//! this is a third part for elgamal security algorithm
//! use for generating public_key and so on
//! ## Example
//! ```rust
//! use elgamal_wasm as elgamal;
//! let seed:Vec<u32> = vec![3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852, 30899];
//! let tuple = elgamal::generate_pub_key(&seed,32,32);
//! let pubkey = tuple.0;
//! let mt19937 = tuple.1;
//! ```
extern crate core;

mod elgamal;

pub use crate::elgamal::*;
use crate::generic::PublicKey;
use num_bigint::BigInt;

pub mod generic;
pub mod utils;

/// Rust generator is not yet stable, use self-defined generator trait.
pub trait KeyGenerator {
    /// Use current data slices as seed and generate a new public key.
    fn yield_pubkey(&self, bit_length: u32) -> Self;
}

impl KeyGenerator for RawPublicKey {
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let pubkey_int = PublicKey::<BigInt>::from_raw(self.clone());
        let seed = pubkey_int.yield_seed_slice();
        // NOTE: confidence is hard coded as 32.
        let new_key = elgamal::generate_pub_key(&seed, bit_length, 32).0;
        new_key.to_raw()
    }
}

impl KeyGenerator for PublicKey<BigInt> {
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let seed = self.yield_seed_slice();
        elgamal::generate_pub_key(&seed, bit_length, 32).0
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use crate::generic::{Encryption, PublicKey};
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
