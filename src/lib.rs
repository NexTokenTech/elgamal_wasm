//! elgamal_wasm
//! this is a third part for elgamal security algorithm
//! use for generating public_key and so on
//! ## Example
//! ```rust
//! use elgamal_wasm as elgamal;
//! use elgamal::utils::*;
//! let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005";//!
//! let big_value = vec32_from_string(big_num);
//! let tuple = elgamal::generate_pub_key(&seed,32,32).unwrap();
//! let pubkey = tuple.0;
//! let mt19937 = tuple.1;
//! ```
mod elgamal;
pub use crate::elgamal::*;
pub mod generic;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use crate::generic::PublicKey;
    use num_bigint::BigInt;
    use rand_core::RngCore;
    use crate::utils::{vec32_from_string};

    fn seed() -> Vec<u32> {
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005";
        let big_value = vec32_from_string(big_num);
        big_value
    }
    #[test]
    fn test_rng() {
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed());
        let random_result = rng.next_u32();
        assert_eq!(3706558615, random_result);
    }
    #[test]
    fn test_public_key() {
        let public_key_result = generate_pub_key(&seed(), 20, 32);
        if public_key_result.is_ok() {
            let result = public_key_result.unwrap();
            let pubkey = result.0;
            assert_eq!("(754739, 8182, 405406)".to_owned(), format!("{}", pubkey));
        }
    }
    #[test]
    fn test_encrypt() {
        let pubkey = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed());
        let msg = "message";
        let result = encrypt(&pubkey, &msg, &mut rng);
        print!("~~~~~~~~~~~~~~~~~~~{}", result);
        assert_eq!(
            "1954317782 623638905 1 1335914958 1954317782 1931457661 1 1068518055 ", result,
            "Encrypt result is not correct!"
        );
    }
}
