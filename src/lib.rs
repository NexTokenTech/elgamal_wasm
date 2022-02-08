//! elgamal_wasm
//! this is a third part for elgamal security algorithm
//! use for generating public_key and so on
//! ## Example
//! ```rust
//! use elgamal_wasm::elgamal;
//! let big_num = BigInt::from(2929);
//! let tuple = elgamal::generate_pub_key(&big_num,32,32);
//! let pubkey = tuple.0;
//! let mt19937 = tuple.1;
//! ```
pub mod elgamal;
pub mod elgamal_utils;

#[cfg(test)]
mod tests {
    use crate::elgamal;
    use crate::elgamal::KeyFormat;
    use const_num_bigint::BigInt;
    use rand_core::RngCore;
    #[test]
    fn test_rng() {
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let key = big_num.to_u32_digits();
        println!("~~~~~~~~~~~~~~~~~{:?}", key.1);
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let random_result = rng.next_u32();
        assert_eq!(3706558615, random_result);
    }
    #[test]
    fn test_public_key() {
        // let result = 2 + 2;
        // assert_eq!(result, 4);
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let public_key_result = elgamal::generate_pub_key(&big_num, 20, 32);
        if public_key_result.is_ok() {
            let result = public_key_result.unwrap();
            let pubkey = result.0;
            pubkey.print_parameter();
            assert_eq!(
                BigInt::from(8182),
                pubkey.g,
                "Public key g part is not correct!"
            );
            assert_eq!(
                BigInt::from(405406),
                pubkey.h,
                "Public key h part is not correct!"
            );
            assert_eq!(
                BigInt::from(754739),
                pubkey.p,
                "Public key p part is not correct!"
            );
        }
    }
}
