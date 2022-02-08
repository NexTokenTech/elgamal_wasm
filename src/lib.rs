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
    use crate::{elgamal, elgamal_utils};
    use crate::elgamal::KeyFormat;
    use const_num_bigint::BigInt;
    use rand_core::RngCore;
    use crate::elgamal::PublicKey;
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
    #[test]
    fn test_public_key_from_hex(){
        let pubkey = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        pubkey.print_parameter();
        assert_eq!(
            BigInt::from(1954317782u64),
            pubkey.g,
            "Public key g part is not correct!"
        );
        assert_eq!(
            BigInt::from(2986608707u64),
            pubkey.h,
            "Public key h part is not correct!"
        );
        assert_eq!(
            BigInt::from(1954317783u64),
            pubkey.p,
            "Public key p part is not correct!"
        );
    }
    #[test]
    fn test_encrypt(){
        let pubkey = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let key = big_num.to_u32_digits();
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let msg = "message";
        let result = elgamal::encrypt(&pubkey, &msg, &mut rng);
        print!("~~~~~~~~~~~~~~~~~~~{}",result);
        assert_eq!(
            "1954317782 623638905 1 1335914958 1954317782 1931457661 1 1068518055 ",
            result,
            "Encrypt result is not correct!"
        );
    }
    #[test]
    fn test_encode_utf16(){
        let s_plaintext = "message";
        let pubkey = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let z = elgamal::encode_utf16(s_plaintext, pubkey.bit_length);
        assert_eq!(
            vec![BigInt::from(7208703), BigInt::from(7536741), BigInt::from(6357107), BigInt::from(6619239)],
            z,
            "Encode result is not correct!"
        );
    }
    #[test]
    fn test_p(){
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let key = big_num.to_u32_digits();
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let bit_length= 20;
        let i_confidence = 32;
        let p = elgamal_utils::random_prime_bigint(bit_length, i_confidence, &mut rng);
        assert_eq!(
            BigInt::from(754739),
            p,
            "p is not correct!"
        )
    }
    #[test]
    fn test_g(){
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let key = big_num.to_u32_digits();
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let p = BigInt::from(754739);
        let g = elgamal_utils::find_primitive_root_bigint(&p, &mut rng);
        assert_eq!(
            BigInt::from(8182),
            g,
            "g is not correct!"
        )
    }
    #[test]
    fn test_h(){
        let big_num = "833050814021254693158343911234888353695402778102174580258852673738983005"
            .parse::<BigInt>()
            .unwrap();
        let key = big_num.to_u32_digits();
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let p = BigInt::from(754739);
        let h = elgamal_utils::find_h_bigint(&p, &mut rng);
        assert_eq!(
            BigInt::from(405406),
            h,
            "h is not correct!"
        )
    }
}
