//! elgamal_wasm
//! this is a third part for elgamal security algorithm
//! use for generating public_key and so on
//! ## Example
//! ```rust
//! use elgamal_wasm as elgamal;
//! let seed:Vec<u32> = vec![3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852, 30899];
//! let tuple = elgamal::generate_pub_key(&seed,32,32).unwrap();
//! let pubkey = tuple.0;
//! let mt19937 = tuple.1;
//! ```

mod elgamal;
pub use crate::elgamal::*;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use rand_core::RngCore;

    //TODO: convert String to Vec<u32>
    #[test]
    fn test_string_to_vecu32() {
        let big_num =
            "833050814021254693158343911234888353695402778102174580258852673738983005".as_bytes();
        println!("~~~~~~~~~~~~~~~~{:?}", big_num);
    }
    #[test]
    fn test_rng() {
        let seed: Vec<u32> = vec![
            3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852,
            30899,
        ];
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed);
        let random_result = rng.next_u32();
        assert_eq!(3706558615, random_result);
    }
    #[test]
    fn test_public_key() {
        let seed: Vec<u32> = vec![
            3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852,
            30899,
        ];
        let public_key_result = generate_pub_key(&seed, 20, 32);
        if public_key_result.is_ok() {
            let result = public_key_result.unwrap();
            let pubkey = result.0;
            assert_eq!("(754739, 8182, 405406)".to_owned(), format!("{}", pubkey));
        }
    }
    #[test]
    fn test_encrypt() {
        let pubkey = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32");
        let seed: Vec<u32> = vec![
            3903800925, 2970875772, 2545702139, 2279902533, 3917580227, 2452829718, 2456858852,
            30899,
        ];
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed);
        let msg = "message";
        let result = encrypt(&pubkey, &msg, &mut rng);
        print!("~~~~~~~~~~~~~~~~~~~{}", result);
        assert_eq!(
            "1954317782 623638905 1 1335914958 1954317782 1931457661 1 1068518055 ", result,
            "Encrypt result is not correct!"
        );
    }
}
