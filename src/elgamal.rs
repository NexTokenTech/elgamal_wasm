//! elgamal mod
//! this is a utils for elgamal security algorithm
//! use for generating public_key
use crate::generic::{Encryption, PublicKey};
use crate::utils;
use codec::{Decode, Encode};
use encoding::all::UTF_16LE;
use encoding::{EncoderTrap, Encoding};
use mt19937;
use num_bigint::{BigInt, Sign};
use rand_core::RngCore;
use sp_core::U256;

pub type KeyWithRng = (PublicKey<BigInt>, mt19937::MT19937);

/// Generate a seed data slice from a key data.
pub trait Seed {
    fn yield_seed_slice(&self) -> Vec<u32>;
}

impl Seed for PublicKey<BigInt> {
    fn yield_seed_slice(&self) -> Vec<u32> {
        let sum = &self.p + &self.h + &self.g;
        sum.to_u32_digits().1
    }
}

/// The raw public key type use bytes string.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct RawPublicKey {
    pub p: U256,
    pub g: U256,
    pub h: U256,
    pub bit_length: u32,
}

/// To and from raw bytes of a public key. Use little endian byte order by default.
pub trait RawKey {
    fn to_raw(self) -> RawPublicKey;
    fn from_raw(raw_key: RawPublicKey) -> Self;
}

impl RawKey for PublicKey<BigInt> {
    fn to_raw(self) -> RawPublicKey {
        RawPublicKey {
            p: U256::from_little_endian(self.p.to_bytes_le().1.as_slice()),
            g: U256::from_little_endian(self.g.to_bytes_le().1.as_slice()),
            h: U256::from_little_endian(self.h.to_bytes_le().1.as_slice()),
            bit_length: self.bit_length,
        }
    }

    fn from_raw(raw_key: RawPublicKey) -> Self {
        let mut num: [u8; 32] = [0u8; 32];
        raw_key.p.to_little_endian(&mut num);
        let p = BigInt::from_bytes_le(Sign::Plus, &num.to_vec());
        raw_key.g.to_little_endian(&mut num);
        let g = BigInt::from_bytes_le(Sign::Plus, &num.to_vec());
        raw_key.h.to_little_endian(&mut num);
        let h = BigInt::from_bytes_le(Sign::Plus, &num.to_vec());
        PublicKey::<BigInt> {
            p,
            g,
            h,
            bit_length: raw_key.bit_length,
        }
    }
}

///generate public_key with seed、bit_length、i_confidence
///Generates public key K1 (p, g, h) and private key K2 (p, g, x).
/// # Logic Desc
/// ```text
/// p is the prime
/// g is the primitive root
/// x is random in (0, p-1) inclusive
/// h = g ^ x mod p
/// ```
pub fn generate_pub_key(seed: &[u32], bit_length: u32, i_confidence: u32) -> KeyWithRng {
    let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed);
    let val = utils::random_prime_bigint(bit_length, i_confidence, &mut rng);
    let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed);
    let val1 = utils::find_primitive_root_bigint(&val, &mut rng);
    let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&seed);
    let val2 = utils::find_h_bigint(&val, &mut rng);
    let pubkey: PublicKey<BigInt> = PublicKey {
        p: val,
        g: val1,
        h: val2,
        bit_length,
    };
    (pubkey, rng)
}

impl Encryption<BigInt> for String {
    ///Encrypts a string using the public key k.
    ///
    /// # Example
    ///```rust
    /// use elgamal_wasm as elgamal;
    /// use elgamal::generic::Encryption;
    /// use num_bigint::BigUint;
    /// let big_num = BigUint::from(2929u32);
    /// let tuple = elgamal::generate_pub_key(&big_num.to_u32_digits(),32,32);
    /// let pubkey = tuple.0;
    /// let msg = String::from("message for encrypt");
    /// let mut rng: mt19937::MT19937 = tuple.1;
    /// let result = msg.encrypt(&pubkey, &mut rng);
    /// ```
    /// # Logic Desc
    /// ```text
    /// if n = 24, k = n / 8 = 3
    /// z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
    /// where m[i] is the ith message byte
    /// ```
    fn encrypt<R: RngCore>(&self, key: &PublicKey<BigInt>, rng: &mut R) -> String {
        let z = encode_utf16(self, key.bit_length);
        // cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
        let mut cipher_pairs = vec![];
        // i is an integer in z
        for i_code in z {
            // pick random y from (0, p-1) inclusive
            let y = utils::gen_bigint_range(rng, &BigInt::from(0), &key.p);
            // c = g^y mod p
            let c = key.g.modpow(&y, &key.p);
            // d = ih^y mod p
            let d = (&i_code * key.h.modpow(&y, &key.p)) % &key.p;
            // add the pair to the cipher pairs list
            let mut arr: Vec<BigInt> = Vec::new();
            arr.push(c);
            arr.push(d);
            cipher_pairs.push(arr);
        }
        let mut encrypted_str = "".to_string();
        let space = " ".to_string();
        for pair in cipher_pairs {
            let pair_one = pair[0].to_str_radix(10).to_string();
            let pair_two = pair[1].to_str_radix(10).to_string();
            encrypted_str += &pair_one;
            encrypted_str += &space;
            encrypted_str += &pair_two;
            encrypted_str += &space;
        }
        encrypted_str
    }
}

/// Encodes bytes to integers mod p.
/// # Logic Desc
/// ```text
/// if n = 24, k = n / 8 = 3
/// z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
/// where m[i] is the ith message byte
/// ```
fn encode_utf16(plaintext: &str, bit_length: u32) -> Vec<BigInt> {
    let mut byte_array: Vec<u8> = UTF_16LE.encode(plaintext, EncoderTrap::Strict).unwrap();
    byte_array.insert(0, 254);
    byte_array.insert(0, 255);

    // z is the array of integers mod p
    let mut z: Vec<BigInt> = vec![];
    // each encoded integer will be a linear combination of k message bytes
    // k must be the number of bits in the prime divided by 8 because each
    // message byte is 8 bits long
    let k: isize = (bit_length / 8) as isize;
    // j marks the jth encoded integer
    // j will start at 0 but make it -k because j will be incremented during first iteration
    let mut j: isize = -1 * k;
    // num is the summation of the message bytes
    // num = 0
    // i iterates through byte array
    for idx in 0..byte_array.len() {
        // if i is divisible by k, start a new encoded integer
        if idx as isize % k == 0 {
            j += k;
            // num = 0
            z.push(BigInt::from(0));
        }
        let index: usize = (j / k) as usize;
        let base: BigInt = BigInt::from(2);
        let mi: u32 = (8 * (idx as isize % k)) as u32;
        // add the byte multiplied by 2 raised to a multiple of 8
        z[index] += BigInt::from(byte_array[idx] as i64) * base.pow(mi);
    }
    z
}
