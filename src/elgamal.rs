//! elgamal mod
//! this is a utils for elgamal security algorithm
//! use for generating public_key
use crate::generic::PublicKey;
use crate::generic::PrivateKey;
use crate::utils;
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, EncoderTrap, Encoding};
use mt19937;
use num_bigint::{BigInt, BigUint};
use std::fmt;
use num_integer::Integer;
use num_traits::{Num, ToPrimitive};

const STR_RADIX: u32 = 10u32;

impl fmt::Display for PublicKey<BigInt> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {}, {})", self.p, self.g, self.h)
    }
}

impl PublicKey<BigInt> {
    /// generate public_key from special string
    /// # Example
    /// ~~~
    /// use elgamal_wasm::generic::PublicKey;
    /// use elgamal_wasm::KeyFormat;
    /// use num_bigint::BigInt;
    /// let pub_key:PublicKey<BigInt> = PublicKey::from_hex_str("0x747c85d7, 0x747c85d6, 0xb2040843, 32").unwrap();
    /// ~~~
    pub fn from_hex_str(key_str: &str) -> Option<PublicKey<BigInt>> {
        let keys: Vec<_> = key_str.split(", ").collect();
        println!("keys~~~~~~~~~~~~~~~~{:?}", keys);
        if keys.len() < 3 {
            println!("The input string is not valid")
        }
        let p =
            BigInt::from(BigUint::parse_bytes(keys[0].replace("0x", "").as_bytes(), 16).unwrap());
        let g =
            BigInt::from(BigUint::parse_bytes(keys[1].replace("0x", "").as_bytes(), 16).unwrap());
        let h =
            BigInt::from(BigUint::parse_bytes(keys[2].replace("0x", "").as_bytes(), 16).unwrap());
        let bit_length = keys[3].parse::<u32>().unwrap();
        let pubkey = PublicKey {
            p,
            g,
            h,
            bit_length,
        };
        Some(pubkey)
    }
}

///generate public_key with seed、bit_length、i_confidence
///Generates public key K1 (p, g, h) and private key K2 (p, g, x).
/// # Logic Desc
/// p is the prime
///
/// g is the primitive root
///
/// x is random in (0, p-1) inclusive
///
/// h = g ^ x mod p
pub fn generate_pub_key(
    seed: &Vec<u32>,
    bit_length: u32,
    i_confidence: u32,
) -> Result<(PublicKey<BigInt>, mt19937::MT19937), &'static str> {
    // let key = seed.to_u32_digits();
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
    Ok((pubkey, rng))
}

///Encrypts a string using the public key k.
///
/// # Example
/// ```rust
/// use elgamal_wasm as elgamal;
/// use num_bigint::BigUint;
/// let big_num = BigUint::from(2929u32);
/// let tuple = elgamal::generate_pub_key(&big_num.to_u32_digits(),32,32).unwrap();
/// let pubkey = tuple.0;
/// let msg = "message for encrypt";
/// let mut rng: mt19937::MT19937 = tuple.1;
/// let result = elgamal::encrypt(&pubkey, &msg, &mut rng);
/// ```
/// # Logic Desc
/// if n = 24, k = n / 8 = 3
///
/// z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
///
/// where m[i] is the ith message byte
/// ```
pub fn encrypt<R: rand_core::RngCore>(
    key: &PublicKey<BigInt>,
    s_plaintext: &str,
    rng: &mut R,
) -> Option<String> {
    let z = encode_utf16(s_plaintext, key.bit_length);
    // cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
    let mut cipher_pairs = vec![];
    // i is an integer in z
    for i_code in z {
        // pick random y from (0, p-1) inclusive
        let y = utils::gen_bigint_range(rng, &BigInt::from(0), &(&key.p));
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
    for pair in cipher_pairs {
        let pair_one = pair[0].to_str_radix(10).to_string();
        let pair_two = pair[1].to_str_radix(10).to_string();
        let space = " ".to_string();

        encrypted_str += &pair_one;
        encrypted_str += &space;
        encrypted_str += &pair_two;
        encrypted_str += &space;
    }
    Some(encrypted_str)
}

///Performs decryption on the cipher pairs found in Cipher using
///private key K2 and writes the decrypted values to file Plaintext.
pub fn decrypt(key: &PrivateKey<BigInt>, cipher_str: &str) -> Option<String> {
    // check if the last char is space
    let mut cipher_chars = cipher_str.chars();
    if let Some(last) = cipher_chars.clone().last() {
        if last.is_whitespace() {
            // if the last char is space, removed it from the string.
            cipher_chars.next_back();
        }
    } else {
        // if the cipher string is empty, return None.
        return None;
    }
    let reduced_str = cipher_chars.as_str();
    let ciphers = reduced_str.split(" ").collect::<Vec<&str>>();

    let count = ciphers.len();
    if count % 2 != 0 {
        return None;
    }
    let mut plain_text = Vec::new();
    for cd in ciphers.chunks(2) {
        // c = first number in pair
        let c = cd[0];
        let c_int = BigInt::from_str_radix(c, STR_RADIX).unwrap();
        // d = second number in pair
        let d = cd[1];
        let d_int = BigInt::from_str_radix(d, STR_RADIX).unwrap();
        // s = c^x mod p
        let s = c_int.modpow(&key.x, &key.p);
        // plaintext integer = ds^-1 mod p
        let p_2 = &key.p - BigInt::from(2);
        let mod_exp_s = s.modpow(&p_2, &key.p);
        let d_by_mod = &d_int * mod_exp_s;
        let plain_i = d_by_mod.mod_floor(&key.p);
        // add plain to list of plaintext integers
        plain_text.push(plain_i);
        // count the length of the cipher strings
    }
    Some(decode_utf16(&plain_text, key.bit_length.clone()))
}

/// Encodes bytes to integers mod p.
/// # Example
/// ```rust
/// use elgamal_wasm as elgamal;
/// let z = elgamal::encode_utf16("test", 32);
/// ```
/// # Logic Desc
/// if n = 24, k = n / 8 = 3
///
/// z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
///
/// where m[i] is the ith message byte

pub fn encode_utf16(s_plaintext: &str, bit_length: u32) -> Vec<BigInt> {
    let mut byte_array: Vec<u8> = UTF_16LE.encode(s_plaintext, EncoderTrap::Strict).unwrap();
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

///Decodes integers to the original message bytes.
/**
Example:
if "You" were encoded.
Letter        #ASCII
Y              89
o              111
u              117
if the encoded integer is 7696217 and k = 3
m[0] = 7696217 % 256 % 65536 / (2^(8*0)) = 89 = 'Y'
7696217 - (89 * (2^(8*0))) = 7696128
m[1] = 7696128 % 65536 / (2^(8*1)) = 111 = 'o'
7696128 - (111 * (2^(8*1))) = 7667712
m[2] = 7667712 / (2^(8*2)) = 117 = 'u'
 */
pub fn decode_utf16(encoded_ints: &Vec<BigInt>, bit_length: u32) -> String {
    // bytes vector will hold the decoded original message bytes
    let mut byte_array: Vec<u8> = Vec::new();
    // each encoded integer is a linear combination of k message bytes
    // k must be the number of bits in the prime divided by 8 because each
    // message byte is 8 bits long
    let k = bit_length / 8;
    for num in encoded_ints {
        let mut temp = num.clone();
        for i in 0..k {
            let idx_1 = i + 1;
            for j in idx_1..k {
                temp = temp.mod_floor(&BigInt::from(2^(8 * j)));
            }
            let two_pow_i = 2^(8 * i);
            let letter = BigInt::from(&temp / &two_pow_i).to_u8().unwrap();
            byte_array.push(letter);
            temp = num - (&(letter as u32) * two_pow_i);
        }
    }
    let raw_text = UTF_16LE.decode(&byte_array, DecoderTrap::Strict).unwrap();
    // remove the byte order mark (BOM)
    let stripped_text = raw_text.strip_prefix("\u{feff}").unwrap();
    stripped_text.to_string()
}
