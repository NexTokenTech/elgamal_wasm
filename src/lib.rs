#[cfg(test)]
mod tests {
    use num::BigInt;
    use crate::elgamal;
    #[test]
    fn it_works() {
        // let result = 2 + 2;
        // assert_eq!(result, 4);
        elgamal::generate_pub_key(&BigInt::from(2929),32,32);
    }
}


/// elgamal mod
/// this is a utils for elgamal security algorithm
/// use for generating public_key
/// ```rust
/// # use elgamal_capsule::elgamal;
/// let big_num = BigInt::from(2929);
/// let tuple = elgamal::generate_pub_key(&big_num,32,32);
/// let pubkey = tuple.0;
/// let mt19937 = tuple.1;
/// ```
pub mod elgamal {
    use crate::elgamal_utils;
    use mt19937;
    use num::bigint::BigInt;
    use encoding::{Encoding, EncoderTrap};
    use encoding::all::UTF_16LE;
    use num::BigUint;

    pub fn test_fn(){
        println!("test function suc");
    }

    ///Init public key structure for elgamal encryption.
    ///
    ///             Args:
    ///                 p: a large prime number
    ///                 g: a generator
    ///                 h:
    ///                 bit_length: bit length of the prime number
    #[derive(Debug)]
    pub struct PublicKey {
        pub p: BigInt,
        pub g: BigInt,
        pub h: BigInt,
        pub bit_length: u32,
    }

    ///init private key structure for elgamal encryption.
    ///
    ///             Args:
    ///                 p: a large prime number
    ///                 g: a generator
    ///                 x: a randomly chosen key
    ///                 bit_length: bit length of the prime number
    #[derive(Debug)]
    pub struct PrivateKey {
        pub p: BigInt,
        pub g: BigInt,
        pub x: BigInt,
    }

    impl PublicKey {
        ///print public_key's p、g、h
        pub fn print_parameter(&self) {
            println!("_____________");
            println!("p:{}", self.p);
            println!("g:{}", self.g);
            println!("h:{}", self.h);
        }
        ///Generate a public key from string.
        pub fn from_hex_str(key_str:&str)->PublicKey{
            let keys:Vec<_> = key_str.split(", ").collect();
            println!("keys~~~~~~~~~~~~~~~~{:?}",keys);
            if keys.len() < 3{
                println!("The input string is not valid")
            }
            let p = BigInt::from(BigUint::parse_bytes(keys[0].replace("0x", "").as_bytes(), 16).unwrap());
            let g = BigInt::from(BigUint::parse_bytes(keys[1].replace("0x", "").as_bytes(), 16).unwrap());
            let h = BigInt::from(BigUint::parse_bytes(keys[2].replace("0x", "").as_bytes(), 16).unwrap());
            let bit_length = keys[3].parse::<u32>().unwrap();
            PublicKey{
                p,
                g,
                h,
                bit_length
            }
        }
    }

    ///generate public_key with seed、bit_length、i_confidence
    ///Generates public key K1 (p, g, h) and private key K2 (p, g, x).
    ///
    ///         Args:
    ///             seed:
    ///             bit_length:
    ///             i_confidence:
    ///
    ///         Returns:
    ///
    ///          p is the prime
    ///          g is the primitive root
    ///          x is random in (0, p-1) inclusive
    ///          h = g ^ x mod p
    pub fn generate_pub_key(seed: &BigInt, bit_length: u32, i_confidence: u32) -> (PublicKey, mt19937::MT19937) {
        let key = seed.to_u32_digits();
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let val = elgamal_utils::random_prime_bigint(bit_length, i_confidence, &mut rng);
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let val1 = elgamal_utils::find_primitive_root_bigint(&val,&mut rng);
        let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
        let val2 = elgamal_utils::find_h_bigint(&val,&mut rng);
        let pubkey: PublicKey = PublicKey {
            p: val,
            g: val1,
            h: val2,
            bit_length,
        };
        println!("p:{}~~~~~~~~g:{}~~~~~~~~~~~h:{}",pubkey.p,pubkey.g,pubkey.h);
        (pubkey,rng)
    }

    ///Encrypts a string using the public key k.
    ///
    ///         Args:
    ///             key: public key for encryption
    ///             s_plaintext: input message string
    ///
    ///         Returns:
    ///             Encrypted text string.
    pub fn encrypt<R: rand_core::RngCore>(key:&PublicKey,s_plaintext:&str,rng:&mut R) -> String{
        let z = encode_utf16(s_plaintext, key.bit_length);
        // cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
        let mut cipher_pairs = vec!();
        // i is an integer in z
        for i_code in z{
            // pick random y from (0, p-1) inclusive
            let y = elgamal_utils::gen_bigint_range(rng, &elgamal_utils::to_bigint_from_int(0), &(&key.p));
            // c = g^y mod p
            let c = key.g.modpow(&y, &key.p);
            // d = ih^y mod p
            let d = (&i_code * key.h.modpow(&y, &key.p)) % &key.p;
            // add the pair to the cipher pairs list
            let mut arr:Vec<BigInt> = Vec::new();
            arr.push(c);
            arr.push(d);
            cipher_pairs.push(arr);
        }
        let mut encrypted_str = "".to_string();
        for pair in cipher_pairs{
            let pair_one = pair[0].to_str_radix(10).to_string();
            let pair_two = pair[1].to_str_radix(10).to_string();
            let space = " ".to_string();

            encrypted_str += &pair_one;
            encrypted_str += &space;
            encrypted_str += &pair_two;
            encrypted_str += &space;
        }
        encrypted_str
    }

    ///Encodes bytes to integers mod p.
    ///         Example
    ///         if n = 24, k = n / 8 = 3
    ///         z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
    ///         where m[i] is the ith message byte
    ///
    ///         Args:
    ///             s_plaintext: String text to be encoded
    ///             bit_length: bit length of the prime number
    ///
    ///         Returns:
    ///             A list of encoded integers
    pub fn encode_utf16(s_plaintext:&str,bit_length:u32) -> Vec<BigInt>{
        let mut byte_array:Vec<u8> = UTF_16LE.encode(s_plaintext, EncoderTrap::Strict).unwrap();
        byte_array.insert(0, 254);
        byte_array.insert(0, 255);

        // z is the array of integers mod p
        let mut z:Vec<BigInt> = vec![];
        // each encoded integer will be a linear combination of k message bytes
        // k must be the number of bits in the prime divided by 8 because each
        // message byte is 8 bits long
        let k:isize = (bit_length / 8) as isize;
        // j marks the jth encoded integer
        // j will start at 0 but make it -k because j will be incremented during first iteration
        let mut j:isize = -1  * k;
        // num is the summation of the message bytes
        // num = 0
        // i iterates through byte array
        for idx in 0..byte_array.len(){
            // if i is divisible by k, start a new encoded integer
            if idx as isize % k == 0{
                j += k;
                // num = 0
                z.push(elgamal_utils::to_bigint_from_int(0));
            }
            let index:usize = (j / k) as usize;
            let base:BigInt = elgamal_utils::to_bigint_from_int(2);
            let mi:u32 = (8*(idx as isize % k)) as u32;
            // add the byte multiplied by 2 raised to a multiple of 8
            z[index] += elgamal_utils::to_bigint_from_int(byte_array[idx] as i64) * base.pow(mi);
        }
        z
    }
}

///elgamal_utils mod
/// use for supporting elgamal public_key generating
/// generate p: a big prime
/// generate g: a prime root
/// generate h: a random from seed
pub mod elgamal_utils{
    #![allow(clippy::unreadable_literal, clippy::upper_case_acronyms)]
    use mt19937::MT19937;
    use mt19937;
    use num::bigint::{BigInt, BigUint, ToBigInt, Sign};
    use num::traits::{Zero,One};
    use num::Integer;

    /** These real versions are due to Kaisuki, 2021/01/07 added */
    pub fn gen_bigint_range<R: rand_core::RngCore>(
        rng: &mut R,
        start: &BigInt,
        stop: &BigInt,
    ) -> BigInt {
        let width: BigInt = stop + 1 - start;
        let k: u64 = width.bits(); // don't use (n-1) here because n can be 1
        let mut r: BigInt = getrandbits(rng, k as usize); // 0 <= r < 2**k
        while r >= width {
            r = getrandbits(rng, k as usize);
        }
        return start + r;
    }

    /// Return an integer with k random bits.
    fn getrandbits<R: rand_core::RngCore>(rng: &mut R, k: usize) -> BigInt {
        if k == 0 {
            return BigInt::from_slice(Sign::NoSign, &[0]);
            // return Err(
            //     vm.new_value_error("number of bits must be greater than zero".to_owned())
            // );
        }

        // let mut rng = self.rng.lock();
        let mut k = k;
        let mut gen_u32 = |k| {
            let r = rng.next_u32();
            if k < 32 {
                r >> (32 - k)
            } else {
                r
            }
        };

        if k <= 32 {
            return gen_u32(k).into();
        }

        let words = (k - 1) / 32 + 1;
        let wordarray = (0..words)
            .map(|_| {
                let word = gen_u32(k);
                k = k.wrapping_sub(32);
                word
            })
            .collect::<Vec<_>>();

        let uint = BigUint::new(wordarray);
        // very unlikely but might as well check
        let sign = if uint.is_zero() {
            Sign::NoSign
        } else {
            Sign::Plus
        };
        BigInt::from_biguint(sign, uint)
    }

    ///Find a prime number p for elgamal public key.
    ///
    ///             Args:
    ///             bit_length: number of binary bits for the prime number.
    ///             i_confidence:
    ///             seed: random generator seed
    ///
    ///         Returns:
    ///             A prime number with requested length of bits in binary.
    #[allow(unused)]
    pub fn random_prime_bigint(
        bit_length: u32,
        i_confidence: u32,
        r: &mut mt19937::MT19937,
    ) -> BigInt {
        let zero: BigInt = Zero::zero();
        //keep testing until one is found
        loop {
            let one: BigInt = One::one();
            let two: BigInt = &one + &one;
            // generate potential prime randomly
            let mut p = gen_prime(&bit_length, r);
            // make sure it is odd
            while p.mod_floor(&two) == zero {
                p = gen_prime(&bit_length, r);
            }
            // keep doing this if the solovay-strassen test fails
            while solovay_strassen(&p, i_confidence, r) != true {
                p = gen_prime(&bit_length, r);
                while p.mod_floor(&two) == zero {
                    p = gen_prime(&bit_length, r);
                }
            }
            // if p is prime compute p = 2*p + 1
            // this step is critical to protect the encryption from Pohlig–Hellman algorithm
            // if p is prime, we have succeeded; else, start over
            p = p * two + one;
            if solovay_strassen(&p, i_confidence, r) == true {
                return p;
            }
        }
    }

    fn gen_prime(bit_length: &u32, r: &mut mt19937::MT19937) -> BigInt {
        let base: BigInt = to_bigint_from_int(2);
        let pow_num_low: BigInt = (bit_length - 2).to_bigint().unwrap();
        let pow_num_high: BigInt = (bit_length - 1).to_bigint().unwrap();
        let low = pow_bigint(&base, &pow_num_low);
        let high = pow_bigint(&base, &pow_num_high);
        let p: BigInt = gen_bigint_range(r, &low, &high);
        p
    }

    ///Finds a primitive root for prime p.
    ///         This function was implemented from the algorithm described here:
    ///         http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
    ///
    ///         Args:
    ///             p:
    ///             seed:
    ///
    ///         Returns:
    ///             A primitive root for prime p.
    /// the prime divisors of p-1 are 2 and (p-1)/2 because
    /// p = 2x + 1 where x is a prime
    pub fn find_primitive_root_bigint(p: &BigInt,r: &mut mt19937::MT19937) -> BigInt {
        let one: BigInt = One::one();
        let two: BigInt = &one + &one;
        if *p == two {
            return One::one();
        }
        let p1: BigInt = two;

        let p2: BigInt = (p - &one) / p1;
        let p3: BigInt = (p - &one) / &p2;
        let mut g;
        //test random g's until one is found that is a primitive root mod p
        loop {
            let range_num_low: BigInt = &one + &one;
            let range_num_high: BigInt = p - &one;
            g = gen_bigint_range(r, &range_num_low, &range_num_high);
            // g is a primitive root if for all prime factors of p-1, p[i]
            // g^((p-1)/p[i]) (mod p) is not congruent to 1
            if g.modpow(&p2, &p) != one {
                if g.modpow(&p3, &p) != one {
                    return g;
                }
            }
        }
    }

    pub fn find_h_bigint(p: &BigInt,r: &mut mt19937::MT19937) -> BigInt {
        let one: BigInt = One::one();
        let range_num_low: BigInt = One::one();
        let range_num_high: BigInt = p - &one;
        let h = gen_bigint_range(r, &range_num_low, &range_num_high);
        h
    }

    /// Solovay-strassen primality test.
    ///     This function tests if num is prime.
    ///     http://www-math.ucdenver.edu/~wcherowi/courses/m5410/ctcprime.html
    ///
    ///     Args:
    ///     num: input integer
    /// i_confidence:
    ///
    ///     Returns:
    /// if pass the test
    /// ensure confidence of t
    pub fn solovay_strassen(num: &BigInt, i_confidence: u32, r: &mut MT19937) -> bool {
        for _idx in 0..i_confidence {
            let one: BigInt = One::one();
            let high: BigInt = num - &one;
            //choose random a between 1 and n-2
            let a: BigInt = gen_bigint_range(r, &one, &high);

            let two: BigInt = &one +&one;
            // if a is not relatively prime to n, n is composite
            if a.gcd(num) > one {
                return false;
            }
            //declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
            let jacobi_result: BigInt = jacobi(&a, num).mod_floor(num);
            let mi: BigInt = (num - &one) / &two;
            let pow_reulst: BigInt = a.modpow(&mi, num);
            if jacobi_result != pow_reulst {
                return false;
            }
        }
        //if there have been t iterations without failure, num is believed to be prime
        return true;
    }

    /// Computes the jacobi symbol of a, n.
    ///
    ///     Args:
    ///     a:
    ///     n:
    ///
    ///     Returns:
    pub fn jacobi(a: &BigInt, n: &BigInt) -> BigInt {
        let bigint_0: BigInt = Zero::zero();
        let bigint_1: BigInt = One::one();
        let bigint_2: BigInt = to_bigint_from_int(2);
        let bigint_r1: BigInt = to_bigint_from_int(-1);
        let bigint_3: BigInt = to_bigint_from_int(3);
        let bigint_4: BigInt = to_bigint_from_int(4);
        let bigint_5: BigInt = to_bigint_from_int(5);
        let bigint_7: BigInt = to_bigint_from_int(7);
        let bigint_8: BigInt = to_bigint_from_int(8);
        return match a {
            a if a == &bigint_0 => {
                if n == &bigint_1 {
                    bigint_1.clone()
                } else {
                    bigint_0.clone()
                }
            },
            a if a == &bigint_r1 => {
                if n.mod_floor(&bigint_2) == bigint_0 {
                    bigint_1.clone()
                } else {
                    bigint_r1.clone()
                }
            },
            a if a == &bigint_1 => {
                bigint_1.clone()
            },
            a if a == &bigint_2 => {
                if (n.mod_floor(&bigint_8) == bigint_1) || (n.mod_floor(&bigint_8) == bigint_7) {
                    bigint_1.clone()
                } else if (n.mod_floor(&bigint_8) == bigint_3) || (n.mod_floor(&bigint_8) == bigint_5) {
                    bigint_r1.clone()
                } else {
                    bigint_0.clone()
                }
            },
            a if a >= n =>{
                let tmp_a = a.mod_floor(n);
                jacobi(&tmp_a, n)
            },
            a if a.mod_floor(&bigint_2) == bigint_0 =>{
                let tmp_a2 = a / &bigint_2;
                jacobi(&bigint_2, n) * jacobi(&tmp_a2, n)
            },
            _ => {
                if (a.mod_floor(&bigint_4) == bigint_3) && (n.mod_floor(&bigint_4) == bigint_3) {
                    bigint_r1 * jacobi(n, a)
                } else {
                    jacobi(n, a)
                }
            }
        };
    }

    pub fn pow_mod_bigint(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
        let zero: BigInt = to_bigint_from_int(0);
        let one: BigInt = to_bigint_from_int(1);

        let mut result: BigInt = One::one();
        let mut e: BigInt = exponent.clone();
        let mut b: BigInt = base.clone();

        while e > zero {
            if &e & &one == one {
                result = (result * &b) % (*&modulus);
            }
            e = e >> 1;
            b = (&b * &b) % (*&modulus);
        }
        result
    }

    pub fn pow_bigint(base: &BigInt, exponent: &BigInt) -> BigInt {
        let zero: BigInt = Zero::zero();
        let one: BigInt = One::one();

        let mut result: BigInt = One::one();
        let mut e: BigInt = exponent.clone();
        let mut b: BigInt = base.clone();

        while e > zero {
            if &e & &one == one {
                result = result * &b;
            }
            e = e >> 1;
            b = &b * &b;
        }
        result
    }

    pub fn to_bigint_from_int(a: i64) -> BigInt {
        let output: BigInt = a.to_bigint().unwrap();
        output
    }
    pub fn to_bigint_from_uint(a: u64) -> BigInt {
        let output: BigInt = a.to_bigint().unwrap();
        output
    }

}
