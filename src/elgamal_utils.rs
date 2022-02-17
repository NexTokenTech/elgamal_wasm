//!elgamal_utils mod
//! use for supporting elgamal public_key generating
//! generate p: a big prime
//! generate g: a prime root
//! generate h: a random from seed
use mt19937;
use mt19937::MT19937;

use const_num_bigint::*;
use num::traits::{One, Zero};
use num::{Integer, ToPrimitive};

/// const for 0,1 ..
const BIGINT_0: &'static BigInt = bigint!("0");
const BIGINT_1: &'static BigInt = bigint!("1");
const BIGINT_2: &'static BigInt = bigint!("2");
const BIGINT_R1: &'static BigInt = bigint!("-1");
const BIGINT_3: &'static BigInt = bigint!("3");
const BIGINT_4: &'static BigInt = bigint!("4");
const BIGINT_5: &'static BigInt = bigint!("5");
const BIGINT_7: &'static BigInt = bigint!("7");
const BIGINT_8: &'static BigInt = bigint!("8");

/** These real versions are due to Kaisuki, 2021/01/07 added */
/// random generator for bigint
/// # Example
/// ```rust
/// use elgamal_wasm::elgamal_utils;
/// g = elgamal_utils::gen_bigint_range(r, &range_num_low, &range_num_high);
/// ```
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

/// Return an integer with k random bits with mt19937 random rng.
/// # Example
/// ```rust
/// use const_num_bigint::*;
/// let width: BigInt = stop + 1 - start;///
/// let k: u64 = width.bits(); // don't use (n-1) here because n can be 1///
/// let mut r: BigInt = getrandbits(rng, k as usize);
/// ```
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
/// # Example
/// ```rust
/// let key = seed.to_u32_digits();
/// let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
/// let val = elgamal_utils::random_prime_bigint(bit_length, i_confidence, &mut rng);
///```
#[allow(unused)]
pub fn random_prime_bigint(bit_length: u32, i_confidence: u32, r: &mut mt19937::MT19937) -> BigInt {
    //keep testing until one is found
    loop {
        // generate potential prime randomly
        let mut p = gen_prime(&bit_length, r);
        // make sure it is odd
        while p.mod_floor(&BIGINT_2) == *BIGINT_0 {
            p = gen_prime(&bit_length, r);
        }
        // keep doing this if the solovay-strassen test fails
        while solovay_strassen(&p, i_confidence, r) != true {
            p = gen_prime(&bit_length, r);
            while p.mod_floor(&BIGINT_2) == *BIGINT_0 {
                p = gen_prime(&bit_length, r);
            }
        }
        // if p is prime compute p = 2*p + 1
        // this step is critical to protect the encryption from Pohlig–Hellman algorithm
        // if p is prime, we have succeeded; else, start over
        p = p * BIGINT_2 + BIGINT_1;
        if solovay_strassen(&p, i_confidence, r) == true {
            return p;
        }
    }
}


///generate a prime for bigint
/// # Example
/// ```rust
/// let key = seed.to_u32_digits();
/// let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
/// let p = gen_prime(&bit_length, rng);
///```
fn gen_prime(bit_length: &u32, r: &mut mt19937::MT19937) -> BigInt {
    let base: BigInt = BigInt::from(2);
    let pow_num_low: BigInt = BigInt::from(bit_length - 2);
    let pow_num_high: BigInt = BigInt::from(bit_length - 1);
    let low = pow_bigint(&base, &pow_num_low);
    let high = pow_bigint(&base, &pow_num_high);
    let p: BigInt = gen_bigint_range(r, &low, &high);
    p
}

///Finds a primitive root for prime p.
///
/// This function was implemented from the algorithm described here:
/// http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
/// # Example
/// ```rust
/// let key = seed.to_u32_digits();
/// let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
/// let g = elgamal_utils::find_primitive_root_bigint(&val, &mut rng);
/// ```
pub fn find_primitive_root_bigint(p: &BigInt, r: &mut mt19937::MT19937) -> BigInt {
    //if p == 2: return 1
    if *p == *BIGINT_2 {
        return BIGINT_1.clone();
    }

    // p2 = (p-1)/2
    // p3 = (p-1)/p2
    let p2: BigInt = (p - BIGINT_1) / BIGINT_2;
    let p3: BigInt = (p - BIGINT_1) / &p2;
    let mut g;
    //test random g's until one is found that is a primitive root mod p
    loop {
        let range_num_low: BigInt = BIGINT_2.clone();
        let range_num_high: BigInt = p - BIGINT_1;
        g = gen_bigint_range(r, &range_num_low, &range_num_high);
        // g is a primitive root if for all prime factors of p-1, p[i]
        // g^((p-1)/p[i]) (mod p) is not congruent to 1
        if g.modpow(&p2, &p) != *BIGINT_1 {
            if g.modpow(&p3, &p) != *BIGINT_1 {
                return g;
            }
        }
    }
}

/// generate h for public_key
/// # Example
/// ```rust
/// let key = seed.to_u32_digits();
/// let mut rng: mt19937::MT19937 = mt19937::MT19937::new_with_slice_seed(&key.1);
/// let h = elgamal_utils::find_h_bigint(&val, &mut rng);
/// ```
pub fn find_h_bigint(p: &BigInt, r: &mut mt19937::MT19937) -> BigInt {
    let one: BigInt = One::one();
    let range_num_low: BigInt = One::one();
    let range_num_high: BigInt = p - &one;
    let h = gen_bigint_range(r, &range_num_low, &range_num_high);
    h
}

/// Solovay-strassen primality test.
///     This function tests if num is prime.
///     http://www-math.ucdenver.edu/~wcherowi/courses/m5410/ctcprime.html
/// # Example
/// ```rust
/// use elgamal_wasm::elgamal;
/// elgamal::solovay_strassen(&p, i_confidence, r);
/// ```
/// # Annotation
/// if pass the test
/// ensure confidence of t
pub fn solovay_strassen(num: &BigInt, i_confidence: u32, r: &mut MT19937) -> bool {
    for _idx in 0..i_confidence {
        // let one: BigInt = One::one();
        let high: BigInt = num - BIGINT_1;
        //choose random a between 1 and n-2
        let a: BigInt = gen_bigint_range(r, &BIGINT_1, &high);

        // let two: BigInt = &one +&one;
        // if a is not relatively prime to n, n is composite
        if a.gcd(num) > *BIGINT_1 {
            return false;
        }
        //declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        let jacobi_result: BigInt = jacobi(&a, num).mod_floor(num);
        let mi: BigInt = (num - BIGINT_1) / BIGINT_2;
        let pow_reulst: BigInt = a.modpow(&mi, num);
        if jacobi_result != pow_reulst {
            return false;
        }
    }
    //if there have been t iterations without failure, num is believed to be prime
    return true;
}

/// Computes the jacobi symbol of a, n.
/// # Example
/// ```rust
/// use elgamal_wasm::elgamal;
/// elgamal::jacobi(&a, num);
/// ```
pub fn jacobi(a: &BigInt, n: &BigInt) -> BigInt {
    if a.to_i64().is_none() {
        jacobi_match_else(a, n)
    } else {
        let a_f64_value = a.to_i64().unwrap();
        return match a_f64_value {
            0 => {
                if n == BIGINT_1 {
                    BIGINT_1.clone()
                } else {
                    BIGINT_0.clone()
                }
            }
            -1 => {
                if n.mod_floor(&BIGINT_2) == *BIGINT_0 {
                    BIGINT_1.clone()
                } else {
                    BIGINT_R1.clone()
                }
            }
            1 => BIGINT_1.clone(),
            2 => {
                if (n.mod_floor(&BIGINT_8) == *BIGINT_1) || (n.mod_floor(&BIGINT_8) == *BIGINT_7) {
                    BIGINT_1.clone()
                } else if (n.mod_floor(&BIGINT_8) == *BIGINT_3)
                    || (n.mod_floor(&BIGINT_8) == *BIGINT_5)
                {
                    BIGINT_R1.clone()
                } else {
                    BIGINT_0.clone()
                }
            }
            _ => jacobi_match_else(a, n),
        };
    }
}

/// Computes the jacobi symbol of a, n.If don't match any pattern or a cannot convert to i64
fn jacobi_match_else(a: &BigInt, n: &BigInt) -> BigInt {
    if a > n {
        let tmp_a = a.mod_floor(n);
        jacobi(&tmp_a, n)
    } else if a.mod_floor(&BIGINT_2) == *BIGINT_0 {
        let tmp_a2 = a / BIGINT_2;
        jacobi(&BIGINT_2, n) * jacobi(&tmp_a2, n)
    } else if (a.mod_floor(&BIGINT_4) == *BIGINT_3) && (n.mod_floor(&BIGINT_4) == *BIGINT_3) {
        BIGINT_R1 * jacobi(n, a)
    } else {
        jacobi(n, a)
    }
}

/// pow operation for bigint
/// # Example
/// ```rust
/// use elgamal_wasm::elgamal_utils;
/// let low = elgamal_utils::pow_bigint(&base, &pow_num_low);
///```
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
