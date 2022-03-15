//!elgamal_utils mod
//! use for supporting elgamal public_key generating
//! generate p: a big prime
//! generate g: a prime root
//! generate h: a random from seed
use mt19937;
use mt19937::MT19937;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::cast::ToPrimitive;
use num_traits::identities::Zero;

/** These real versions are due to Kaisuki, 2021/01/07 added */
/// random generator for bigint
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
fn getrandbits<R: rand_core::RngCore>(rng: &mut R, k: usize) -> BigInt {
    if k == 0 {
        return BigInt::from_slice(Sign::NoSign, &[0]);
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
    let word_array = (0..words)
        .map(|_| {
            let word = gen_u32(k);
            k = k.wrapping_sub(32);
            word
        })
        .collect::<Vec<_>>();

    let uint = BigUint::new(word_array);
    // very unlikely but might as well check
    let sign = if uint.is_zero() {
        Sign::NoSign
    } else {
        Sign::Plus
    };
    BigInt::from_biguint(sign, uint)
}

///Find a prime number p for elgamal public key.
pub fn random_prime_bigint(bit_length: u32, i_confidence: u32, r: &mut mt19937::MT19937) -> BigInt {
    let big_int_0 = BigInt::from(0);
    let big_int_1 = BigInt::from(1);
    let big_int_2 = BigInt::from(2);
    //keep testing until one is found
    loop {
        // generate potential prime randomly
        let mut p = gen_prime(&bit_length, r);
        // make sure it is odd
        while p.mod_floor(&big_int_2) == big_int_0.clone() {
            p = gen_prime(&bit_length, r);
        }
        // keep doing this if the solovay-strassen test fails
        while solovay_strassen(&p, i_confidence, r) != true {
            p = gen_prime(&bit_length, r);
            while p.mod_floor(&big_int_2) == big_int_0 {
                p = gen_prime(&bit_length, r);
            }
        }
        // if p is prime compute p = 2*p + 1
        // this step is critical to protect the encryption from Pohlig–Hellman algorithm
        // if p is prime, we have succeeded; else, start over
        p = p * &big_int_2 + &big_int_1;
        if solovay_strassen(&p, i_confidence, r) == true {
            return p;
        }
    }
}

///generate a prime for bigint
///```
fn gen_prime(bit_length: &u32, r: &mut mt19937::MT19937) -> BigInt {
    let base: BigInt = BigInt::from(2);
    let pow_num_low: u32 = bit_length - 2;
    let pow_num_high: u32 = bit_length - 1;
    let low = base.clone().pow(pow_num_low);
    let high = base.pow(pow_num_high);
    let p: BigInt = gen_bigint_range(r, &low, &high);
    p
}

///Finds a primitive root for prime p.
///
/// This function was implemented from the algorithm described here:
/// http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
pub fn find_primitive_root_bigint(p: &BigInt, r: &mut mt19937::MT19937) -> BigInt {
    let big_int_1 = BigInt::from(1);
    let big_int_2 = BigInt::from(2);
    //if p == 2: return 1
    if p == &big_int_2 {
        return big_int_1;
    }

    // p2 = (p-1)/2
    // p3 = (p-1)/p2
    let p2: BigInt = (p - &big_int_1) / &big_int_2;
    let p3: BigInt = (p - &big_int_1) / &p2;
    let mut g;
    //test random g's until one is found that is a primitive root mod p
    loop {
        let range_num_low: BigInt = big_int_2.clone();
        let range_num_high: BigInt = p - &big_int_1;
        g = gen_bigint_range(r, &range_num_low, &range_num_high);
        // g is a primitive root if for all prime factors of p-1, p[i]
        // g^((p-1)/p[i]) (mod p) is not congruent to 1
        if g.modpow(&p2, &p) != big_int_1.clone() {
            if g.modpow(&p3, &p) != big_int_1 {
                return g;
            }
        }
    }
}

/// generate h for public_key
pub fn find_h_bigint(p: &BigInt, r: &mut mt19937::MT19937) -> BigInt {
    let one: BigInt = BigInt::from(1);
    let range_num_low: BigInt = one.clone();
    let range_num_high: BigInt = p - &one;
    gen_bigint_range(r, &range_num_low, &range_num_high)
}

/// Solovay-strassen primality test.
///     This function tests if num is prime.
///     http://www-math.ucdenver.edu/~wcherowi/courses/m5410/ctcprime.html
/// # Annotation
/// if pass the test
/// ensure confidence of t
pub fn solovay_strassen(num: &BigInt, i_confidence: u32, r: &mut MT19937) -> bool {
    let big_int_1 = BigInt::from(1);
    let big_int_2 = BigInt::from(2);
    for _idx in 0..i_confidence {
        // let one: BigInt = One::one();
        let high: BigInt = num - &big_int_1;
        //choose random a between 1 and n-2
        let a: BigInt = gen_bigint_range(r, &big_int_1, &high);

        // let two: BigInt = &one +&one;
        // if a is not relatively prime to n, n is composite
        if a.gcd(num) > big_int_1.clone() {
            return false;
        }
        //declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        let jacobi_result: BigInt = jacobi(&a, num).mod_floor(num);
        let mi: BigInt = (num - &big_int_1) / &big_int_2;
        let pow_res: BigInt = a.modpow(&mi, num);
        if jacobi_result != pow_res {
            return false;
        }
    }
    //if there have been t iterations without failure, num is believed to be prime
    true
}

/// Computes the jacobi symbol of a, n.
pub fn jacobi(a: &BigInt, n: &BigInt) -> BigInt {
    let big_int_r1 = BigInt::from(-1);
    let big_int_0 = BigInt::from(0);
    let big_int_1 = BigInt::from(1);
    let big_int_2 = BigInt::from(2);
    let big_int_3 = BigInt::from(3);
    let big_int_5 = BigInt::from(5);
    let big_int_7 = BigInt::from(7);
    let big_int_8 = BigInt::from(8);
    if a.to_i64().is_none() {
        jacobi_match_else(a, n)
    } else {
        let a_f64_value = a.to_i64().unwrap();
        match a_f64_value {
            0 => {
                if n == &big_int_1 {
                    big_int_1
                } else {
                    big_int_0
                }
            }
            -1 => {
                if n.mod_floor(&big_int_2) == big_int_0 {
                    big_int_1
                } else {
                    big_int_r1
                }
            }
            1 => big_int_1,
            2 => {
                if (n.mod_floor(&big_int_8) == big_int_1.clone())
                    || (n.mod_floor(&big_int_8) == big_int_7)
                {
                    big_int_1
                } else if (n.mod_floor(&big_int_8) == big_int_3)
                    || (n.mod_floor(&big_int_8) == big_int_5)
                {
                    big_int_r1
                } else {
                    big_int_0
                }
            }
            _ => jacobi_match_else(a, n),
        }
    }
}

/// Computes the jacobi symbol of a, n.If don't match any pattern or a cannot convert to i64
fn jacobi_match_else(a: &BigInt, n: &BigInt) -> BigInt {
    let big_int_0 = BigInt::from(0);
    let big_int_2 = BigInt::from(2);
    let big_int_r1 = BigInt::from(-1);
    let big_int_3 = BigInt::from(3);
    let big_int_4 = BigInt::from(4);
    if a > n {
        let tmp_a = a.mod_floor(n);
        jacobi(&tmp_a, n)
    } else if a.mod_floor(&big_int_2) == big_int_0 {
        let tmp_a2 = a / &big_int_2;
        jacobi(&big_int_2, n) * jacobi(&tmp_a2, n)
    } else if (a.mod_floor(&big_int_4) == big_int_3.clone())
        && (n.mod_floor(&big_int_4) == big_int_3)
    {
        big_int_r1 * jacobi(n, a)
    } else {
        jacobi(n, a)
    }
}
