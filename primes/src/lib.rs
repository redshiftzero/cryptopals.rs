#[macro_use]
extern crate lazy_static;

use num_bigint::{BigUint, RandBigInt};

// Setting this very small because we're just using for testing.
pub const BITLEN: u64 = 128;
pub const NUM_TRIALS: u8 = 6;

// Hardcoding the integers 0-3 as constants as we use them
// a lot below.
const ZERO_U64: u64 = 0;
const ONE_U64: u64 = 1;
const TWO_U64: u64 = 2;
const THREE_U64: u64 = 3;

// This is implemented as a struct type implementing
// Deref, i.e. we will need to deref it when we use
// these bigint constants.
lazy_static! {
    static ref ZERO: BigUint = BigUint::from(ZERO_U64);
    static ref ONE: BigUint = BigUint::from(ONE_U64);
    static ref TWO: BigUint = BigUint::from(TWO_U64);
    static ref THREE: BigUint = BigUint::from(THREE_U64);
}

/// Modular exponentiation using biguints.
pub fn pow_mod(
    base: &BigUint,
    exponent: &BigUint,
    modulus: &BigUint,
) -> Result<BigUint, &'static str> {
    let mut result = ONE.clone();
    let mut exponent = exponent.clone();
    let mut base = base % modulus;

    while exponent > *ZERO {
        if &exponent % &*TWO == *ONE {
            result = (result * &base) % modulus;
        }
        exponent >>= 1;
        base = (&base * &base) % modulus;
    }
    Ok(result)
}

/// Determine if a number is prime using the probabalistic
/// Miller-Rabin primality test.
///
/// # Arguments
///
/// * `n` - The number to test.
/// * `k` - The number of trials. Confidence increases with k.
pub fn is_prime(n: BigUint, mut k: u8) -> bool {
    if n.clone() == ONE.clone() {
        return false;
    } else if n.clone() == THREE.clone() {
        return true;
    }

    // Even numbers immediately return false.
    if n.clone() % TWO_U64 == *ZERO {
        return false;
    }

    // Try different r until we get a d that satisfies 2 * r * d = n - 1.
    // Find d such that 2r * d = n - 1
    // n is odd. n-1 is even. r must be >0.
    let mut r: u64 = 1;
    let n_minus_one = n.clone() - ONE.clone();
    let mut two_times_r_u64 = 2 * r;
    let mut two_times_r = BigUint::from(two_times_r_u64);
    let mut d = n_minus_one.clone() / two_times_r.clone();

    while d.clone() * two_times_r.clone() != n_minus_one {
        r += 1;
        two_times_r_u64 = 2 * r;
        two_times_r = BigUint::from(two_times_r_u64);
        d = n_minus_one.clone() / two_times_r.clone();
    }

    // Do Miller-Rabin trials k times and return early if any fail.
    while k > 0 {
        if !miller_rabin_trial(n.clone(), d.clone()) {
            return false;
        } else {
            k -= 1;
        }
    }

    // If we get here, all trials passed, and we return True.
    true
}

fn miller_rabin_trial(n: BigUint, mut d: BigUint) -> bool {
    let mut rng = rand::thread_rng();

    let n_minus_two = n.clone() - TWO.clone();
    let n_minus_one = n.clone() - ONE.clone();

    if *TWO > n_minus_two {
        panic!("boom");
    }
    let a = rng.gen_biguint_range(&TWO, &n_minus_two);

    // Calculate x = a^d mod n.
    let mut x = pow_mod(&a, &d, &n).unwrap();

    // Return early if x is 1 or n-1.
    if x.clone() == *ONE {
        return true;
    } else if x.clone() == n_minus_one {
        return true;
    }

    while d != n_minus_one {
        x = x.clone() * x.clone() % n.clone();
        d = TWO_U64 * d.clone();
        if x == *ONE {
            return false;
        } else if x == n_minus_one {
            return true;
        }
    }

    false
}

/// Generate a large prime number.
pub fn generate_prime() -> Result<BigUint, ()> {
    let mut rng = rand::thread_rng();

    let mut n = rng.gen_biguint(BITLEN);

    if n.clone() % TWO_U64 == *ZERO {
        n += &*ONE;
    }

    loop {
        if is_prime(n.clone(), NUM_TRIALS) {
            break;
        } else {
            n += &*TWO;
        }
    }

    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_prime_results_small_primes() {
        let test_u64: u64 = 3;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), true);

        let test_u64: u64 = 5;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), true);

        let test_u64: u64 = 97;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), true);

        let test_u64: u64 = 99;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), false);
    }

    #[test]
    fn is_prime_results_base_cases() {
        let test_u64: u64 = 0;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), false);

        let test_u64: u64 = 1;
        let test_num = BigUint::from(test_u64);
        assert_eq!(is_prime(test_num, 2), false);
    }
}
