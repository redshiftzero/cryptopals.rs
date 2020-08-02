#[macro_use]
extern crate lazy_static;
extern crate hex;

use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use primes::pow_mod;

const ZERO_U64: u64 = 0;
const ONE_U64: u64 = 1;

// Public exponent is hardcoded in Challenge 39.
lazy_static! {
    static ref PUBLIC_EXPONENT: BigUint =
        3.clone().to_biguint().expect("cannot convert to biguint!");
    static ref ZERO: BigInt = BigInt::from(ZERO_U64);
    static ref ONE: BigInt = BigInt::from(ONE_U64);
}

#[derive(Debug)]
pub struct RSAPrivateKey {
    n: BigUint,
    p: BigUint,
    q: BigUint,
    e: BigUint,
    d: BigUint,
}

#[derive(Debug)]
pub struct RSAPublicKey {
    n: BigUint,
    e: BigUint,
}

pub trait Encrypt {
    fn encrypt(&self, m: &BigUint) -> BigUint;
    fn encrypt_str(&self, m: &String) -> BigUint;
}

pub trait Decrypt {
    fn decrypt(&self, c: &BigUint) -> BigUint;
    fn decrypt_str(&self, c: &BigUint) -> String;
}

// Adapted the invmod/egcd algo from the Python version in https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a == *ZERO {
        return (b, ZERO.clone(), ONE.clone());
    } else {
        let (g, y, x) = egcd(b.clone() % a.clone(), a.clone());
        let mut modified_x = x.clone();
        modified_x -= (b / a) * y.clone();

        return (g, modified_x, y);
    }
}

fn invmod(a: BigUint, m: BigUint) -> Result<BigUint, &'static str> {
    let (g, mut x, y) = egcd(
        a.to_bigint().expect("cant convert to bigint!"),
        m.clone().to_bigint().expect("cant convert to bigint!"),
    );
    if g != *ONE {
        return Err("modular inverse does not exist");
    } else {
        if x < *ZERO {
            x += m.clone().to_bigint().expect("cant convert to bigint");
        }
        let result = x.to_biguint().expect("cant convert to biguint!") % m;
        return Ok(result.to_biguint().expect("cant convert to biguint!"));
    }
}

impl RSAPrivateKey {
    fn new() -> RSAPrivateKey {
        // We loop until we get a pair of (p-1), (n-1) for which the
        // modular inverse exists.
        loop {
            let p = primes::generate_prime().expect("failed to find a prime!");
            let q = primes::generate_prime().expect("failed to find a prime!");

            let one_uint: BigUint = BigUint::from(ONE_U64);

            let p_minus_one = p.clone() - one_uint.clone();
            let q_minus_one = q.clone() - one_uint.clone();
            let n = p.clone() * q.clone();
            let totient = p_minus_one * q_minus_one % n.clone();

            let d = invmod(PUBLIC_EXPONENT.clone(), totient);

            match d {
                Ok(d) => {
                    return RSAPrivateKey {
                        n,
                        p,
                        q,
                        e: PUBLIC_EXPONENT.clone(),
                        d,
                    }
                }
                Err(d) => (),
            }
        }
    }

    fn to_pubkey(&self) -> RSAPublicKey {
        RSAPublicKey {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}

impl Encrypt for RSAPublicKey {
    fn encrypt(&self, m: &BigUint) -> BigUint {
        return pow_mod(m, &self.e, &self.n).expect("could not perform modular exponentiation");
    }

    /// Helper method to convert string to int and _then_ encrypt.
    fn encrypt_str(&self, m: &String) -> BigUint {
        let hex_str = String::from("0x") + &hex::encode(m)[..];
        let plaintext_int: u64 = hex::encode(m)[..].parse().unwrap();
        let plaintext: BigUint = plaintext_int
            .to_biguint()
            .expect("could not create biguint");
        return self.encrypt(&plaintext);
    }
}

impl Decrypt for RSAPrivateKey {
    fn decrypt(&self, c: &BigUint) -> BigUint {
        return pow_mod(c, &self.d, &self.n).expect("could not perform modular exponentiation");
    }

    fn decrypt_str(&self, c: &BigUint) -> String {
        let plaintext_bigint = self.decrypt(&c);

        // TODO: Do this more directly (going u32 -> hex str -> u8 -> str ... oyy).
        let plaintext_u32 = plaintext_bigint.to_u32_digits();

        // Now trim off the [ ] brackets around the value.
        let plaintext_hex = &format!("{:?}", plaintext_u32);
        let plaintext_sans_first = &plaintext_hex.trim_start_matches('[').to_string();
        let plaintext_sans_first_last = &plaintext_sans_first.trim_end_matches(']').to_string();

        let plaintext_u8 = hex::decode(&plaintext_sans_first_last).unwrap();
        let plaintext = std::str::from_utf8(&plaintext_u8).unwrap().to_string();

        return plaintext;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation() {
        let privkey = RSAPrivateKey::new();
        let pubkey = privkey.to_pubkey();
    }

    #[test]
    fn key_encrypt_and_decrypt_consistency() {
        let message = 42.to_biguint().expect("could not convert to biguint");
        let privkey = RSAPrivateKey::new();
        let pubkey = privkey.to_pubkey();

        let ciphertext = pubkey.encrypt(&message);
        let plaintext = privkey.decrypt(&ciphertext);

        assert_eq!(message, plaintext);
    }

    #[test]
    fn key_encrypt_and_decrypt_consistency_string() {
        let message_str = String::from("test");
        let privkey = RSAPrivateKey::new();
        let pubkey = privkey.to_pubkey();

        let ciphertext = pubkey.encrypt_str(&message_str);
        let plaintext = privkey.decrypt_str(&ciphertext);

        assert_eq!(message_str, plaintext);
    }

    #[test]
    fn test_invmod_medium_sized_int() {
        let arg1_u64: u64 = 17;
        let arg1_num = BigUint::from(arg1_u64);
        let arg2_u64: u64 = 3120;
        let arg2_num = BigUint::from(arg2_u64);

        let result_u64: u64 = 2753;
        let result_num = BigUint::from(result_u64);
        assert_eq!(
            invmod(arg1_num, arg2_num).expect("no modular inverse"),
            result_num
        );
    }

    #[test]
    fn test_invmod_small_int() {
        let arg1_u64: u64 = 3;
        let arg1_num = BigUint::from(arg1_u64);
        let arg2_u64: u64 = 11;
        let arg2_num = BigUint::from(arg2_u64);

        let result_u64: u64 = 4;
        let result_num = BigUint::from(result_u64);
        assert_eq!(
            invmod(arg1_num, arg2_num).expect("no modular inverse"),
            result_num
        );
    }

    #[test]
    fn test_invmod_example() {
        let arg1_u64: u64 = 3;
        let arg1_num = BigUint::from(arg1_u64);
        let arg2_u64: u64 = 11 * 13;
        let arg2_num = BigUint::from(arg2_u64);

        let result_u64: u64 = 48;
        let result_num = BigUint::from(result_u64);
        assert_eq!(
            invmod(arg1_num, arg2_num).expect("no modular inverse"),
            result_num
        );
    }
}
