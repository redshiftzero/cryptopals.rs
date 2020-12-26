use num_bigint::{BigUint, RandBigInt};
use primes::pow_mod;

const BITLEN: u64 = 64u64;

#[derive(Debug, Clone, PartialEq)]
struct DHPrivateKey(BigUint);
#[derive(Debug, Clone, PartialEq)]
struct DHPublicKey(BigUint);

struct DiffieHellmanRequest {
    p: BigUint,
    g: BigUint,
    private: DHPrivateKey,
    public: DHPublicKey,
}

#[derive(PartialEq, Debug)]
struct DiffieHellmanSharedSecret {
    s: DHPrivateKey,
}

impl DiffieHellmanRequest {
    pub fn derive_shared_secret(&self, bob_key: DHPublicKey) -> DiffieHellmanSharedSecret {
        let s = pow_mod(&bob_key.0, &self.private.0, &self.p).unwrap();
        DiffieHellmanSharedSecret { s: DHPrivateKey(s) }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn set5_challenge33_wee() {
        let mut rng = rand::thread_rng();
        let p = BigUint::from(37u64);
        let g = BigUint::from(5u64);

        let ZERO = BigUint::from(0u64);
        let ONE = BigUint::from(1u64);
        let p_minus_one = p.clone() - ONE;
        // a must be a random number mod 37
        let a = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let A = DHPublicKey(pow_mod(&g, &a.0, &p).unwrap());

        let aliceSession = DiffieHellmanRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };

        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let B = DHPublicKey(pow_mod(&g, &b.0, &p).unwrap());
        let bobSession = DiffieHellmanRequest {
            public: B.clone(),
            p: p,
            g: g,
            private: b,
        };

        let aliceSharedSecret = aliceSession.derive_shared_secret(B);
        let bobSharedSecret = bobSession.derive_shared_secret(A);
        assert_eq!(aliceSharedSecret, bobSharedSecret);
    }

    #[test]
    fn set5_challenge33_bigint() {
        let mut rng = rand::thread_rng();
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = BigUint::from(2u64);

        let ZERO = BigUint::from(0u64);
        let ONE = BigUint::from(1u64);
        let p_minus_one = p.clone() - ONE;
        let a = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let A = DHPublicKey(pow_mod(&g, &a.0, &p).unwrap());

        let aliceSession = DiffieHellmanRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };

        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let B = DHPublicKey(pow_mod(&g, &b.0, &p).unwrap());
        let bobSession = DiffieHellmanRequest {
            public: B.clone(),
            p: p,
            g: g,
            private: b,
        };

        let aliceSharedSecret = aliceSession.derive_shared_secret(B);
        let bobSharedSecret = bobSession.derive_shared_secret(A);
        assert_eq!(aliceSharedSecret, bobSharedSecret);
    }
}
