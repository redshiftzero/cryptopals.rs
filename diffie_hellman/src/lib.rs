#![allow(non_snake_case)]
#![allow(dead_code)]

use block_ciphers::{aes_decrypt_cbc, aes_encrypt_cbc};
use hashes::Sha1;
use num_bigint::{BigUint, RandBigInt};
use primes::pow_mod;
use rand::{CryptoRng, Rng};
use std::convert::TryInto;

const BITLEN: u64 = 1024u64;

#[derive(Debug, Clone, PartialEq)]
struct DHPrivateKey(BigUint);
#[derive(Debug, Clone, PartialEq)]
struct DHPublicKey(BigUint);

/// Local struct that keeps track of the parameters we are using
/// as well as our own DH secret while we wait for a response
/// from Bob.
struct DiffieHellmanPendingRequest {
    p: BigUint,
    g: BigUint,
    private: DHPrivateKey,
    public: DHPublicKey,
}

/// Struct we send over the wire to Bob to let him know what parameters
/// we are using, as well as our DH public key.
struct DiffieHellmanRequest {
    p: BigUint,
    g: BigUint,
    public: DHPublicKey,
}

/// Once we receive a response from Bob with his public key, we both
/// derive DiffieHellmanSharedSecret from our pending request.
#[derive(PartialEq, Debug)]
struct DiffieHellmanSharedSecret {
    s: DHPrivateKey,
}

impl DiffieHellmanPendingRequest {
    pub fn derive_shared_secret(&self, bob_key: DHPublicKey) -> DiffieHellmanSharedSecret {
        let s = pow_mod(&bob_key.0, &self.private.0, &self.p).unwrap();
        DiffieHellmanSharedSecret { s: DHPrivateKey(s) }
    }

    /// These parts we send over the wire.
    pub fn to_send(&self) -> DiffieHellmanRequest {
        DiffieHellmanRequest {
            p: self.p.clone(),
            g: self.g.clone(),
            public: self.public.clone(),
        }
    }
}

#[derive(PartialEq, Debug)]
struct Message {
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
}

impl DiffieHellmanSharedSecret {
    pub fn encrypt_message<R: Rng + CryptoRng>(&self, msg: &[u8], csprng: &mut R) -> Message {
        const block_size: usize = 16;

        let mut m = Sha1::new();
        m.update(&self.s.0.to_bytes_be());

        let key = &m.hexdigest().as_bytes()[0..block_size]
            .try_into()
            .expect("encrypt_message: key wrong length");

        let iv = csprng.gen::<[u8; block_size]>().to_vec();

        // i.e. AES-CBC(SHA1(s)[0:16], iv=random(16), msg)
        let ciphertext = aes_encrypt_cbc(key, &msg, &iv);
        Message { ciphertext, iv }
    }

    pub fn decrypt_message(&self, msg: &Message) -> Vec<u8> {
        const block_size: usize = 16;

        let mut m = Sha1::new();
        m.update(&self.s.0.to_bytes_be());

        let key = &m.hexdigest().as_bytes()[0..block_size]
            .try_into()
            .expect("decrypt_message: key wrong length");

        let plaintext = aes_decrypt_cbc(key, &msg.ciphertext, &msg.iv);
        plaintext
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

        let aliceSession = DiffieHellmanPendingRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };

        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let B = DHPublicKey(pow_mod(&g, &b.0, &p).unwrap());
        let bobSession = DiffieHellmanPendingRequest {
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

        let aliceSession = DiffieHellmanPendingRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };

        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let B = DHPublicKey(pow_mod(&g, &b.0, &p).unwrap());
        let bobSession = DiffieHellmanPendingRequest {
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
    fn set5_challenge34_base_scenario() {
        let mut rng = rand::thread_rng();

        // A->B: She sends p, g, A
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = BigUint::from(2u64);

        let ZERO = BigUint::from(0u64);
        let ONE = BigUint::from(1u64);
        let p_minus_one = p.clone() - ONE.clone();
        let a = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let A = DHPublicKey(pow_mod(&g, &a.0, &p).unwrap());

        let aliceSession = DiffieHellmanPendingRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };
        let alice_to_bob_intro = aliceSession.to_send();

        // B->A: Bob sends B (constructed using p and g given to us by Alice)
        let bob_p = alice_to_bob_intro.p;
        let bob_p_minus_one = bob_p.clone() - ONE;
        let bob_g = alice_to_bob_intro.g;
        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &bob_p_minus_one));
        let B = DHPublicKey(pow_mod(&bob_g, &b.0, &bob_p).unwrap());
        let bobSession = DiffieHellmanPendingRequest {
            public: B.clone(),
            p: p,
            g: g,
            private: b,
        };

        // B and A now both have a shared secret.
        let aliceSharedSecret = aliceSession.derive_shared_secret(B);
        let bobSharedSecret = bobSession.derive_shared_secret(A);
        assert_eq!(aliceSharedSecret, bobSharedSecret);

        // A->B message send
        let expected_plaintext = "huehuehuehuehueh".as_bytes();
        let alice_to_bob_message = aliceSharedSecret.encrypt_message(&expected_plaintext, &mut rng);

        // B->A message receive
        let plaintext = bobSharedSecret.decrypt_message(&alice_to_bob_message);
        assert_eq!(plaintext, expected_plaintext);
    }

    #[test]
    fn set5_challenge34_mitm_scenario() {
        // MITM key-fixing attack on DH with parameter injection
        let mut rng = rand::thread_rng();

        // A->M: She sends p, g, A
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = BigUint::from(2u64);

        let ZERO = BigUint::from(0u64);
        let ONE = BigUint::from(1u64);
        let p_minus_one = p.clone() - ONE.clone();
        let a = DHPrivateKey(rng.gen_biguint_range(&ZERO, &p_minus_one));
        let A = DHPublicKey(pow_mod(&g, &a.0, &p).unwrap());

        let aliceSession = DiffieHellmanPendingRequest {
            public: A.clone(),
            p: p.clone(),
            g: g.clone(),
            private: a,
        };
        let alice_to_mitm_intro = aliceSession.to_send();

        // ATTACKER: gets alice_to_mitm_intro
        // M->B: send "p", "g", "p"
        let mitm_to_bob_into = DiffieHellmanRequest {
            p: alice_to_mitm_intro.p.clone(),
            g: alice_to_mitm_intro.g.clone(),
            public: DHPublicKey(alice_to_mitm_intro.p.clone()),
        };

        // B->M: Bob sends B (constructed using p and g given to us by the attacker)
        let bob_p = mitm_to_bob_into.p;
        let bob_p_minus_one = bob_p.clone() - ONE;
        let bob_g = mitm_to_bob_into.g;
        let b = DHPrivateKey(rng.gen_biguint_range(&ZERO, &bob_p_minus_one));
        let B = DHPublicKey(pow_mod(&bob_g, &b.0, &bob_p).unwrap());
        let bobSession = DiffieHellmanPendingRequest {
            public: B.clone(),
            p: p,
            g: g,
            private: b,
        };

        // ATTACKER: Now has access to B. Sends p instead to Alice.
        // M->A: Send "p"
        let alice_B = DHPublicKey(bob_p.clone());

        // What does swapping A and B out with p do to the protocol?
        // From Alice's perspective: She has constructed $A = g^a \mod p$
        // She derives for her shared secret K $K = (B)^a \mod p$
        // Substituting in $B = p$ gives: $K = p^a \mod p = 0^a \mod p = 0 \mod p$
        // The same is derived by Bob. The attacker can also derive this.
        let aliceSharedSecret = aliceSession.derive_shared_secret(alice_B);
        let bobSharedSecret = bobSession.derive_shared_secret(mitm_to_bob_into.public);
        assert_eq!(aliceSharedSecret, bobSharedSecret);
        let attackerSharedSecret = DiffieHellmanSharedSecret {
            s: DHPrivateKey(ZERO),
        };
        assert_eq!(aliceSharedSecret, attackerSharedSecret);
        assert_eq!(bobSharedSecret, attackerSharedSecret);

        // A->M->B message send
        let expected_plaintext = "huehuehuehuehueh".as_bytes();
        let alice_to_bob_message = aliceSharedSecret.encrypt_message(&expected_plaintext, &mut rng);

        // Attacker can decrypt messages as they go by:
        let attacker_p = attackerSharedSecret.decrypt_message(&alice_to_bob_message);
        assert_eq!(attacker_p, expected_plaintext);

        // B->M->A message receive
        let plaintext = bobSharedSecret.decrypt_message(&alice_to_bob_message);
        assert_eq!(plaintext, expected_plaintext);
    }
}
