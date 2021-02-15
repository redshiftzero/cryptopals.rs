#![allow(non_snake_case)]
#![allow(dead_code)]

use hmac::{hmac_sha256, verify_hmac_sha256};
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use primes::pow_mod;
use rand::{CryptoRng,Rng};
use sha2::{Digest, Sha256};
use utils::bytes_to_hex;

#[derive(Debug, Clone, PartialEq)]
struct PrivateKey(BigUint);
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(pub BigUint);

/// Step 0
/// Client & Server:
/// Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub N: BigUint,
    pub g: BigUint,
    pub k: u32,
    pub I: Vec<u8>,
    pub P: Vec<u8>,
}

/// Step 1
/// Server:
/// Generate salt as random integer
/// Generate string xH=SHA256(salt|password)
/// Convert xH to integer x somehow (put 0x on hexdigest)
/// Generate v=g**x % N
/// Save everything but x, xH
#[derive(Clone)]
pub struct ServerProtocolSetup {
    salt: u64,
    v: BigUint,
}

impl ServerProtocolSetup {
    pub fn new<R: Rng + CryptoRng>(csprng: &mut R, params: &Parameters) -> Self {
        let salt: u64 = csprng.gen();

        let mut m = Sha256::new();
        let mut xH_input = Vec::new();
        xH_input.extend_from_slice(&salt.to_be_bytes());
        xH_input.extend_from_slice(&params.P);
        m.update(&xH_input);
        let xH = m.finalize();
        let xH_hexstr = bytes_to_hex(xH.to_vec());
        let x = BigUint::parse_bytes(xH_hexstr.as_bytes(), 16)
            .expect("could not convert from hex str to big uint");
        let v = pow_mod(&params.g, &x, &params.N).expect("could not compute pow_mod");

        ServerProtocolSetup { salt, v }
    }
}

/// Step 2
/// Client->Server
/// Send I, A=g**a % N (a la Diffie Hellman)
pub struct ClientLoginAttemptPendingResponse {
    pub I: Vec<u8>,
    pub A: PublicKey,
    a: PrivateKey,
}

#[derive(Clone)]
pub struct ClientLoginAttemptRequest {
    pub I: Vec<u8>,
    pub A: PublicKey,
}

impl ClientLoginAttemptPendingResponse {
    pub fn new<R: Rng + CryptoRng>(csprng: &mut R, params: &Parameters) -> Self {
        let ZERO = BigUint::from(0u64);
        // TODO: UNSURE IF THE UPPER RANGE HERE IS CORRECT
        let a = csprng.gen_biguint_range(&ZERO, &params.N);
        let A = pow_mod(&params.g, &a, &params.N).expect("could not compute pow_mod");

        ClientLoginAttemptPendingResponse {
            I: params.I.clone(),
            A: PublicKey(A),
            a: PrivateKey(a),
        }
    }

    pub fn to_server(&self) -> ClientLoginAttemptRequest {
        ClientLoginAttemptRequest {
            I: self.I.clone(),
            A: self.A.clone(),
        }
    }
}

/// Step 3
/// S->C
/// Send salt, B=kv + g**b % N
#[derive(Clone)]
pub struct ServerLoginAttemptSession {
    salt: u64,
    pub B: PublicKey,
    b: PrivateKey,
}

#[derive(Clone)]
pub struct ServerLoginAttemptResponse {
    salt: u64,
    pub B: PublicKey,
}

impl ServerLoginAttemptSession {
    pub fn new<R: Rng + CryptoRng>(
        csprng: &mut R,
        params: &Parameters,
        setup: &ServerProtocolSetup,
    ) -> Self {
        let ZERO = BigUint::from(0u64);
        // TODO: ALSO UNSURE IF THE UPPER RANGE HERE IS CORRECT
        let b = csprng.gen_biguint_range(&ZERO, &params.N);

        let B = params.k.clone() * setup.v.clone()
            + pow_mod(&params.g, &b, &params.N).expect("could not compute pow_mod");

        ServerLoginAttemptSession {
            salt: setup.salt.clone(),
            B: PublicKey(B),
            b: PrivateKey(b),
        }
    }

    pub fn to_client(&self) -> ServerLoginAttemptResponse {
        ServerLoginAttemptResponse {
            salt: self.salt.clone(),
            B: self.B.clone(),
        }
    }
}

/// Step 4
/// S, C
/// Compute string uH = SHA256(A|B), u = integer of uH
#[derive(Clone)]
pub struct SharedValue {
    u: BigUint,
}

impl SharedValue {
    pub fn new(A: &PublicKey, B: &PublicKey) -> Self {
        let mut m = Sha256::new();
        let mut uH_input = Vec::new();
        uH_input.extend_from_slice(&A.0.to_bytes_be());
        uH_input.extend_from_slice(&B.0.to_bytes_be());
        m.update(&uH_input);
        let uH = m.finalize();
        let uH_hexstr = bytes_to_hex(uH.to_vec());
        let u = BigUint::parse_bytes(uH_hexstr.as_bytes(), 16)
            .expect("could not convert from hex str to big uint");

        SharedValue { u }
    }
}

/// Step 5
/// C
/// Generate string xH=SHA256(salt|password)
/// Convert xH to integer x somehow (put 0x on hexdigest)
/// Generate S = (B - k * g**x)**(a + u * x) % N
/// Generate K = SHA256(S)
pub struct ClientKey {
    pub K: Vec<u8>,
}

impl ClientKey {
    pub fn new(
        params: &Parameters,
        server_resp: &ServerLoginAttemptResponse,
        client_req: &ClientLoginAttemptPendingResponse,
        shared_val: &SharedValue,
    ) -> Self {
        let mut m = Sha256::new();
        let mut xH_input = Vec::new();
        xH_input.extend_from_slice(&server_resp.salt.to_be_bytes());
        xH_input.extend_from_slice(&params.P);
        m.update(&xH_input);
        let xH = m.finalize();
        let xH_hexstr = bytes_to_hex(xH.to_vec());
        let x = BigUint::parse_bytes(xH_hexstr.as_bytes(), 16)
            .expect("could not convert from hex str to big uint");

        // (B - k * g**x)
        let ONE = BigUint::from(1u64);
        let S_base = server_resp.B.0.clone()
            - pow_mod(
                &params.k.to_biguint().expect("could not convert to biguint"),
                &ONE,
                &params.N,
            )
            .expect("could not compute pow_mod")
                * pow_mod(&params.g, &x, &params.N).expect("could not compute pow_mod");

        // (a + u * x)
        let S_exp = client_req.a.0.clone() + shared_val.u.clone() * x;
        let S = pow_mod(&S_base, &S_exp, &params.N).expect("could not compute pow_mod");

        let mut m = Sha256::new();
        m.update(&S.to_bytes_be());
        let K = m.finalize();

        ClientKey { K: K.to_vec() }
    }
}

/// Step 6
/// S
/// Generate S = (A * v**u) ** b % N
/// Generate K = SHA256(S)
#[derive(Clone)]
pub struct ServerKey {
    K: Vec<u8>,
}

impl ServerKey {
    pub fn new(
        params: &Parameters,
        server_resp: &ServerLoginAttemptSession,
        client_req: &ClientLoginAttemptRequest,
        shared_val: &SharedValue,
        server_setup: &ServerProtocolSetup,
    ) -> Self {
        // (A * v**u)
        let S_base = client_req.A.0.clone()
            * pow_mod(&server_setup.v, &shared_val.u, &params.N)
                .expect("could not compute pow_mod");

        let S = pow_mod(&S_base, &server_resp.b.0, &params.N).expect("could not compute pow_mod");

        let mut m = Sha256::new();
        m.update(&S.to_bytes_be());
        let K = m.finalize();

        ServerKey { K: K.to_vec() }
    }
}

/// Step 7
/// C->S
/// Send HMAC-SHA256(K, salt)
impl ClientKey {
    pub fn gen_mac(&self, server_resp: &ServerLoginAttemptResponse) -> Vec<u8> {
        hmac_sha256(&self.K, &server_resp.salt.to_be_bytes())
    }
}

/// Step 8
/// S->C
/// Send "OK" if HMAC-SHA256(K, salt) validates
impl ServerKey {
    pub fn verify_mac(&self, setup: &ServerProtocolSetup, mac: &Vec<u8>) -> bool {
        verify_hmac_sha256(&self.K, &setup.salt.to_be_bytes(), mac)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn set5_challenge36_successful() {
        let mut rng = rand::thread_rng();

        let parameters = Parameters {
            N: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
            g: 2u32.to_biguint().expect("cant convert to biguint!"),
            k: 3u32,
            I: "jen@dontemailme.com".as_bytes().to_vec(),
            P: "hunter2".as_bytes().to_vec(),
        };

        let server_step1 = ServerProtocolSetup::new(&mut rng, &parameters);
        let client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
        let server_step2 = client_step2.to_server();
        let server_step3 = ServerLoginAttemptSession::new(&mut rng, &parameters, &server_step1);
        let client_step3 = server_step3.to_client();
        let server_step4 = SharedValue::new(&server_step2.A, &server_step3.B);
        let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
        let step5 = ClientKey::new(&parameters, &client_step3, &client_step2, &client_step4);
        let step6 = ServerKey::new(
            &parameters,
            &server_step3,
            &server_step2,
            &server_step4,
            &server_step1,
        );
        let mac = step5.gen_mac(&client_step3);
        let mac_validation = step6.verify_mac(&server_step1, &mac);

        assert_eq!(mac_validation, true);
    }

    #[test]
    fn set5_challenge36_not_successful() {
        let mut rng = rand::thread_rng();

        let server_parameters = Parameters {
            N: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
            g: 2u32.to_biguint().expect("cant convert to biguint!"),
            k: 3u32,
            I: "jen@dontemailme.com".as_bytes().to_vec(),
            P: "hunter2".as_bytes().to_vec(),
        };

        let client_parameters = Parameters {
            N: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
            g: 2u32.to_biguint().expect("cant convert to biguint!"),
            k: 3u32,
            I: "jen@dontemailme.com".as_bytes().to_vec(),
            P: "but muh password is wrong!".as_bytes().to_vec(),
        };

        let server_step1 = ServerProtocolSetup::new(&mut rng, &server_parameters);
        let client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &client_parameters);
        let server_step2 = client_step2.to_server();
        let server_step3 =
            ServerLoginAttemptSession::new(&mut rng, &server_parameters, &server_step1);
        let client_step3 = server_step3.to_client();
        let server_step4 = SharedValue::new(&server_step2.A, &server_step3.B);
        let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
        let step5 = ClientKey::new(
            &client_parameters,
            &client_step3,
            &client_step2,
            &client_step4,
        );
        let step6 = ServerKey::new(
            &server_parameters,
            &server_step3,
            &server_step2,
            &server_step4,
            &server_step1,
        );
        let mac = step5.gen_mac(&client_step3);
        let mac_validation = step6.verify_mac(&server_step1, &mac);

        assert_eq!(mac_validation, false);
    }
}
