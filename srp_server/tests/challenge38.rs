#![allow(non_snake_case)]
use hmac::hmac_sha256;
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use primes::pow_mod;
use sha2::{Digest, Sha256};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use utils::bytes_to_hex;

use secure_remote_password::Parameters;
use secure_remote_password::{
    PrivateKey, PublicKey, SimplifiedClientKey, SimplifiedClientLoginAttemptPendingResponse,
};
use srp_server::{SRPMessage, SRPServer};

#[test]
fn challenge_38_success() {
    // Client and server both "know" the SRP parameters.
    let parameters: Parameters = Parameters {
        N: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
        g: 2u32.to_biguint().expect("cant convert to biguint!"),
        k: 3u32,
        I: "jen@dontemailme.com".as_bytes().to_vec(),
        P: "hunter2".as_bytes().to_vec(),
    };

    let (tx_server, rx_server): (Sender<SRPMessage>, Receiver<SRPMessage>) = mpsc::channel();
    let (tx_client, rx_client): (Sender<SRPMessage>, Receiver<SRPMessage>) = mpsc::channel();
    SRPServer::run(parameters.clone(), rx_server);

    let mut rng = rand::thread_rng();

    let client_step2 = SimplifiedClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::SimplifiedClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::SimplifiedServerLoginResponse { msg: client_step3 } => {
            let step5 = SimplifiedClientKey::new(&parameters, &client_step3, &client_step2);
            tx_server
                .send(SRPMessage::ClientMac {
                    I: parameters.I.clone(),
                    mac: step5.gen_mac(&client_step3),
                })
                .expect("failed to send message to server!");
        }
        _ => {
            panic!("unexpected message from server!")
        }
    }

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::LoginStatus { status } => {
            assert_eq!(true, status)
        }
        _ => {
            panic!("unexpected message from server!")
        }
    }
}

fn generate_mac(
    password: &Vec<u8>,
    A: &PublicKey,
    u: &BigUint,
    b: &PrivateKey,
    salt: &u64,
    params: &Parameters,
) -> Vec<u8> {
    // x = SHA256(salt|password)
    let mut m = Sha256::new();
    let mut xH_input = Vec::new();
    xH_input.extend_from_slice(&salt.to_be_bytes());
    xH_input.extend_from_slice(&password);
    m.update(&xH_input);
    let xH = m.finalize();
    let xH_hexstr = bytes_to_hex(xH.to_vec());
    let x = BigUint::parse_bytes(xH_hexstr.as_bytes(), 16)
        .expect("could not convert from hex str to big uint");

    // S = (G ** (u x) * A % n) ** b % n =
    let inner =
        &A.0 * pow_mod(&params.g, &(u.clone() * x), &params.N).expect("could not compute pow_mod");
    let S = pow_mod(&inner, &b.0, &params.N).expect("could not compute pow_mod");

    let mut m = Sha256::new();
    m.update(&S.to_bytes_be());
    let K = m.finalize();
    hmac_sha256(&K, &salt.to_be_bytes())
}

#[test]
fn challenge_38_actual_challenge_mitm() {
    // Client and server both "know" the SRP parameters.
    let parameters: Parameters = Parameters {
        N: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
        g: 2u32.to_biguint().expect("cant convert to biguint!"),
        k: 3u32,
        I: "jen@dontemailme.com".as_bytes().to_vec(),
        P: "x".as_bytes().to_vec(),
    };

    let (tx_server, rx_server): (Sender<SRPMessage>, Receiver<SRPMessage>) = mpsc::channel();
    let (tx_client, rx_client): (Sender<SRPMessage>, Receiver<SRPMessage>) = mpsc::channel();
    SRPServer::run(parameters.clone(), rx_server);

    let mut rng = rand::thread_rng();

    let client_step2 = SimplifiedClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::SimplifiedClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::SimplifiedServerLoginResponse {
            msg: mut client_step3,
        } => {
            // MITM TIME. Attacker mutates response from server.
            client_step3.u = 1u32.to_biguint().expect("cant convert to biguint!");
            client_step3.salt = 1u64;
            let b = PrivateKey(1u32.to_biguint().expect("cant convert to biguint!"));
            client_step3.B = PublicKey(
                pow_mod(&parameters.g, &b.0, &parameters.N).expect("could not compute pow_mod"),
            );

            let step5 = SimplifiedClientKey::new(&parameters, &client_step3, &client_step2);

            let client_mac = step5.gen_mac(&client_step3);

            // Now we take client_mac and we brute force to get the password
            // Iterate over all possible passwords (single char for demonstration/fast test purposes).
            let mut passwords = Vec::<Vec<u8>>::new();
            let alphabet: Vec<char> =
                "abcdefghijklmnopqrstuvwxyzABCDEFGIJKLMNOPQRSTUVWXYZ0123456789"
                    .chars()
                    .collect();
            for test_char in alphabet.iter() {
                let mut this_password = Vec::<u8>::new();
                this_password.push(test_char.clone() as u8);
                // For longer passwords we'd add additional chars to each password in the test set
                passwords.push(this_password);
            }

            for test_password in passwords {
                let test_mac = generate_mac(
                    &test_password,
                    &client_step2.A, // server has this but not a
                    &client_step3.u,
                    &b,
                    &client_step3.salt,
                    &parameters,
                );
                if test_mac == client_mac {
                    assert_eq!(test_password, parameters.P);
                    return;
                }
            }
        }
        _ => {
            panic!("unexpected message from server!")
        }
    }
}
