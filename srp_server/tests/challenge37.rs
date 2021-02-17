#![allow(non_snake_case)]
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use sha2::{Digest, Sha256};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

use secure_remote_password::Parameters;
use secure_remote_password::{
    ClientKey, ClientLoginAttemptPendingResponse, PublicKey, SharedValue,
};
use srp_server::{SRPMessage, SRPServer};

#[test]
fn challenge_37_success() {
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

    let client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::ServerLoginResponse { msg: client_step3 } => {
            let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
            let step5 = ClientKey::new(&parameters, &client_step3, &client_step2, &client_step4);
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

#[test]
fn challenge_37_failure() {
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

    let wrong_a = PublicKey(1u32.to_biguint().expect("cant convert to biguint!"));
    let mut rng = rand::thread_rng();

    let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
    // A is wrong, we shouldn't log in.
    client_step2.A = wrong_a.clone();
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::ServerLoginResponse { msg: client_step3 } => {
            let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
            let step5 = ClientKey::new(&parameters, &client_step3, &client_step2, &client_step4);
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
            assert_eq!(false, status)
        }
        _ => {
            panic!("unexpected message from server!")
        }
    }
}

#[test]
fn challenge_37_actual_challenge_all_zero() {
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

    let all_zero_a = PublicKey(0u32.to_biguint().expect("cant convert to biguint!"));
    let mut rng = rand::thread_rng();

    let mut client_parameters = parameters.clone();
    client_parameters.P = "muhpassword".as_bytes().to_vec();
    let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &client_parameters);
    // A replaced with all 0s.
    client_step2.A = all_zero_a.clone();
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::ServerLoginResponse { msg: client_step3 } => {
            let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
            let mut step5 = ClientKey::new(
                &client_parameters,
                &client_step3,
                &client_step2,
                &client_step4,
            );

            // Now modify K on the attacker side to hash 0. Why? because
            // S = (A * v**u) ** b % N on the server side which we expect to be zero given
            // the value of A we provided.
            let S = 0u32.to_biguint().expect("cant convert to biguint!");
            let mut m = Sha256::new();
            m.update(&S.to_bytes_be());
            let K = m.finalize();
            step5.K = K.to_vec();

            tx_server
                .send(SRPMessage::ClientMac {
                    I: client_parameters.I.clone(),
                    mac: step5.gen_mac(&client_step3),
                })
                .expect("failed to send message to server!");
        }
        _ => {
            panic!("unexpected message from server!")
        }
    }
    assert_eq!(all_zero_a.clone().0, client_step2.A.0);

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

#[test]
fn challenge_37_actual_challenge_N() {
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

    let mut client_parameters = parameters.clone();
    client_parameters.P = "muhpassword".as_bytes().to_vec();
    let n_a = PublicKey(client_parameters.N.clone());
    let mut rng = rand::thread_rng();

    let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &client_parameters);
    // A replaced with N.
    client_step2.A = n_a.clone();
    let server_step2 = client_step2.to_server();
    tx_server
        .send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        })
        .expect("failed to send message to server!");

    let resp = rx_client.recv().unwrap();
    match resp {
        SRPMessage::ServerLoginResponse { msg: client_step3 } => {
            let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
            let mut step5 = ClientKey::new(
                &client_parameters,
                &client_step3,
                &client_step2,
                &client_step4,
            );

            // Now modify K on the attacker side to hash 0. Why? because
            // S = (A * v**u) ** b % N on the server side which we expect to be zero given
            // the value of A we provided.
            let S = 0u32.to_biguint().expect("cant convert to biguint!");
            let mut m = Sha256::new();
            m.update(&S.to_bytes_be());
            let K = m.finalize();
            step5.K = K.to_vec();

            tx_server
                .send(SRPMessage::ClientMac {
                    I: client_parameters.I.clone(),
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
