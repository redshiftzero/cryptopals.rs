use num_bigint::BigUint;
use num_bigint::ToBigUint;
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use secure_remote_password::Parameters;
use secure_remote_password::{
    ClientKey, ClientLoginAttemptPendingResponse, ClientLoginAttemptRequest, PublicKey, ServerKey,
    ServerLoginAttemptResponse, ServerLoginAttemptSession, ServerProtocolSetup, SharedValue,
};

// Messages that go between client and server during the protocol run are SRPMessages
// In a "real" protocol we'd also have a SRPMessage variant for registering I (email), P (password))
pub enum SRPMessage {
    ClientLoginStart {
        sender: Sender<SRPMessage>,
        msg: ClientLoginAttemptRequest,
    },
    ServerLoginResponse {
        msg: ServerLoginAttemptResponse,
    },
    ClientMac {
        I: Vec<u8>,
        mac: Vec<u8>,
    },
    LoginStatus {
        status: bool,
    },
}

pub struct ClientLoginStart {
    pub sender: Sender<SRPMessage>,
    pub msg: SRPMessage,
}

// Server uses this to keep track of logins and in-progress sessions
pub struct ClientStatus {
    pub A: Option<PublicKey>,
    pub sender: Option<Sender<SRPMessage>>,
    pub server_step1: ServerProtocolSetup,
    pub server_step2: Option<ClientLoginAttemptRequest>,
    pub server_step3: Option<ServerLoginAttemptSession>,
    pub server_step4: Option<SharedValue>,
    pub step6: Option<ServerKey>,
    pub logged_in: bool,
}

impl ClientStatus {
    fn new(setup: ServerProtocolSetup) -> Self {
        ClientStatus {
            A: None,
            sender: None,
            server_step1: setup,
            server_step2: None,
            server_step3: None,
            server_step4: None,
            step6: None,
            logged_in: false,
        }
    }
}

pub struct SRPServer {
    params: Parameters,
    pub clients: HashMap<Vec<u8>, ClientStatus>,
}

impl SRPServer {
    pub fn run(params: Parameters, receiver: mpsc::Receiver<SRPMessage>) {
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        // The below would be done during registration but we're just
        // acting on the single client so lets add the shared params now.
        let server_step1 = ServerProtocolSetup::new(&mut rng, &params);
        let mut clients = HashMap::new();
        clients.insert(params.I.clone(), ClientStatus::new(server_step1.clone()));

        let mut server = SRPServer {
            params: params.clone(),
            clients,
        };

        thread::spawn(move || {
            for message in receiver {
                match message {
                    SRPMessage::ClientLoginStart { sender, msg } => {
                        // new session
                        let server_step2 = msg.clone();
                        match msg {
                            ClientLoginAttemptRequest { I, A } => {
                                if !server.clients.contains_key(&I) {
                                    println!("user not registered! WAAHH!")
                                } else {
                                    let entry = server.clients.get_mut(&I).unwrap();
                                    entry.A = Some(server_step2.A.clone());
                                    entry.server_step2 = Some(server_step2.clone());
                                    let server_step3 = ServerLoginAttemptSession::new(
                                        &mut rng,
                                        &params,
                                        &server_step1,
                                    );
                                    entry.server_step3 = Some(server_step3.clone());
                                    let server_step4 = SharedValue::new(&A, &server_step3.B);
                                    entry.server_step4 = Some(server_step4.clone());
                                    let client_step3 = SRPMessage::ServerLoginResponse {
                                        msg: server_step3.to_client(),
                                    };
                                    sender.send(client_step3);
                                    entry.sender = Some(sender);
                                    let step6 = ServerKey::new(
                                        &params,
                                        &server_step3,
                                        &server_step2,
                                        &server_step4,
                                        &server_step1,
                                    );
                                    entry.step6 = Some(step6);
                                }
                            }
                        };
                    }
                    SRPMessage::ClientMac { I, mac } => {
                        // continuing existing session
                        if !server.clients.contains_key(&I) {
                            println!("user not registered!")
                        } else {
                            let entry = server.clients.get_mut(&I).unwrap();
                            let mac_validation = entry
                                .step6
                                .clone()
                                .expect("step 6 not computed for this user!")
                                .verify_mac(&entry.server_step1.clone(), &mac);
                            entry.logged_in = true;
                            let resp = SRPMessage::LoginStatus {
                                status: mac_validation,
                            };
                            entry
                                .sender
                                .clone()
                                .expect("no sending channel stored for this user!")
                                .send(resp)
                                .expect("could not send to user!");
                        }
                    }
                    _ => panic!("uh oh got unexpected message"),
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use secure_remote_password::ServerLoginAttemptResponse;

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
        let server = SRPServer::run(parameters.clone(), rx_server);

        let mut rng = rand::thread_rng();

        let client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
        let server_step2 = client_step2.to_server();
        tx_server.send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        });

        let resp = rx_client.recv().unwrap();
        match resp {
            SRPMessage::ServerLoginResponse { msg } => {
                let client_step3 = msg.clone();
                match msg {
                    ServerLoginAttemptResponse => {
                        let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
                        let step5 = ClientKey::new(
                            &parameters,
                            &client_step3,
                            &client_step2,
                            &client_step4,
                        );
                        tx_server.send(SRPMessage::ClientMac {
                            I: parameters.I.clone(),
                            mac: step5.gen_mac(&client_step3),
                        });
                    }
                }
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
        let server = SRPServer::run(parameters.clone(), rx_server);

        let wrong_a = PublicKey(1u32.to_biguint().expect("cant convert to biguint!"));
        let mut rng = rand::thread_rng();

        let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &parameters);
        // A is wrong, we shouldn't log in.
        client_step2.A = wrong_a.clone();
        let server_step2 = client_step2.to_server();
        tx_server.send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        });

        let resp = rx_client.recv().unwrap();
        match resp {
            SRPMessage::ServerLoginResponse { msg } => {
                let client_step3 = msg.clone();
                match msg {
                    ServerLoginAttemptResponse => {
                        let client_step4 = SharedValue::new(&client_step2.A, &client_step3.B);
                        let step5 = ClientKey::new(
                            &parameters,
                            &client_step3,
                            &client_step2,
                            &client_step4,
                        );
                        tx_server.send(SRPMessage::ClientMac {
                            I: parameters.I.clone(),
                            mac: step5.gen_mac(&client_step3),
                        });
                    }
                }
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
        let server = SRPServer::run(parameters.clone(), rx_server);

        let all_zero_a = PublicKey(0u32.to_biguint().expect("cant convert to biguint!"));
        let mut rng = rand::thread_rng();

        let mut client_parameters = parameters.clone();
        client_parameters.P = "muhpassword".as_bytes().to_vec();
        let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &client_parameters);
        // A replaced with all 0s.
        client_step2.A = all_zero_a.clone();
        let server_step2 = client_step2.to_server();
        tx_server.send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        });

        let resp = rx_client.recv().unwrap();
        match resp {
            SRPMessage::ServerLoginResponse { msg } => {
                let client_step3 = msg.clone();
                match msg {
                    ServerLoginAttemptResponse => {
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

                        tx_server.send(SRPMessage::ClientMac {
                            I: client_parameters.I.clone(),
                            mac: step5.gen_mac(&client_step3),
                        });
                    }
                }
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
        let server = SRPServer::run(parameters.clone(), rx_server);

        let mut client_parameters = parameters.clone();
        client_parameters.P = "muhpassword".as_bytes().to_vec();
        let n_a = PublicKey(client_parameters.N.clone());
        let mut rng = rand::thread_rng();

        let mut client_step2 = ClientLoginAttemptPendingResponse::new(&mut rng, &client_parameters);
        // A replaced with N.
        client_step2.A = n_a.clone();
        let server_step2 = client_step2.to_server();
        tx_server.send(SRPMessage::ClientLoginStart {
            sender: tx_client,
            msg: server_step2,
        });

        let resp = rx_client.recv().unwrap();
        match resp {
            SRPMessage::ServerLoginResponse { msg } => {
                let client_step3 = msg.clone();
                match msg {
                    ServerLoginAttemptResponse => {
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

                        tx_server.send(SRPMessage::ClientMac {
                            I: client_parameters.I.clone(),
                            mac: step5.gen_mac(&client_step3),
                        });
                    }
                }
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
}
