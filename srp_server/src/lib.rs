#![allow(non_snake_case)]
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;

use secure_remote_password::Parameters;
use secure_remote_password::{
    ClientLoginAttemptRequest, PublicKey, ServerKey, ServerLoginAttemptResponse,
    ServerLoginAttemptSession, ServerProtocolSetup, SharedValue,
    SimplifiedClientLoginAttemptRequest, SimplifiedServerLoginAttemptResponse,
    SimplifiedServerLoginAttemptSession,
};

// Messages that go between client and server during the protocol run are SRPMessages
// In a "real" protocol we'd also have a SRPMessage variant for registering I (email), P (password))
pub enum SRPMessage {
    ClientLoginStart {
        sender: Sender<SRPMessage>,
        msg: ClientLoginAttemptRequest,
    },
    SimplifiedClientLoginStart {
        sender: Sender<SRPMessage>,
        msg: SimplifiedClientLoginAttemptRequest,
    },
    ServerLoginResponse {
        msg: ServerLoginAttemptResponse,
    },
    SimplifiedServerLoginResponse {
        msg: SimplifiedServerLoginAttemptResponse,
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

pub struct SimplifiedClientLoginStart {
    pub sender: Sender<SRPMessage>,
    pub msg: SRPMessage,
}

// Server uses this to keep track of logins and in-progress sessions
// TODO: Decouple regular SRP from simplified SRP
pub struct ClientStatus {
    pub A: Option<PublicKey>,
    pub sender: Option<Sender<SRPMessage>>,
    pub server_step1: ServerProtocolSetup,
    pub server_step2: Option<ClientLoginAttemptRequest>,
    pub simplified_server_step2: Option<SimplifiedClientLoginAttemptRequest>,
    pub server_step3: Option<ServerLoginAttemptSession>,
    pub simplified_server_step3: Option<SimplifiedServerLoginAttemptSession>,
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
            simplified_server_step2: None,
            server_step3: None,
            server_step4: None,
            simplified_server_step3: None,
            step6: None,
            logged_in: false,
        }
    }
}

pub struct SRPServer {
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

        let mut server = SRPServer { clients };

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
                                    sender
                                        .send(client_step3)
                                        .expect("failed to send to client!");
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
                    SRPMessage::SimplifiedClientLoginStart {
                        sender,
                        msg: server_step2,
                    } => {
                        if !server.clients.contains_key(&server_step2.I) {
                            println!("user not registered! WAAHH!")
                        } else {
                            let entry = server.clients.get_mut(&server_step2.I).unwrap();
                            entry.A = Some(server_step2.A.clone());
                            entry.simplified_server_step2 = Some(server_step2.clone());
                            let server_step3 = SimplifiedServerLoginAttemptSession::new(
                                &mut rng,
                                &params,
                                &server_step1,
                            );
                            entry.simplified_server_step3 = Some(server_step3.clone());
                            let client_step3 = SRPMessage::SimplifiedServerLoginResponse {
                                msg: server_step3.to_client(),
                            };
                            sender
                                .send(client_step3)
                                .expect("failed to send to client!");
                            entry.sender = Some(sender);
                            let step6 = ServerKey::new_simplified(
                                &params,
                                &server_step3,
                                &server_step2,
                                &server_step1,
                            );
                            entry.step6 = Some(step6);
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
