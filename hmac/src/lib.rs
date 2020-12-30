use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 64; // bytes
pub const OUTPUT_SIZE: usize = 32; // bytes

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut kvec = Vec::with_capacity(BLOCK_SIZE); // Padded key

    if key.len() > BLOCK_SIZE {
        let mut m = Sha256::new();
        m.update(key);
        kvec.extend_from_slice(&m.finalize());
    }

    if key.len() < BLOCK_SIZE {
        let padding = BLOCK_SIZE - key.len();
        kvec.extend_from_slice(key);
        for _ in 0..padding {
            kvec.push(0x00u8);
        }
    }

    let mut o_key_pad = Vec::new(); // Outer padded key
    let mut i_key_pad = Vec::new(); // Inner padded key
    for (a, b) in kvec[..].iter().zip(&[0x5cu8; BLOCK_SIZE]) {
        o_key_pad.push(a ^ b);
    }
    for (a, b) in kvec[..].iter().zip(&[0x36u8; BLOCK_SIZE]) {
        i_key_pad.push(a ^ b);
    }

    // hash(i_key_pad || message)
    let mut m = Sha256::new();
    let mut i_key_pad_concat_message = Vec::new();
    i_key_pad_concat_message.extend_from_slice(&i_key_pad[..]);
    i_key_pad_concat_message.extend_from_slice(&message);
    m.update(&i_key_pad_concat_message);
    let hash_i_key_pad_message = m.finalize();

    // hash(o_key_pad || hash(i_key_pad || message))
    let mut m = Sha256::new();
    let mut o_key_pad_concat_message = Vec::new();
    o_key_pad_concat_message.extend_from_slice(&o_key_pad[..]);
    o_key_pad_concat_message.extend_from_slice(&hash_i_key_pad_message[..]);
    m.update(&o_key_pad_concat_message);
    m.finalize().to_vec()
}

pub fn verify_hmac_sha256(key: &[u8], message: &[u8], mac: &Vec<u8>) -> bool {
    let test_mac = hmac_sha256(key, message);

    let mut result = true;
    for (a, b) in test_mac.iter().zip(mac) {
        if *a != *b {
            result = false;
        }
    }
    result
}
