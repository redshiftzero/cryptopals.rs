use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;

const BLOCK_SIZE: usize = 16usize;

#[allow(dead_code)]
fn aes_decrypt_ecb(key: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    if data.len() % BLOCK_SIZE != 0 {
        panic!("aes_decrypt_ecb: input is not a multiple of block size");
    }

    let key = GenericArray::from_slice(key);
    let mut result = Vec::new();

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        let cipher = Aes128::new(&key);
        cipher.decrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    result
}

#[allow(dead_code)]
fn aes_encrypt_ecb(key: &[u8; BLOCK_SIZE], data: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let mut result = Vec::new();

    for chunk in data.chunks(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        let cipher = Aes128::new(&key);
        cipher.encrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    result
}

#[allow(dead_code)]
fn pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut vec = data.to_vec();
    let padding = block_size - vec.len() % block_size;
    for _i in 0..padding {
        vec.push(padding as u8);
    }
    vec
}

#[allow(dead_code)]
pub fn aes_decrypt_cbc(key: &[u8; BLOCK_SIZE], data: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let mut result = Vec::new();

    // First block
    let cipher = Aes128::new(&key);
    let mut input = &data[0..BLOCK_SIZE];
    let mut block = GenericArray::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    for (a, b) in block.iter().zip(iv) {
        result.push(a ^ b);
    }

    // Subsequent blocks
    for chunk in data[BLOCK_SIZE..].chunks(BLOCK_SIZE) {
        let cipher = Aes128::new(&key);
        let mut block = GenericArray::clone_from_slice(&chunk);
        cipher.decrypt_block(&mut block);

        // XOR new plaintext with last ciphertext block
        for (a, b) in input.iter().zip(block) {
            result.push(a ^ b);
        }

        // Save this ciphertext for the next iteration
        input = chunk;
    }
    result
}

#[allow(dead_code)]
pub fn aes_encrypt_cbc(key: &[u8; BLOCK_SIZE], data: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let mut result = Vec::new();

    // First block
    let cipher = Aes128::new(&key);
    let mut input = Vec::new();
    for (a, b) in data[0..BLOCK_SIZE].iter().zip(iv) {
        input.push(a ^ b);
    }
    let mut block = GenericArray::clone_from_slice(&input);
    cipher.encrypt_block(&mut block);
    result.extend_from_slice(&block);

    // Subsequent blocks
    for chunk in data[BLOCK_SIZE..].chunks(BLOCK_SIZE) {
        let cipher = Aes128::new(&key);
        let mut input = Vec::new();

        // XOR new plaintext with last ciphertext block
        for (a, b) in chunk.iter().zip(block) {
            input.push(a ^ b);
        }

        block = GenericArray::clone_from_slice(&input);
        cipher.encrypt_block(&mut block);
        result.extend_from_slice(&block);
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::*;

    use utils::{base64_to_bytes, hex_to_bytes};

    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    #[test]
    fn set1_challenge7() {
        let mut file = File::open("test_data/7.txt").unwrap();
        let mut test_data = String::new();
        file.read_to_string(&mut test_data).unwrap();
        let test_data = test_data.replace("\n", "");

        let key = b"YELLOW SUBMARINE";
        let result = String::from_utf8(aes_decrypt_ecb(key, &base64_to_bytes(test_data))).unwrap();
        assert_eq!(result.contains("I'm back and I'm ringin' the bell"), true);
    }

    #[test]
    fn set1_challenge8() {
        let file = File::open("test_data/8.txt").unwrap();
        let buf = BufReader::new(file).lines();

        let mut num_ciphertexts_with_duplicate_blocks: usize = 0;
        for line in buf {
            let hex_cipher = line.unwrap();
            let ciphertext = hex_to_bytes(&hex_cipher);
            let mut vec_blocks = Vec::new();
            for chunk in ciphertext.chunks(BLOCK_SIZE) {
                vec_blocks.push(chunk)
            }
            // Now see if there are duplicates
            vec_blocks.sort();
            let len_before = vec_blocks.len();
            vec_blocks.dedup();
            let len_after = vec_blocks.len();
            if len_after != len_before {
                num_ciphertexts_with_duplicate_blocks = num_ciphertexts_with_duplicate_blocks + 1;
            }
        }
        assert_eq!(num_ciphertexts_with_duplicate_blocks, 1);
    }

    #[test]
    fn set2_challenge9() {
        let plaintext = "YELLOW SUBMARINE".as_bytes();
        let result = pkcs7_padding(plaintext, 20);
        assert_eq!(result, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());

        let plaintext = "YELLOW SUBMARINE".as_bytes();
        let result = pkcs7_padding(plaintext, 16);
        // \x10 = 16 in hex
        assert_eq!(
            result,
            "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                .as_bytes()
        );

        let plaintext = "YEL".as_bytes();
        let result = pkcs7_padding(plaintext, 3);
        assert_eq!(result, "YEL\x03\x03\x03".as_bytes());
    }

    #[test]
    fn set2_challenge10() {
        let mut file = File::open("test_data/10.txt").unwrap();
        let mut test_data = String::new();
        file.read_to_string(&mut test_data).unwrap();
        let test_data = test_data.replace("\n", "");

        let key = b"YELLOW SUBMARINE";
        let iv = "0000000000000000".as_bytes();
        let original_ciphertext = base64_to_bytes(test_data);
        let plaintext = aes_decrypt_cbc(key, &original_ciphertext, &iv);
        let result = String::from_utf8(plaintext.clone()).unwrap();
        assert_eq!(
            result.contains("Play that funky music A little louder now"),
            true
        );

        let ciphertext = aes_encrypt_cbc(key, &plaintext, &iv);
        assert_eq!(ciphertext, original_ciphertext);
    }
}
