use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;

use utils::xor;

/// Measure English character frequency from a reference corpus.
#[allow(dead_code)]
fn get_english_text_frequency() -> std::io::Result<HashMap<char, f32>> {
    let mut file = File::open("src/christmas.txt")?;
    let mut corpus = String::new();
    file.read_to_string(&mut corpus)?;

    let mut char_freq = HashMap::new();
    for c in corpus.chars() {
        let new = match char_freq.get(&c) {
            Some(val) => val + 1.0f32,
            None => 1.0f32,
        };
        char_freq.insert(c, new);
    }

    let mut keys = Vec::new();
    for c in char_freq.keys() {
        keys.push(c.clone());
    }

    for c in keys {
        let v = char_freq.get(&c).unwrap().clone();
        char_freq.insert(c, v / corpus.len() as f32);
    }
    Ok(char_freq)
}

#[allow(dead_code)]
fn score_english_text(text: String, eng_freq: &HashMap<char, f32>) -> f32 {
    let mut score = 0.0f32;
    for c in text.chars() {
        let delta_score = match eng_freq.get(&c) {
            Some(val) => *val as f32,
            None => 0.0f32,
        };
        score = score + delta_score;
    }
    return score / text.len() as f32;
}

#[allow(dead_code)]
fn crack_single_char_xor(
    ciphertext: &[u8],
    eng_text_freq: &HashMap<char, f32>,
) -> (Vec<u8>, char, f32) {
    let mut scores = HashMap::new();
    for b in 0..255u8 {
        let plaintext = xor(ciphertext, &[b as u8]);
        match String::from_utf8(plaintext) {
            Err(_) => scores.insert(b as char, 0.0),
            Ok(val) => scores.insert(b as char, score_english_text(val, &eng_text_freq)),
        };
    }

    let mut best_score = 0.0;
    let mut best_key = 'a';
    for (key, val) in &scores {
        if *val > best_score {
            best_score = *val;
            best_key = *key;
        }
    }
    (xor(ciphertext, &[best_key as u8]), best_key, best_score)
}

#[allow(dead_code)]
fn edit_distance(arr1: &[u8], arr2: &[u8]) -> u32 {
    if arr1.len() != arr2.len() {
        panic!("edit_distance: arrays not equal length");
    }

    let mut bits = 0;
    for (a, b) in arr1.iter().zip(arr2) {
        bits = bits + (*a ^ *b).count_ones()
    }
    bits
}

#[allow(dead_code)]
fn guess_key_size(ciphertext: &[u8], start_key: usize, stop_key: usize) -> usize {
    let mut best_keysize = 0;
    let mut lowest_edit_distance = 1000;
    for keysize in start_key..=stop_key {
        // To reduce variance, problem text suggested "Or take 4 KEYSIZE blocks instead of
        // 2 and average the distances.". Here we take 8 blocks since we have a big ol ciphertext.
        let dist = edit_distance(
            &ciphertext[0..keysize * 8],
            &ciphertext[keysize * 8..keysize * 16],
        ) / keysize as u32;
        if dist < lowest_edit_distance {
            lowest_edit_distance = dist;
            best_keysize = keysize;
        }
    }
    best_keysize
}

#[allow(dead_code)]
fn solve_repeating_key_xor(ciphertext: &[u8], keysize: usize) -> Vec<u8> {
    let mut key = Vec::new();
    let eng_text_freq = get_english_text_frequency().unwrap();

    for i in 0..keysize {
        let mut block = Vec::new();
        for j in ciphertext[i..].iter().step_by(keysize) {
            block.push(*j);
        }

        let (_, keybyte, _) = crack_single_char_xor(&block[..], &eng_text_freq);
        key.push(keybyte as u8);
    }
    key
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::io::BufReader;
    use utils::{base64_to_bytes, bytes_to_hex, hex_to_bytes};

    #[test]
    fn set1_challenge3() {
        let hexstr =
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string();
        let expected_message = "Cooking MC's like a pound of bacon".to_string();
        let eng_text_freq = get_english_text_frequency().unwrap();
        let (msg, key, _) = crack_single_char_xor(&hex_to_bytes(&hexstr), &eng_text_freq);
        assert_eq!(
            String::from_utf8(msg).expect("Found invalid UTF-8"),
            expected_message
        );
        assert_eq!(key, 'X');
    }

    #[test]
    fn set1_challenge4() {
        let file = File::open("test_data/4.txt").unwrap();
        let buf = BufReader::new(file).lines();

        let mut score_per_ciphertext = HashMap::new();
        let eng_text_freq = get_english_text_frequency().unwrap();
        for line in buf {
            let ciphertext = line.unwrap();
            let (msg, _, score) = crack_single_char_xor(&hex_to_bytes(&ciphertext), &eng_text_freq);
            score_per_ciphertext.insert(msg, score);
        }
        let mut best_score = 0.0;
        let mut best_msg = "teehee".to_string();
        for (key, val) in &score_per_ciphertext {
            let score = val.clone();
            let msg = match String::from_utf8((*key.clone()).to_vec()) {
                Err(_) => "nope".to_string(),
                Ok(value) => value,
            };
            if *val > best_score {
                best_score = score;
                best_msg = msg;
            }
        }

        let expected_message = "Now that the party is jumping\n".to_string();
        assert_eq!(best_msg, expected_message);
    }

    #[test]
    fn set1_challenge5() {
        let msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .to_string();
        let result_bytes = xor(msg.as_bytes(), b"ICE");
        let expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let result_hex = bytes_to_hex(result_bytes);
        assert_eq!(result_hex, expected_result);
    }

    #[test]
    fn test_edit_distance() {
        let result = edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
        assert_eq!(result, 37);
    }

    #[test]
    fn set1_challenge6() {
        let mut file = File::open("test_data/6.txt").unwrap();
        let mut test_data = String::new();
        file.read_to_string(&mut test_data).unwrap();
        test_data = test_data.replace("\n", ""); // Remove newlines so base64 decode doesn't panic

        let ciphertext = base64_to_bytes(test_data);
        let keysize = guess_key_size(&ciphertext, 2, 40);
        assert_eq!(keysize, 29);

        let key = solve_repeating_key_xor(&ciphertext, keysize);
        assert_eq!(
            String::from_utf8(key).expect("Found invalid UTF-8"),
            "Terminator X: Bring the noise".to_string()
        );
    }
}
