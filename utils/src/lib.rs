use base64;
use hex;

pub fn hex_to_bytes(input: String) -> Vec<u8> {
    hex::decode(input).expect("could not hex decode")
}

pub fn bytes_to_hex(input: Vec<u8>) -> String {
    hex::encode(input)
}

pub fn bytes_to_base64(input: Vec<u8>) -> String {
    base64::encode(input)
}

pub fn hex_to_base64(input: String) -> String {
    let bytes_from_hex = hex_to_bytes(input);
    bytes_to_base64(bytes_from_hex)
}

pub fn single_char_xor(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    if bytes1.len() == !bytes2.len() {
        panic!("waaah not equal length buffers!")
    }
    let mut result = Vec::new();
    for (a, b) in bytes1.iter().zip(bytes2.iter()) {
        result.push(a ^ b);
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn set1_challenge1() {
        let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(hex_to_base64(hex_str.to_string()), base64_str);
    }

    #[test]
    fn set1_challenge2() {
        let str1 = "1c0111001f010100061a024b53535009181c".to_string();
        let str2 = "686974207468652062756c6c277320657965".to_string();

        let expected_result = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            bytes_to_hex(single_char_xor(&hex_to_bytes(str1), &hex_to_bytes(str2))),
            expected_result
        );
    }
}
