use hashes::Sha1;

const HASH_LEN: usize = 20;

/// macro from ring: https://github.com/briansmith/ring/blob/c786cd7c285cf03bdb15a29b66f4a20303a0a144/src/polyfill.rs#L139-L158
/// Returns a reference to the elements of `$slice` as an array, verifying that
/// the slice is of length `$len`.
macro_rules! slice_as_array_ref {
    ($slice:expr, $len:expr) => {{
        fn slice_as_array_ref<T>(slice: &[T]) -> Result<&[T; $len], ()> {
            if slice.len() != $len {
                return Err(());
            }
            Ok(unsafe { &*(slice.as_ptr() as *const [T; $len]) })
        }
        slice_as_array_ref($slice)
    }};
}

pub fn gen_keyed_mac(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();

    let content = [key, message].concat();

    hasher.update(&content);

    let result = hasher.bytes();

    let mac = slice_as_array_ref!(&result[..], HASH_LEN);
    *mac.unwrap()
}

pub fn verify_keyed_mac(key: &[u8], message: &[u8], mac: &[u8]) -> bool {
    let test_mac = gen_keyed_mac(key, message);

    // We don't return during this loop (waiting instead until we compare
    // all values) to avoid a timing attack.
    let mut result = true;
    for (a, b) in test_mac.iter().zip(mac) {
        if a != b {
            result = false;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyed_mac_and_verification() {
        // This solves Set 4, Challenge 28, wherein we implement a SHA-1 keyed MAC.
        // We auth a message using a secret key, i.e.:
        //
        // SHA-1(key || msg)
        //
        // This gives us a tag that we can send with the message to ensure that you
        // cannot tamper with the message unless you have the secret key.
        let key = "key".as_bytes();
        let message = "secret secret".as_bytes();
        let mac = gen_keyed_mac(&key, &message);

        let result = verify_keyed_mac(&key, &message, &mac);
        assert_eq!(result, true);

        let not_key = "not da key".as_bytes();
        let result = verify_keyed_mac(&not_key, &message, &mac);
        assert_eq!(result, false);
    }

    #[test]
    fn test_break_keyed_mac_using_length_extension() {
        // This solves Set 4, Challenge 29.

        // Original key and message. We'll not use these from the attacker's perspective.
        let key = "key".as_bytes();
        let message =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
                .as_bytes();
        let mac = gen_keyed_mac(&key, &message);

        // take the SHA-1 secret-prefix MAC of the message you want to forge
        // and break it into 32 bit SHA-1 registers
        let mut state = [0u32; 5];

        // TODO: Better way of doing the below?
        fn slice_to_arr(slice: &[u8]) -> [u8; 4] {
            [slice[0], slice[1], slice[2], slice[3]]
        }

        for n in 0..5 {
            let state_bytes: [u8; 4] = slice_to_arr(&mac[4 * n..4 * (n + 1)]);
            state[n] = u32::from_be_bytes(state_bytes);
        }
        let mut hasher = Sha1::new_state(state);

        // We need to GUESS the key length.
        for key_len in 3..12 {
            let msg_len = key_len + message.len();
            fn compute_padding(msg_len: usize) -> Vec<u8> {
                let mut vec = Vec::with_capacity(256);
                let padding = (64 - (msg_len + 9) % 64) % 64;
                vec.extend_from_slice(&[0x80u8]);
                for _ in 0..padding {
                    vec.push(0u8);
                }
                let l = ((msg_len) * 8).to_be_bytes();
                vec.extend_from_slice(&l);
                vec
            }
            let glue_padding = compute_padding(msg_len);

            // Forged message:
            // SHA-1(key || msg || glue padding || new msg)
            let new_message = ";admin=true".as_bytes();
            let original_msg_len = msg_len + glue_padding.len();
            hasher.set_len(original_msg_len as u64);
            hasher.update(&new_message);
            let result = hasher.bytes();
            let mac = slice_as_array_ref!(&result[..], HASH_LEN);
            let forged_tag = *mac.unwrap();

            let forged_message = [message, &glue_padding[..], new_message].concat();

            // Assuming the position of the victim, we ensure the forged tag verifies.
            let result = verify_keyed_mac(&key, &forged_message, &forged_tag);
            if result == true {
                // Then the attacker guessed the key length correctly
                return; // Stop the test, we did it.
            }
        }

        assert_eq!(false, true); // If we get here, we didn't forge a tag successfully.
    }
}
