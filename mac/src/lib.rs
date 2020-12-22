use hashes::Sha1;

const HASH_LEN: usize = 20;


/// macro from ring: https://github.com/briansmith/ring/blob/c786cd7c285cf03bdb15a29b66f4a20303a0a144/src/polyfill.rs#L139-L158
/// Returns a reference to the elements of `$slice` as an array, verifying that
/// the slice is of length `$len`.
macro_rules! slice_as_array_ref {
    ($slice:expr, $len:expr) => {
        {
            fn slice_as_array_ref<T>(slice: &[T])
                                     -> Result<&[T; $len], ()> {
                if slice.len() != $len {
                    return Err(());
                }
                Ok(unsafe {
                    &*(slice.as_ptr() as *const [T; $len])
                })
            }
            slice_as_array_ref($slice)
        }
    }
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
        let key = "key".as_bytes();
        let message = "secret secret".as_bytes();
        let mac = gen_keyed_mac(&key, &message);

        let result = verify_keyed_mac(&key, &message, &mac);
        assert_eq!(result, true);

        let not_key = "not da key".as_bytes();
        let result = verify_keyed_mac(&not_key, &message, &mac);
        assert_eq!(result, false);
    }

}
