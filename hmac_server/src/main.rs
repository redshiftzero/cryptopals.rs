#![feature(proc_macro_hygiene, decl_macro)]
mod hmac;

use hmac::{KEY, verify_hmac, hmac, OUTPUT_SIZE};

#[macro_use] extern crate rocket;

#[get("/test?<file>&<signature>")]
fn hmac_test(file: String, signature: String) -> &'static str {
    let result = verify_hmac(KEY, file.as_bytes(), &signature);
    println!("got sig: {}",signature.clone());
    if result == true {
        "rekt"
    } else {
        let actual_mac = hmac(KEY, file.as_bytes());
        // debug line that will appear in the console
        println!("u failed, should be {}", actual_mac.clone());
        "fail"
    }
}

fn rocket() -> rocket::Rocket {
    rocket::ignite().mount("/", routes![hmac_test])
}

/// This is the server side for set 4, challenge 31 in cryptopals.
/// http://localhost:8000/test?file=beepboop&signature=477691a8a4cfe763c4e29fce405fc2e3cc7c9ada
fn main() {
    rocket().launch();
}

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::local::Client;
    use std::time::Instant;
    use crate::OUTPUT_SIZE;
    use std::collections::HashMap;

    #[test]
    #[ignore]
    fn challenge_31() {
        // Exploit artificial timing leak in server-side HMAC-SHA1 validation
        let client = Client::new(rocket()).expect("valid rocket instance");
        let mut reconstructed_mac = Vec::new();
        // Test space is lowercase hex chars
        let hex_chars = ["a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
        for _ in 0..OUTPUT_SIZE*2 {
            reconstructed_mac.push("a");
        }

        for i in 0..OUTPUT_SIZE*2 {
            // We create a hash map that shows us which letter took the longest
            // time (that is the one that allowed us to move to the next byte),
            // and use that.
            let mut char_to_time = HashMap::new();

            for test_char in hex_chars.iter() {
                reconstructed_mac[i] = test_char;
                let now = Instant::now();
                let test_sig: String = reconstructed_mac.clone().into_iter().collect();
                let mut _response = client.get(format!("/test?file=file&signature={}",test_sig)).dispatch();
                char_to_time.entry(test_char).or_insert(now.elapsed().as_millis());
            }

            // At the end of the loop, we pick the shortest time
            // and that's our winner for that round.
            let mut best_value = 0;
            for (key, value) in char_to_time {
                if value > best_value {
                    reconstructed_mac[i] = key;
                    best_value = value;
                }
            }
        }

        // Now check we successfully reconstructed in one last request:
        let test_sig: String = reconstructed_mac.into_iter().collect();
        let mut response = client.get(format!("/test?file=file&signature={}",test_sig)).dispatch();
        assert_eq!(response.body_string(), Some("rekt".into()));
    }
}