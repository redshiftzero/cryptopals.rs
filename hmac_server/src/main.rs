#![feature(proc_macro_hygiene, decl_macro)]
mod hmac;

use hmac::{hmac, verify_hmac, KEY, OUTPUT_SIZE};

#[macro_use]
extern crate rocket;

#[get("/test?<file>&<signature>")]
fn hmac_test(file: String, signature: String) -> &'static str {
    let result = verify_hmac(KEY, file.as_bytes(), &signature);
    println!("got sig: {}", signature);
    if result {
        "rekt"
    } else {
        let actual_mac = hmac(KEY, file.as_bytes());
        // debug line that will appear in the console
        println!("u failed, should be {}", actual_mac);
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
    use crate::OUTPUT_SIZE;
    use rocket::local::Client;
    use std::collections::HashMap;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn challenge_31_and_32() {
        // Exploit timing leak in server-side HMAC-SHA1 validation
        let client = Client::new(rocket()).expect("valid rocket instance");
        let mut reconstructed_mac = Vec::new();
        // Test space is lowercase hex chars
        let hex_chars = [
            "a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        ];
        for _ in 0..OUTPUT_SIZE * 2 {
            reconstructed_mac.push("a");
        }

        // Addition for challenge 32: Take multiple measurements of each character's response time
        // to reduce random error.

        for i in 0..OUTPUT_SIZE * 2 {
            // We create a hash map that shows us which letter took the longest
            // time (that is the one that allowed us to move to the next byte),
            // and use that.
            let mut char_to_time = HashMap::new();

            for test_char in hex_chars.iter() {
                let mut vec_times = Vec::new();

                for _ in 0..25 {
                    reconstructed_mac[i] = test_char;
                    let now = Instant::now();
                    let test_sig: String = reconstructed_mac.clone().into_iter().collect();
                    let mut _response = client
                        .get(format!("/test?file=file&signature={}", test_sig))
                        .dispatch();
                    vec_times.push(now.elapsed().as_millis());
                }
                println!("{:?}", vec_times);
                let sum: f32 = vec_times.iter().map(|&v| v as f32).sum();
                let avg = f32::from(sum) / (vec_times.len() as f32);
                // Now just save the mean of the measured values.
                char_to_time.entry(test_char).or_insert(avg as u32);
            }

            // At the end of the loop, we pick the shortest time
            // and that's our winner for that round.
            let mut best_value: u32 = 0;
            for (key, value) in char_to_time {
                if value > best_value {
                    reconstructed_mac[i] = key;
                    best_value = value;
                }
            }
        }

        // Now check we successfully reconstructed in one last request:
        let test_sig: String = reconstructed_mac.into_iter().collect();
        let mut response = client
            .get(format!("/test?file=file&signature={}", test_sig))
            .dispatch();
        assert_eq!(response.body_string(), Some("rekt".into()));
    }
}
