use rsa::{invmod, Decrypt, Encrypt, RSAPrivateKey};

#[test]
fn challenge_40() {
    // E=3 RSA broadcast attack
    let message_str = String::from("test");

    let privkey0 = RSAPrivateKey::new();
    let pubkey0 = privkey0.to_pubkey();
    let ciphertext0 = pubkey0.encrypt_str(&message_str);
    let plaintext = privkey0.decrypt(&ciphertext0); // We will recover this

    let privkey1 = RSAPrivateKey::new();
    let pubkey1 = privkey1.to_pubkey();
    let ciphertext1 = pubkey1.encrypt_str(&message_str);

    let privkey2 = RSAPrivateKey::new();
    let pubkey2 = privkey2.to_pubkey();
    let ciphertext2 = pubkey2.encrypt_str(&message_str);

    let m_s_0 = &pubkey1.n * &pubkey2.n;
    let m_s_1 = &pubkey2.n * &pubkey0.n;
    let m_s_2 = &pubkey0.n * &pubkey1.n;
    let n_012 = &pubkey0.n * &pubkey1.n * &pubkey2.n;

    let result =
        ((&ciphertext0 * &m_s_0 * invmod(m_s_0, pubkey0.n).expect("cant compute invmod!"))
            + (&ciphertext1 * &m_s_1 * invmod(m_s_1, pubkey1.n).expect("cant compute invmod!"))
            + (&ciphertext2 * &m_s_2 * invmod(m_s_2, pubkey2.n).expect("cant compute invmod!")))
            % n_012;

    let attacker_decryption = result.cbrt();
    assert_eq!(attacker_decryption, plaintext);
}
