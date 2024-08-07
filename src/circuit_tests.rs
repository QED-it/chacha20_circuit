use crate::utilities::{
    create_circuit, draw_circuit, run_mock_prover, run_negative_test, run_plonk_prover,
    to_halo2_instance,
};

pub fn run_chacha20_circuit_example(
    operation: String,
    key_vectors: Vec<Vec<bool>>,
    nonce_vectors: Vec<Vec<bool>>,
    plaintext_vectors: Vec<Vec<bool>>,
    ciphertext_vectors: Vec<Vec<bool>>,
) {
    // Size of the circuit. Circuit must fit within 2^k rows.
    let k = 12;

    // Create circuit
    let chacha_circuit = create_circuit(key_vectors, nonce_vectors, plaintext_vectors);

    // Ciphertext is stored in the public instance
    let public_inputs = to_halo2_instance(ciphertext_vectors);

    match &operation[..] {
        "mock_prover" => {
            run_mock_prover(k, &chacha_circuit, public_inputs);
        }
        "negative_test" => {
            run_negative_test(k, &chacha_circuit, public_inputs);
        }
        "plonk_prover" => {
            run_plonk_prover(k, &chacha_circuit, public_inputs);
        }
        "visualization" => {
            draw_circuit(k, &chacha_circuit);
        }
        _ => {}
    };
}
#[cfg(test)]
mod tests {
    use crate::circuit_tests::run_chacha20_circuit_example;
    use crate::constants::CIPHERTEXT_LENGTH;
    use crate::utilities::{pad_u8_vec, u8_to_32bit_binary, u8_to_binary};
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;
    use rand::Rng;
    use rand_core::OsRng;

    #[test]
    fn round_trip() {
        let mut rng = OsRng;

        // The following key, nonce and plaintext can be replaced by custom generated values
        // sample a random key
        let mut key = [0u8; 32];
        rng.fill(&mut key);

        // sample a random nonce
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);

        // sample a random plaintext
        let mut plaintext = [0u8; CIPHERTEXT_LENGTH];
        rng.fill(&mut plaintext[..]);

        // Compute a ciphertext from the external chacha20 encryption (default counter = 0)
        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        let mut ciphertext = plaintext.clone();
        // apply keystream (encrypt)
        cipher.apply_keystream(&mut ciphertext);

        let block: usize = (CIPHERTEXT_LENGTH + 3) / 4;

        let key_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&key, 8, true);
        let nonce_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&nonce, 3, true);
        let padded_plaintext_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&plaintext, block, false);
        let ciphertext_vectors: Vec<Vec<bool>> = u8_to_binary(&ciphertext);

        // Run mock prover
        run_chacha20_circuit_example(
            "mock_prover".to_string(),
            key_vectors.clone(),
            nonce_vectors.clone(),
            padded_plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );

        // Run plonk prover

        run_chacha20_circuit_example(
            "plonk_prover".to_string(),
            key_vectors.clone(),
            nonce_vectors.clone(),
            padded_plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );

        run_chacha20_circuit_example(
            "visualization".to_string(),
            key_vectors.clone(),
            nonce_vectors.clone(),
            padded_plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );
    }

    #[test]
    fn negative_test() {
        let mut rng = OsRng;

        // The following key, nonce and plaintext can be replaced by custom generated values
        // sample a random key
        let mut key = [0u8; 32];
        rng.fill(&mut key);

        // sample a random nonce
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);

        // sample a random plaintext
        let mut plaintext = [0u8; 64];
        rng.fill(&mut plaintext[..]);

        // Compute a ciphertext from the external chacha20 encryption (default counter = 0)
        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        let mut ciphertext = plaintext.clone();
        // apply keystream (encrypt)
        cipher.apply_keystream(&mut ciphertext);

        // Fake witness generation for negative test
        // Simulate the case where an adversary cannot fake a valid proof without the knowledge of the real witness values
        // sample a random key
        let mut fake_key = [0u8; 32];
        rng.fill(&mut fake_key);

        // sample a random nonce
        let mut fake_nonce = [0u8; 12];
        rng.fill(&mut fake_nonce);

        // sample a random plaintext
        let mut fake_plaintext = [0u8; 64];
        rng.fill(&mut fake_plaintext[..]);

        let fake_key_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&fake_key, 8, true);
        let fake_nonce_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&fake_nonce, 3, true);
        let fake_plaintext_vectors: Vec<Vec<bool>> =
            u8_to_32bit_binary(&pad_u8_vec(&fake_plaintext), 16, false);
        let ciphertext_vectors: Vec<Vec<bool>> = u8_to_binary(&ciphertext);

        run_chacha20_circuit_example(
            "negative_test".to_string(),
            fake_key_vectors.clone(),
            fake_nonce_vectors.clone(),
            fake_plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );
    }
}
