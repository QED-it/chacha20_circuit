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
    use crate::utilities::{u32_to_binary, u8_to_u32};
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;
    use rand::Rng;
    use rand_core::OsRng;

    #[test]
    fn round_trip() {
        let mut rng = OsRng;

        // sample a random key
        let mut init_key = [0u8; 32];
        rng.fill(&mut init_key);
        let key = u8_to_u32::<16>(&init_key);

        // sample a random nonce
        let mut init_nonce = [0u8; 12];
        rng.fill(&mut init_nonce);
        let nonce: [u32; 3] = u8_to_u32::<3>(&init_nonce);

        // sample a random plaintext
        let mut init_plaintext = [0u8; 64];
        rng.fill(&mut init_plaintext);
        let plaintext: [u32; 16] = u8_to_u32::<16>(&init_plaintext);

        // Compute a ciphertext from the external chacha20 encryption (default counter = 0)
        let mut cipher = ChaCha20::new(&init_key.into(), &init_nonce.into());
        let mut buffer = init_plaintext.clone();
        // apply keystream (encrypt)
        cipher.apply_keystream(&mut buffer);
        let ciphertext: [u32; 16] = u8_to_u32::<16>(&buffer);

        let key_vectors: Vec<Vec<bool>> = u32_to_binary(&key);
        let nonce_vectors: Vec<Vec<bool>> = u32_to_binary(&nonce);
        let plaintext_vectors: Vec<Vec<bool>> = u32_to_binary(&plaintext);
        let ciphertext_vectors: Vec<Vec<bool>> = u32_to_binary(&ciphertext);

        // Run mock prover
        //run_chacha20_circuit_example("mock_prover".to_string(), key_vectors.clone(), nonce_vectors.clone(), plaintext_vectors.clone(), ciphertext_vectors.clone());

        // Run plonk prover
        run_chacha20_circuit_example(
            "plonk_prover".to_string(),
            key_vectors.clone(),
            nonce_vectors.clone(),
            plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );
        run_chacha20_circuit_example(
            "visualization".to_string(),
            key_vectors,
            nonce_vectors,
            plaintext_vectors,
            ciphertext_vectors,
        );
    }
    #[test]
    fn negative_test() {
        let mut rng = OsRng;

        // sample a random key
        let mut init_key = [0u8; 32];
        rng.fill(&mut init_key);

        // sample a random nonce
        let mut init_nonce = [0u8; 12];
        rng.fill(&mut init_nonce);

        // sample a random plaintext
        let mut init_plaintext = [0u8; 64];
        rng.fill(&mut init_plaintext);

        // Compute a ciphertext from the external chacha20 encryption (default counter = 0)
        let mut cipher = ChaCha20::new(&init_key.into(), &init_nonce.into());
        let mut buffer = init_plaintext.clone();
        // apply keystream (encrypt)
        cipher.apply_keystream(&mut buffer);
        let ciphertext: [u32; 16] = u8_to_u32::<16>(&buffer);

        // Fake witness generation for negative test
        // Simulate the case where an adversary cannot fake a valid proof without the knowledge of the real witness values
        let mut fake_init_key = [0u8; 32];
        rng.fill(&mut fake_init_key);
        let fake_key = u8_to_u32::<8>(&fake_init_key);

        let mut fake_init_nonce = [0u8; 12];
        rng.fill(&mut fake_init_nonce);
        let fake_nonce: [u32; 3] = u8_to_u32::<3>(&fake_init_nonce);

        let mut fake_init_plaintext = [0u8; 64];
        rng.fill(&mut fake_init_plaintext);
        let fake_plaintext: [u32; 16] = u8_to_u32::<16>(&fake_init_plaintext);

        let fake_key_vectors: Vec<Vec<bool>> = u32_to_binary(&fake_key);
        let fake_nonce_vectors: Vec<Vec<bool>> = u32_to_binary(&fake_nonce);
        let fake_plaintext_vectors: Vec<Vec<bool>> = u32_to_binary(&fake_plaintext);
        let ciphertext_vectors: Vec<Vec<bool>> = u32_to_binary(&ciphertext);

        run_chacha20_circuit_example(
            "negative_test".to_string(),
            fake_key_vectors.clone(),
            fake_nonce_vectors.clone(),
            fake_plaintext_vectors.clone(),
            ciphertext_vectors.clone(),
        );
    }
}
