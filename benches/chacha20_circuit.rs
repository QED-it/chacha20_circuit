use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_chacha20::utilities::{
    create_circuit, generate_keys, generate_proof, generate_setup_params, to_halo2_instance,
    u8_to_32bit_binary, u8_to_binary, verify,
};
use rand::rngs::OsRng;
use rand::Rng;

fn criterion_benchmark(c: &mut Criterion) {
    let k = 12;
    let mut rng = OsRng;

    // The following key, nonce and plaintext can be replaced by custom generated values
    // sample a random key
    let mut key = [0u8; 32];
    rng.fill(&mut key);

    // sample a random nonce
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);

    // sample a random plaintext
    let mut plaintext = [0u8; 30];
    rng.fill(&mut plaintext[..]);

    // Compute a ciphertext from the external chacha20 encryption (default counter = 0)
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    let mut ciphertext = plaintext.clone();
    // apply keystream (encrypt)
    cipher.apply_keystream(&mut ciphertext);

    let block: usize = (30 + 3) / 4;

    let key_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&key, 8, true);
    let nonce_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&nonce, 3, true);
    let padded_plaintext_vectors: Vec<Vec<bool>> = u8_to_32bit_binary(&plaintext, block, false);
    let ciphertext_vectors: Vec<Vec<bool>> = u8_to_binary(&ciphertext);

    // Create circuit
    let chacha_circuit = create_circuit(key_vectors, nonce_vectors, padded_plaintext_vectors);

    // Ciphertext is stored in the public instance
    let public_inputs = to_halo2_instance(ciphertext_vectors);

    // Generate setup params
    let params = generate_setup_params(k);

    // Generate proving and verifying keys
    let (pk, vk) = generate_keys(&params, &chacha_circuit);

    // Benchmark proof creation
    {
        c.bench_function("chacha20_proving", |b| {
            b.iter(|| {
                generate_proof(&params, &pk, chacha_circuit.clone(), &public_inputs);
            });
        });
    }

    // Benchmark proof verification
    {
        // Create a proof
        let proof = generate_proof(&params, &pk, chacha_circuit.clone(), &public_inputs);

        c.bench_function("chacha20_verifying", |b| {
            b.iter(|| {
                verify(&params, &vk, &public_inputs, &proof);
            });
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
