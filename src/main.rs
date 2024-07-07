use halo2_chacha20::utilities::{
    create_circuit, draw_circuit, empty_circuit, generate_keys, generate_proof,
    generate_setup_params, run_mock_prover, u32_to_binary, verify,
};
use pasta_curves::vesta;
use std::time::Instant;

pub fn run_chacha20_circuit_example(operation: String) {
    // Size of the circuit. Circuit must fit within 2^k rows.
    let k = 12;

    const PLAINTEXT: [u32; 16] = [
        1768186188, 1629516645, 1193305198, 1819569765, 1852140901, 543584032, 543516788,
        1935764579, 1718558835, 960046880, 1716068410, 1663060256, 1684829551, 1717989152,
        2032169573, 1864398191,
    ];

    const CIPHERTEXT: [u32; 16] = [
        2587176558, 2163828773, 671595073, 2171145693, 3967450857, 3261088541, 3434030858,
        195993597, 3311737849, 2872264530, 2872924559, 1471374029, 618019094, 2874298854,
        890000271, 3630237855,
    ];

    // initial state
    const INIT_STATE: [u32; 16] = [
        1634760805, 857760878, 2036477234, 1797285236, // constants
        50462976, 117835012, 185207048, 252579084, // key
        319951120, 387323156, 454695192, 522067228, // key
        1, 0, 1241513984, 0, // counter (u32), nonce ([u32;3])
    ];

    let init_state_vectors: Vec<Vec<u64>> = u32_to_binary(&INIT_STATE);
    let plaintext_vectors: Vec<Vec<u64>> = u32_to_binary(&PLAINTEXT);
    let ciphertext_vectors: Vec<Vec<u64>> = u32_to_binary(&CIPHERTEXT);

    // Create circuit
    let chacha_circuit = create_circuit(init_state_vectors, plaintext_vectors, ciphertext_vectors);
    let public_inputs = vec![vec![]];

    match &operation[..] {
        "mock_prover" => {
            run_mock_prover(k, &chacha_circuit, public_inputs);
        }
        "visualization" => {
            draw_circuit(k, &chacha_circuit);
        }
        "plonk_prover" => {
            // Generate setup params
            let params = generate_setup_params(k);

            // Generate proving and verifying keys
            let empty_circuit = empty_circuit();
            let (pk, vk) = generate_keys(&params, &empty_circuit);

            // Generate proof
            let start_proof = Instant::now(); // Start timing
            let proof = generate_proof(&params, &pk, chacha_circuit.clone(), &vec![]);
            println!("Proof length: {} Bytes", proof.len());
            let duration_proof = start_proof.elapsed(); // Calculate elapsed time
            println!("Proof creation time: {:?}", duration_proof);

            // Verify proof
            let start_verify = Instant::now(); // Start timing
            verify(&params, &vk, &vec![], proof);
            let duration_verify = start_verify.elapsed(); // Calculate elapsed time
            println!("Verification time: {:?}", duration_verify);

            // Calculate the circuit cost
            let circuit_cost =
                halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, &chacha_circuit);
            println!("Circuit cost: {:?}", circuit_cost);
        }
        _ => {}
    };
}

fn main() {
    // Run plonk prover
    run_chacha20_circuit_example("plonk_prover".to_string());
    run_chacha20_circuit_example("visualization".to_string());

}
