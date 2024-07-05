use halo2_chacha20::utilities::{create_circuit, draw_circuit, run_mock_prover, u32_to_binary};

fn main() {
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

    // Items that are useful for debugging issues
    draw_circuit(k, &chacha_circuit);
    run_mock_prover(k, &chacha_circuit, public_inputs);
}
