use crate::chacha20_v1::ChaCha20Circuit;
use crate::constants::{BINARY_LENGTH, STATE_LENGTH};
use ff::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, SingleVerifier,
    VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand_core::OsRng;

// Draws the layout of the circuit. Super useful for debugging.
pub fn draw_circuit<F: Field>(k: u32, circuit: &ChaCha20Circuit<F>) {
    use plotters::prelude::*;
    let base = BitMapBackend::new("layout.png", (2600, 1600)).into_drawing_area();
    base.fill(&WHITE).unwrap();
    let base = base.titled("ChaCha20 Circuit", ("sans-serif", 24)).unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_equality_constraints(true)
        .render(k, circuit, &base)
        .unwrap();
}

// Generates an empty circuit. Useful for generating the proving/verifying keys.
pub fn empty_circuit() -> ChaCha20Circuit<Fp> {
    let unknown_input = [Value::unknown(); BINARY_LENGTH];
    let unknown_output = [Value::unknown(); BINARY_LENGTH];

    ChaCha20Circuit {
        init_state: vec![unknown_input; STATE_LENGTH], // Populate the vector with STATE_LENGTH unknown state arrays
        plaintexts: vec![unknown_input; STATE_LENGTH], // Populate the vector with STATE_LENGTH unknown state arrays
        ciphertexts: vec![unknown_output; STATE_LENGTH], // Same for outputs
    }
}

// Creates a circuit from the initial state, plaintext and ciphertext
pub fn create_circuit(
    init_state: Vec<Vec<u64>>,
    plaintext: Vec<Vec<u64>>,
    ciphertext: Vec<Vec<u64>>,
) -> ChaCha20Circuit<Fp> {
    let mut state = Vec::new();
    for i in init_state {
        let i_vec: [Value<Fp>; BINARY_LENGTH] = i
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        state.push(i_vec);
    }

    let mut plaintexts = Vec::new();

    for p in plaintext {
        let p_vec: [Value<Fp>; BINARY_LENGTH] = p
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        plaintexts.push(p_vec);
    }

    let mut ciphertexts = Vec::new();
    for c in ciphertext {
        let c_vec: [Value<Fp>; BINARY_LENGTH] = c
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        ciphertexts.push(c_vec);
    }

    // Create circuit from inputs
    ChaCha20Circuit {
        init_state: state,
        plaintexts,
        ciphertexts,
    }
}

// Generates setup parameters using k, which is the number of rows of the circuit
// can fit in and must be a power of two
pub fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

// Generates the verifying and proving keys. We can pass in an empty circuit to generate these
pub fn generate_keys(
    params: &Params<EqAffine>,
    circuit: &ChaCha20Circuit<Fp>,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    // just to emphasize that for vk, pk we don't need to know the value of `x`
    let vk = keygen_vk(params, circuit).expect("vk should not fail");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("pk should not fail");
    (pk, vk)
}

// Runs the mock prover and prints any errors
pub fn run_mock_prover(k: u32, circuit: &ChaCha20Circuit<Fp>, pub_input: Vec<Vec<Fp>>) {
    let prover = MockProver::run(k, circuit, pub_input).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("MockProver OK"),
        Err(e) => println!("err {:#?}", e),
    }
}

// Generates a proof
pub fn generate_proof(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: ChaCha20Circuit<Fp>,
    pub_input: &Vec<Fp>,
) -> Vec<u8> {
    println!("Generating proof...");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &[&[pub_input]],
        OsRng,
        &mut transcript,
    )
    .expect("Prover should not fail");
    transcript.finalize()
}

// Verifies the proof
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    pub_input: &Vec<Fp>,
    proof: Vec<u8>,
) -> Result<(), Error> {
    println!("Verifying proof...");
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(params, vk, strategy, &[&[pub_input]], &mut transcript)
}

/// data transformation
pub fn hex_to_binary(hex: &[&str]) -> Vec<Vec<u64>> {
    // Convert hex strings to u32
    let u32_state_values: Vec<u32> = hex
        .iter()
        .map(|&hex| u32::from_str_radix(hex, 16).expect("Invalid hex input"))
        .collect();

    // Convert each u32 to a binary vector
    let init_state_vectors: Vec<Vec<u64>> = u32_state_values
        .iter()
        .map(|&num| {
            format!("{:032b}", num) // Ensure each number is represented as a 32-bit binary string
                .chars()
                .map(|c| c.to_digit(10).expect("Should be a digit") as u64)
                .collect()
        })
        .collect();
    init_state_vectors
}

pub fn u32_to_binary(u32_vec: &[u32; 16]) -> Vec<Vec<u64>> {
    // Convert each u32 to a binary vector
    let init_state_vectors: Vec<Vec<u64>> = u32_vec
        .iter()
        .map(|&num| {
            format!("{:032b}", num) // Ensure each number is represented as a 32-bit binary string
                .chars()
                .map(|c| c.to_digit(10).expect("Should be a digit") as u64)
                .collect()
        })
        .collect();
    init_state_vectors
}
