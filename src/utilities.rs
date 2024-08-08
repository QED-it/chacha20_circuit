use crate::chacha20_circuit::ChaCha20Circuit;
use crate::constants::CONSTANTS;
use ff::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use pasta_curves::vesta;
use rand_core::OsRng;
use std::time::Instant;

// Draws the layout of the circuit.
pub fn draw_circuit<F: Field>(k: u32, circuit: &ChaCha20Circuit<F>) {
    use plotters::prelude::*;
    let base = BitMapBackend::new("layout.png", (2600, 1600)).into_drawing_area();
    base.fill(&WHITE).unwrap();
    let base = base.titled("ChaCha20 Circuit", ("sans-serif", 24)).unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        // You can optionally render only a section of the circuit.
        // .view_width(0..2)
        // .view_height(0..16)
        // You can hide labels, which can be useful with smaller areas.
        .show_labels(false)
        // Draws red lines between equality-constrained cells.
        .show_equality_constraints(false)
        // Marks cells involved in equality constraints, in red.
        .mark_equality_cells(false)
        // Render the circuit onto your area!
        // The first argument is the size parameter for the circuit.
        .render(k, circuit, &base)
        .unwrap();
}

// Creates a circuit from the constant and witness (key, nonce and plaintext)
pub fn create_circuit(
    key: Vec<Vec<bool>>,
    nonce: Vec<Vec<bool>>,
    plaintext: Vec<Vec<bool>>,
) -> ChaCha20Circuit<Fp> {
    // constant to the ChaCha20Circuit
    // CONSTANTS is the constant used to set up the initial state
    let mut constants = Vec::new();
    let constant_vectors: Vec<Vec<bool>> = u32_to_binary(&CONSTANTS);

    for c in constant_vectors {
        let c_vec = c
            .clone()
            .iter()
            .map(|f| Fp::from(*f))
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap();
        constants.push(c_vec);
    }

    let mut keys = Vec::new();
    for k in key {
        let k_vec = k
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        keys.push(k_vec);
    }

    let mut nonces = Vec::new();
    for n in nonce {
        let n_vec = n
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        nonces.push(n_vec);
    }
    let mut plaintexts = Vec::new();

    for p in plaintext {
        let p_vec = p
            .clone()
            .iter()
            .map(|f| Value::known(Fp::from(*f)))
            .collect::<Vec<Value<Fp>>>()
            .try_into()
            .unwrap();
        plaintexts.push(p_vec);
    }

    // Create circuit from constants and witness (key, nonce, plaintext)
    ChaCha20Circuit {
        constants,
        keys,
        nonces,
        padded_plaintexts: plaintexts,
    }
}

// Convert the public input to a halo2 instance
pub fn to_halo2_instance(ciphertext: Vec<Vec<bool>>) -> Vec<Fp> {
    let mut instance: Vec<Fp> = Vec::new();

    for c in ciphertext {
        let c_vec: Vec<Fp> = c.clone().iter().map(|f| Fp::from(*f)).collect::<Vec<Fp>>();

        for i in c_vec {
            instance.push(i);
        }
    }

    instance
}

// Generates setup parameters using k, which is the number of rows of the circuit
// can fit in and must be a power of two
pub fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

// Generates the verifying and proving keys.
pub fn generate_keys(
    params: &Params<EqAffine>,
    circuit: &ChaCha20Circuit<Fp>,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    // just to emphasize that for vk, pk we don't need to know the value of witness
    let vk = keygen_vk(params, circuit).expect("vk should not fail");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("pk should not fail");
    (pk, vk)
}

// Generates a proof
pub fn generate_proof(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: ChaCha20Circuit<Fp>,
    pub_input: &Vec<Fp>,
) -> Vec<u8> {
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
    proof: &[u8],
) {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    assert!(verify_proof(params, vk, strategy, &[&[pub_input]], &mut transcript).is_ok());
}

// Runs the mock prover and prints any errors
pub fn run_mock_prover(k: u32, circuit: &ChaCha20Circuit<Fp>, pub_input: Vec<Fp>) {
    let prover = MockProver::run(k, circuit, vec![pub_input]).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("MockProver OK"),
        Err(e) => println!("err {:#?}", e),
    }
}

// Runs the negative test using mock prover and prints the result
pub fn run_negative_test(k: u32, circuit: &ChaCha20Circuit<Fp>, pub_input: Vec<Fp>) {
    let prover = MockProver::run(k, circuit, vec![pub_input]).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("Negative test fails"),
        Err(_) => println!("Negative test OK"),
    }
}

// Runs the plonk prover and prints any errors
pub fn run_plonk_prover(k: u32, circuit: &ChaCha20Circuit<Fp>, pub_input: Vec<Fp>) {
    // Generate setup params
    let params = generate_setup_params(k);

    // Generate proving and verifying keys
    let (pk, vk) = generate_keys(&params, circuit);

    // Generate proof
    let start_proof = Instant::now(); // Start timing
    let proof = generate_proof(&params, &pk, circuit.clone(), &pub_input);
    println!("Proof length: {} Bytes", proof.len());
    let duration_proof = start_proof.elapsed(); // Calculate elapsed time
    println!("Proof creation time: {:?}", duration_proof);

    // Verify proof
    let start_verify = Instant::now(); // Start timing
    verify(&params, &vk, &pub_input, &proof);
    let duration_verify = start_verify.elapsed(); // Calculate elapsed time
    println!("Verification time: {:?}", duration_verify);

    // Calculate the circuit cost
    let circuit_cost = halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, circuit);
    println!("Circuit cost: {:?}", circuit_cost);
}

/// data transformation
// Converts an u32 slice to a vector of binary vectors.
pub fn u32_to_binary(u32_vec: &[u32]) -> Vec<Vec<bool>> {
    // Convert each u32 to a binary vector
    u32_vec
        .iter()
        .map(|&num| {
            format!("{:032b}", num) // Ensure each number is represented as a 32-bit binary string
                .chars()
                .map(|c| c.to_digit(10).expect("Should be a bool") != 0)
                .collect()
        })
        .collect()
}

// Converts an u8 slice to a vector of binary vectors.
pub fn u8_to_binary(u8_vec: &[u8]) -> Vec<Vec<bool>> {
    // Convert each u8 to a binary vector
    u8_vec
        .iter()
        .map(|&num| {
            format!("{:08b}", num) // Ensure each number is represented as an 8-bit binary string
                .chars()
                .map(|c| c.to_digit(2).expect("Should be a bool") != 0)
                .collect()
        })
        .collect()
}

// Pads a u8 vector to ensure its length is a multiple of 4.
pub fn pad_u8_vec(u8_vec: &[u8]) -> Vec<u8> {
    let mut padded_u8_vec = Vec::from(u8_vec);

    // If the length is not a multiple of 4, pad with zeros
    if padded_u8_vec.len() % 4 != 0 {
        let padding = 4 - (padded_u8_vec.len() % 4);
        padded_u8_vec.extend(vec![0; padding]);
    }
    padded_u8_vec
}

// Converts a u8 slice to a vector of binary vectors, with optional endianness.
pub fn u8_to_32bit_binary(u8_vec: &[u8], n: usize, little_endian: bool) -> Vec<Vec<bool>> {
    let padded_u8_vec = pad_u8_vec(u8_vec);

    // Convert every four u8 to u32
    let mut u32s = vec![0u32; n];

    for (i, chunk) in padded_u8_vec.chunks(4).take(n).enumerate() {
        let bytes: [u8; 4] = chunk.try_into().expect("slice with incorrect size");
        u32s[i] = if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };
    }

    // Convert each u32 to a binary vector
    u32s.iter()
        .map(|&num| {
            format!("{:032b}", num) // Ensure each number is represented as a 32-bit binary string
                .chars()
                .map(|c| c.to_digit(10).expect("Should be a bool") != 0)
                .collect()
        })
        .collect()
}
