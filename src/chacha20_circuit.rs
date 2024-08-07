use crate::constants::{
    BINARY_LENGTH, CIPHERTEXT_LENGTH, COLUMN_QROUND_ARGS, DIAGONAL_QROUND_ARGS, ROTATION_LENGTHS,
};
use halo2_proofs::plonk::{Constraints, Fixed, Instance};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

// Traits for the chip
trait Instructions<F: Field>: Chip<F> {
    type Num;

    // Loads private inputs (decomposed) into BINARY_LENGTH advice columns and checks if the digits are binary values
    fn load_private_and_check_binary(
        &self,
        layouter: impl Layouter<F>,
        value: [Value<F>; BINARY_LENGTH],
    ) -> Result<Vec<Self::Num>, Error>;

    // Loads constant inputs into the circuit as fixed constants.
    fn load_constant(
        &self,
        layouter: impl Layouter<F>,
        constants: [F; BINARY_LENGTH],
    ) -> Result<Vec<Self::Num>, Error>;

    // Performs a wrapping_add operation between two field elements
    fn wrapping_add(
        &self,
        layouter: impl Layouter<F>,
        a: Vec<Self::Num>,
        b: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error>;

    // Performs an XOR operation between two field elements of BINARY_LENGTH bits
    fn xor(
        &self,
        layouter: impl Layouter<F>,
        a: Vec<Self::Num>,
        b: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error>;

    // Performs a left rotation operation for one field element, left rotate l bits
    fn left_rotate_l(
        &self,
        layouter: impl Layouter<F>,
        values: Vec<Self::Num>,
        l: usize,
    ) -> Result<Vec<Self::Num>, Error>;

    // Check that elements in the vector num are equal to public inputs starting from start.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        start_index: usize,
        num: Vec<Self::Num>,
    ) -> Result<(), Error>;

    // Serialize the state to the key stream
    fn serialize(
        &self,
        layouter: impl Layouter<F>,
        state: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error>;

    // An algorithm in chacha20 encryption
    fn quarter_round(
        &self,
        layouter: impl Layouter<F>,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        state: &mut Vec<Vec<Self::Num>>,
    ) -> Result<(), Error>;
}

// The chip which holds the circuit config

pub struct ChaCha20Chip<F: Field> {
    config: ChaCha20Config,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for ChaCha20Chip<F> {
    type Config = ChaCha20Config;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

// The configuration of the circuit
#[derive(Debug, Clone)]
pub struct ChaCha20Config {
    // We have BINARY_LENGTH advice columns
    advice: [Column<Advice>; BINARY_LENGTH],
    instance: Column<Instance>,

    // Selectors for choosing which operation to run at each row
    s_binary: Selector,
    s_wrapping_add: Selector,
    s_xor: Selector,
    s_rotate: Vec<Selector>,
}

impl<F: Field> ChaCha20Chip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; BINARY_LENGTH],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);
        meta.enable_constant(constant);
        for column in &advice {
            meta.enable_equality(*column);
        }

        let s_binary = meta.selector();
        // Gate that checks that the values in the BINARY_LENGTH advice column's cells are 0 or 1
        meta.create_gate("is binary", |meta| {
            let mut constraints = Vec::new();
            let s_binary = meta.query_selector(s_binary);
            for &column in advice.iter().take(BINARY_LENGTH) {
                let value = meta.query_advice(column, Rotation::cur());
                constraints.push(value.clone() * (Expression::Constant(F::ONE) - value));
            }
            Constraints::with_selector(s_binary, constraints)
        });

        let s_wrapping_add = meta.selector();
        // This gate performs a wrapping add operation between two cells and outputs the result to a third cell
        // out = (a + b) % 2**32
        meta.create_gate("wrapping add", |meta| {
            let mut constraints = Expression::Constant(F::ZERO);
            let mut two_pow_32 = Expression::Constant(F::ONE);

            let s_wrapping_add = meta.query_selector(s_wrapping_add);
            for &column in advice.iter().take(BINARY_LENGTH) {
                let a = meta.query_advice(column, Rotation::prev());
                let b = meta.query_advice(column, Rotation::cur());
                let out = meta.query_advice(column, Rotation::next());

                // The wrapping add constraint is defined as OUT = (A + B) % 2**32 = A + B or A + B - 2**32
                // where A = a_0 * 2^31 + a_1*2^30 + ... + a_31
                // where B = b_0 * 2^31 + b_1*2^30 + ... + b_31
                // where OUT = out_0 * 2^31 + out_1*2^30 + ... + out_31

                // The wrapping add constraint is defined as
                // (((constraints_0 * 2 + constraints_1) * 2 + constraints_2) * ... + constraints_30) * 2 + constraints_31 == 0 or 2**32
                // where constraints_i = (a_i + b_i - out_i)
                constraints = constraints.clone() * Expression::Constant(F::ONE.double())
                    + (a.clone() + b.clone() - out.clone());
                //todo: any simpler way to directly compute 2**32?
                two_pow_32 = two_pow_32 * Expression::Constant(F::ONE.double());
                // Compute 2**32
            }
            // constraints = 0 or 2**32
            vec![s_wrapping_add * (constraints.clone() * (two_pow_32 - constraints.clone()))]
        });

        let s_xor = meta.selector();
        // This gate performs an XOR operation between two cells and outputs the result to a third cell
        // out = a XOR b
        meta.create_gate("xor", |meta| {
            let mut constraints = Vec::new();
            let s_xor = meta.query_selector(s_xor);

            for &column in advice.iter().take(BINARY_LENGTH) {
                let a = meta.query_advice(column, Rotation::prev());
                let b = meta.query_advice(column, Rotation::cur());
                let out = meta.query_advice(column, Rotation::next());

                // The XOR constraint is defined as (a + b - 2ab - out) == 0
                constraints.push(
                    a.clone() + b.clone()
                        - Expression::Constant(F::ONE.double()) * a * b
                        - out.clone(),
                );
            }
            Constraints::with_selector(s_xor, constraints)
        });

        // This gate performs a left rotation operation for a field element
        // The valid rotation lengths are defined in ROTATION_LENGTHS
        let mut s_rotate = Vec::new();
        for &length in ROTATION_LENGTHS.iter() {
            let selector = meta.selector();
            s_rotate.push(selector);
            meta.create_gate("left rotate", move |meta| {
                let mut constraints = Vec::new();
                let rotation_selector = meta.query_selector(selector);

                for i in 0..BINARY_LENGTH {
                    let current = meta.query_advice(advice[i], Rotation::cur());
                    let new_position = (i + BINARY_LENGTH - length) % BINARY_LENGTH;
                    let out = meta.query_advice(advice[new_position], Rotation::next());

                    // The Rotate constraint is defined as (current_i - out_new_position) == 0
                    constraints.push(current - out);
                }
                Constraints::with_selector(rotation_selector, constraints)
            });
        }

        ChaCha20Config {
            advice,
            instance,
            s_binary,
            s_xor,
            s_wrapping_add,
            s_rotate,
        }
    }
}

// Implement all chip traits. In this section, we'll be describing how Layout will assign values to
// various cells in the circuit.
impl<F: Field> Instructions<F> for ChaCha20Chip<F> {
    type Num = AssignedCell<F, F>;

    // Loads private inputs into advice columns and checks if the digits are binary values
    fn load_private_and_check_binary(
        &self,
        mut layouter: impl Layouter<F>,
        values: [Value<F>; BINARY_LENGTH],
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "assign private values and check binary",
            |mut region| {
                // Check that each cell of the input is a binary value
                config.s_binary.enable(&mut region, 0)?;

                values
                    .iter()
                    .enumerate()
                    .map(|(i, value)| {
                        region.assign_advice(
                            || "assign private input",
                            config.advice[i],
                            0,
                            || *value,
                        )
                    })
                    .collect()
            },
        )
    }

    // Loads constant inputs into the circuit as fixed constants.
    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constants: [F; BINARY_LENGTH],
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                let mut results = Vec::with_capacity(BINARY_LENGTH);

                for (i, &constant) in constants.iter().enumerate() {
                    let result = region.assign_advice_from_constant(
                        || "constant value",
                        config.advice[i],
                        0,
                        constant,
                    )?;
                    results.push(result);
                }
                Ok(results)
            },
        )
    }

    // Performs a wrapping add operation between two field elements a and b (decomposed)
    // the addition start from the right most bit
    fn wrapping_add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Vec<Self::Num>,
        b: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "wrapping add",
            |mut region: Region<'_, F>| {
                config.s_wrapping_add.enable(&mut region, 1)?;

                // Ensure the out_cell is boolean
                config.s_binary.enable(&mut region, 2)?;

                let mut out = Vec::new();

                // Set the initial carry value to be 0
                let mut carry = Value::known(F::ZERO);

                for (i, (a_val, b_val)) in a.iter().rev().zip(b.iter().rev()).enumerate() {
                    // Calculate the add result
                    // Copy the a and b advice cell values
                    let a_v = a_val.copy_advice(
                        || "a",
                        &mut region,
                        config.advice[BINARY_LENGTH - 1 - i],
                        0,
                    )?;
                    let b_v = b_val.copy_advice(
                        || "b",
                        &mut region,
                        config.advice[BINARY_LENGTH - 1 - i],
                        1,
                    )?;

                    // compute sum_val, it can be 0, 1, 2, or 3
                    let sum_val = a_v.value().copied() + b_v.value().copied() + carry;

                    //  if sum_val = 0 or 1, sum_mod2_val = sum_val; else sum_mod2_val = sum_val - 2
                    let sum_mod2_val = sum_val.map(|sum| {
                        if sum == F::ONE || sum == F::ZERO {
                            sum
                        } else {
                            sum - F::ONE.double()
                        }
                    });

                    let out_cell = region
                        .assign_advice(
                            || "(a + b) % 2**32 (decomposed)",
                            config.advice[BINARY_LENGTH - 1 - i],
                            2,
                            || sum_mod2_val,
                        )
                        .unwrap();

                    if i < BINARY_LENGTH - 1 {
                        //  if sum_val = 0 or 1 (equivalent to sum_mod2_val = sum_val), the next carry bit carry = 0; else carry = 1
                        carry = sum_val.zip(sum_mod2_val).map(|(sum, sum_mod2)| {
                            if sum == sum_mod2 {
                                F::ZERO
                            } else {
                                F::ONE
                            }
                        });
                    }

                    out.push(out_cell);
                }
                Ok(out.iter().rev().cloned().collect())
            },
        )
    }

    // Performs an XOR operation between two field elements a and b (decomposed)
    fn xor(
        &self,
        mut layouter: impl Layouter<F>,
        a: Vec<Self::Num>,
        b: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "xor",
            |mut region: Region<'_, F>| {
                config.s_xor.enable(&mut region, 1)?;

                let mut out = Vec::new();

                for (i, (a_val, b_val)) in a.iter().zip(b.iter()).enumerate() {
                    // Copy the a and b advice cell values
                    let a_v = a_val.copy_advice(|| "a", &mut region, config.advice[i], 0)?;
                    let b_v = b_val.copy_advice(|| "b", &mut region, config.advice[i], 1)?;

                    // Calculate the XOR result. If a = b, xor_result = 0; else xor_result = 1
                    let xor_result =
                        a_v.value()
                            .zip(b_v.value())
                            .map(|(a, b)| if *a == *b { F::ZERO } else { F::ONE });

                    let out_cell = region
                        .assign_advice(|| "a xor b", config.advice[i], 2, || xor_result)
                        .unwrap();

                    out.push(out_cell);
                }
                Ok(out)
            },
        )
    }

    // Performs a left rotation operation for a decomposed field element 'values', the rotation length is l
    fn left_rotate_l(
        &self,
        mut layouter: impl Layouter<F>,
        values: Vec<Self::Num>,
        l: usize,
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || format!("left rotate by {} bits", l),
            |mut region| {
                let selector_index = ROTATION_LENGTHS.iter().position(|&len| len == l);
                if let Some(index) = selector_index {
                    config.s_rotate[index].enable(&mut region, 0)?;
                } else {
                    return Err(Error::Synthesis); // Return an error if `l` is not a predefined rotation length
                }

                let mut left = Vec::new();
                let mut right = Vec::new();

                for (i, cell) in values.iter().enumerate() {
                    let new_position = (i + BINARY_LENGTH - l) % BINARY_LENGTH;

                    let v = cell.copy_advice(|| "v", &mut region, config.advice[i], 0)?;
                    let rotate_result = v.value().map(|&v| v);
                    let out_cell = region
                        .assign_advice(
                            || "rotate",
                            config.advice[new_position],
                            1,
                            || rotate_result,
                        )
                        .unwrap();
                    if i < l {
                        left.push(out_cell);
                    } else {
                        right.push(out_cell);
                    }
                }
                // Rotate out = right || left, with 'right' starting from the l+1-th bit of the original number 'values'
                let out: Vec<_> = [&right[..], &left[..]].concat();
                Ok(out)
            },
        )
    }

    // Check that elements in the vector num are equal to public inputs starting from start_index.
    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        start_index: usize,
        vec: Vec<Self::Num>,
    ) -> Result<(), Error> {
        let config = self.config();
        for (i, vec_val) in vec.iter().enumerate() {
            // Compare a binary number 'vec' with the public inputs bit-by-bit, starting from 'start_index'.
            // 'vec' is a binary number of length BINARY_LENGTH bits.
            if start_index < (CIPHERTEXT_LENGTH / 4) * BINARY_LENGTH //  For public inputs starting from 'start_index', and having at least BINARY_LENGTH bits remaining to compare with 'vec'.
                || (start_index == (CIPHERTEXT_LENGTH / 4) * BINARY_LENGTH //  For public inputs starting from 'start_index', and having less than BINARY_LENGTH bits remaining to compare with 'vec'.
                && i < (CIPHERTEXT_LENGTH % 4) * 8)
            {
                layouter.constrain_instance(vec_val.cell(), config.instance, start_index + i)?;
            }
        }
        Ok(())
    }

    // Serialize the state to the key stream
    fn serialize(
        &self,
        mut layouter: impl Layouter<F>,
        state: Vec<Self::Num>,
    ) -> Result<Vec<Self::Num>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "serialize key stream".to_string(),
            |mut region| {
                let mut a = Vec::new();
                let mut b = Vec::new();
                let mut c = Vec::new();
                let mut d = Vec::new();

                for (i, cell) in state.iter().enumerate() {
                    let v = cell.copy_advice(|| "v", &mut region, config.advice[i], 0)?;
                    let rotate_result = v.value().map(|&v| v);
                    let result_cell = region
                        .assign_advice(|| "i-th value", config.advice[i], 1, || rotate_result)
                        .unwrap();
                    if i < 8 {
                        a.push(result_cell);
                    } else if i < 16 {
                        b.push(result_cell);
                    } else if i < 24 {
                        c.push(result_cell);
                    } else if i < 32 {
                        d.push(result_cell);
                    }
                }
                // serialized result = d || c || b || a
                let results: Vec<_> = [&d[..], &c[..], &b[..], &a[..]].concat();
                Ok(results)
            },
        )
    }

    fn quarter_round(
        &self,
        mut layouter: impl Layouter<F>,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        state: &mut Vec<Vec<Self::Num>>,
    ) -> Result<(), Error> {
        state[a] = self.wrapping_add(
            layouter.namespace(|| "wrapping add".to_string()),
            state[a].clone(),
            state[b].clone(),
        )?;
        state[d] = self.xor(
            layouter.namespace(|| "xor".to_string()),
            state[d].clone(),
            state[a].clone(),
        )?;
        state[d] = self.left_rotate_l(
            layouter.namespace(|| "rotate".to_string()),
            state[d].clone(),
            16,
        )?;

        state[c] = self.wrapping_add(
            layouter.namespace(|| "wrapping add".to_string()),
            state[c].clone(),
            state[d].clone(),
        )?;
        state[b] = self.xor(
            layouter.namespace(|| "xor".to_string()),
            state[b].clone(),
            state[c].clone(),
        )?;
        state[b] = self.left_rotate_l(
            layouter.namespace(|| "rotate".to_string()),
            state[b].clone(),
            12,
        )?;

        state[a] = self.wrapping_add(
            layouter.namespace(|| "wrapping add".to_string()),
            state[a].clone(),
            state[b].clone(),
        )?;
        state[d] = self.xor(
            layouter.namespace(|| "xor".to_string()),
            state[d].clone(),
            state[a].clone(),
        )?;
        state[d] = self.left_rotate_l(
            layouter.namespace(|| "rotate".to_string()),
            state[d].clone(),
            8,
        )?;

        state[c] = self.wrapping_add(
            layouter.namespace(|| "wrapping add".to_string()),
            state[c].clone(),
            state[d].clone(),
        )?;
        state[b] = self.xor(
            layouter.namespace(|| "xor".to_string()),
            state[b].clone(),
            state[c].clone(),
        )?;
        state[b] = self.left_rotate_l(
            layouter.namespace(|| "rotate".to_string()),
            state[b].clone(),
            7,
        )?;

        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub struct ChaCha20Circuit<F: Field> {
    pub(crate) constants: Vec<[F; BINARY_LENGTH]>,
    pub(crate) keys: Vec<[Value<F>; BINARY_LENGTH]>,
    pub(crate) nonces: Vec<[Value<F>; BINARY_LENGTH]>,
    pub(crate) padded_plaintexts: Vec<[Value<F>; BINARY_LENGTH]>,
}

impl<F: Field> Circuit<F> for ChaCha20Circuit<F> {
    type Config = ChaCha20Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice_columns_vec: Vec<Column<Advice>> =
            (0..BINARY_LENGTH).map(|_| meta.advice_column()).collect();

        // Create advice columns
        let advice_columns: [Column<Advice>; BINARY_LENGTH] =
            advice_columns_vec.try_into().expect("Incorrect length");

        // Create a fixed column to load constants.
        let constant = meta.fixed_column();

        // Create a fixed column to load instance.
        let instance = meta.instance_column();

        ChaCha20Chip::configure(meta, advice_columns, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chacha20_chip = ChaCha20Chip::<F>::construct(config.clone());

        // Load data into initial state, state = constants | key | counter | nonce
        let mut state = Vec::new();

        // Load the constant
        for c in self.constants.clone() {
            let input = chacha20_chip.load_constant(layouter.namespace(|| "load constants"), c)?;
            state.push(input.clone());
        }

        // Load the key
        for k in self.keys.clone() {
            let input = chacha20_chip
                .load_private_and_check_binary(layouter.namespace(|| "load key"), k)?;
            state.push(input.clone());
        }

        // Load the counter, counter = 0
        let zeros: [F; 32] = [F::ZERO; 32];
        let input = chacha20_chip.load_constant(layouter.namespace(|| "load counter"), zeros)?;
        state.push(input.clone());

        // Load the nonce
        for n in self.nonces.clone() {
            let input = chacha20_chip
                .load_private_and_check_binary(layouter.namespace(|| "load nonce"), n)?;
            state.push(input.clone());
        }

        // Copy the initial state to working state to compute the key stream
        let mut working_state = state.clone();

        // Load private variable vectors & check if each digit is binary
        let mut plaintexts = Vec::new();

        for p in self.padded_plaintexts.clone() {
            let plaintext = chacha20_chip
                .load_private_and_check_binary(layouter.namespace(|| "load plaintexts"), p)?;
            plaintexts.push(plaintext);
        }

        // Perform chacha20_encrypt(key, counter, nonce, plaintext) for a 30 bytes plaintext
        // compute the key_stream, where encrypted_message = key_stream XOR plaintexts_block
        let mut key_stream = state.clone();
        let mut encrypted_message = plaintexts.clone();
        for _ in 0..10 {
            // todo: consider run 4 cpu

            // Column rounds
            for &(a, b, c, d) in COLUMN_QROUND_ARGS.iter() {
                let _ = chacha20_chip.quarter_round(
                    layouter.namespace(|| "quarter_round".to_string()),
                    a,
                    b,
                    c,
                    d,
                    &mut working_state,
                );
            }

            // Diagonal rounds
            for &(a, b, c, d) in DIAGONAL_QROUND_ARGS.iter() {
                let _ = chacha20_chip.quarter_round(
                    layouter.namespace(|| "quarter_round".to_string()),
                    a,
                    b,
                    c,
                    d,
                    &mut working_state,
                );
            }
        }

        for (i, p) in plaintexts.iter().enumerate() {
            // state = (working_state + state) % 2**32
            state[i] = chacha20_chip.wrapping_add(
                layouter.namespace(|| "wrapping add".to_string()),
                state[i].clone(),
                working_state[i].clone(),
            )?;

            // key_stream = serialize(state)
            key_stream[i] = chacha20_chip.serialize(
                layouter.namespace(|| "serialize".to_string()),
                state[i].clone(),
            )?;

            // encrypted_message = key_stream XOR plaintexts_block
            encrypted_message[i] = chacha20_chip.xor(
                layouter.namespace(|| "xor".to_string()),
                key_stream[i].clone(),
                p.clone(),
            )?;

            // check if encrypted_message =  ciphertext
            chacha20_chip.expose_public(
                layouter.namespace(|| "expose encrypted message".to_string()),
                i * BINARY_LENGTH,
                encrypted_message[i].clone(),
            )?;
        }

        Ok(())
    }
}
