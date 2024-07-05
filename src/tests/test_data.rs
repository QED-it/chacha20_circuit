/// This file shows how to perform chacha20 encryption
/// It is also used to generate test data for chacha20 circuit
///
extern crate chacha20;
extern crate rand;
use crate::constants::BLOCK_LEN;

// The initial state matrix for ChaCha20 is 16 words (4x4 matrix)
struct ChaCha20State {
    matrix: [u32; 16],
}

impl ChaCha20State {
    #[allow(dead_code)]
    fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

        let key_words: [u32; 8] = [
            u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        let nonce_words: [u32; 3] = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        Self {
            matrix: [
                constants[0],
                constants[1],
                constants[2],
                constants[3],
                key_words[0],
                key_words[1],
                key_words[2],
                key_words[3],
                key_words[4],
                key_words[5],
                key_words[6],
                key_words[7],
                counter,
                nonce_words[0],
                nonce_words[1],
                nonce_words[2],
            ],
        }
    }
}
#[allow(dead_code)]
fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[allow(dead_code)]
fn chacha20_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        // inner_block(state)
        // Column rounds
        quarter_round(0, 4, 8, 12, state);
        quarter_round(1, 5, 9, 13, state);
        quarter_round(2, 6, 10, 14, state);
        quarter_round(3, 7, 11, 15, state);

        // Diagonal rounds
        quarter_round(0, 5, 10, 15, state);
        quarter_round(1, 6, 11, 12, state);
        quarter_round(2, 7, 8, 13, state);
        quarter_round(3, 4, 9, 14, state);
    }
}

#[allow(dead_code)]
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Vec<u8> {
    let mut state = ChaCha20State::new(key, nonce, counter).matrix;
    let init_state = state;

    // Apply the ChaCha20 rounds
    chacha20_rounds(&mut state);

    // Add the original state to the state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(init_state[i]);
    }

    // Serialize the state
    let mut serialized_block = Vec::new();
    for value in state {
        serialized_block.extend_from_slice(&value.to_le_bytes());
    }
    serialized_block
}

#[allow(dead_code)]
fn chacha20_encrypt(key: &[u8; 32], counter: u32, nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = plaintext.to_owned(); // Create a mutable copy of the plaintext

    let mut key_stream = Vec::new();
    let chunks = plaintext.len() / BLOCK_LEN;
    let tail_pos = BLOCK_LEN * chunks;
    let tail_len = plaintext.len() - tail_pos;

    // generate key_stream
    for j in 0..chunks {
        let key_stream_chunk = chacha20_block(key, counter + j as u32, nonce);

        for value in key_stream_chunk {
            key_stream.extend_from_slice(&value.to_le_bytes());
        }
    }
    if tail_len != 0 {
        let j = chunks;
        let key_stream_chunk = chacha20_block(key, counter + j as u32, nonce);
        for item in key_stream_chunk.iter().take(tail_len) {
            key_stream.extend_from_slice(&item.to_le_bytes());
        }
    }

    for i in 0..plaintext.len() {
        ciphertext[i] ^= key_stream[i];
    }
    ciphertext
}

#[allow(dead_code)]
fn u8_to_u32(ciphertext: &[u8]) -> [u32; 16] {
    let mut u32s: [u32; 16] = [0; 16];

    // Convert every 4 bytes of the u8 array into a single u32 using little-endian format
    for (i, chunk) in ciphertext.chunks(4).enumerate() {
        u32s[i] = u32::from_le_bytes(chunk.try_into().expect("slice with incorrect size"));
    }
    u32s
}
#[allow(dead_code)]
fn u32_to_u8(plaintext: &[u32; 16]) -> [u8; 64] {
    let mut bytes: [u8; 64] = [0; 64]; // 16 u32s * 4 bytes each = 64 bytes
    for (i, &num) in plaintext.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&num.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod chacha20test {
    use crate::tests::test_data::chacha20::cipher::KeyIvInit;
    use crate::tests::test_data::{chacha20_block, chacha20_encrypt, u32_to_u8, u8_to_u32};
    use chacha20::ChaCha20;

    extern crate chacha20;
    extern crate rand;

    use chacha20::cipher::StreamCipher;
    use hex_literal::hex;
    const KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const NONCE: [u8; 12] = hex!("000000000000004a00000000");

    const PLAINTEXT: [u8; 114] = hex!(
        "
        4c616469657320616e642047656e746c
        656d656e206f662074686520636c6173
        73206f66202739393a20496620492063
        6f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220
        746865206675747572652c2073756e73
        637265656e20776f756c642062652069
        742e
        "
    );

    #[test]
    fn test_chacha20_block() {
        let expected_key_stream: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        let key_bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce_bytes = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let key: [u8; 32] = key_bytes;
        let nonce: [u8; 12] = nonce_bytes;
        let counter = 1;

        let key_stream = chacha20_block(&key, counter, &nonce);

        assert_eq!(key_stream, expected_key_stream);
    }

    #[test]
    fn generate_chacha20_encrypt_data() {
        let key: [u8; 32] = KEY;
        let nonce: [u8; 12] = NONCE;
        let plaintext: [u32; 16] = [
            1768186188, 1629516645, 1193305198, 1819569765, 1852140901, 543584032, 543516788,
            1935764579, 1718558835, 960046880, 1716068410, 1663060256, 1684829551, 1717989152,
            2032169573, 1864398191,
        ];
        let bytes: [u8; 64] = u32_to_u8(&plaintext);

        let counter = 1;
        let ciphertext = chacha20_encrypt(&key, counter, &nonce, &bytes.to_vec());
        println!("ciphertext={:?}", u8_to_u32(&ciphertext));
    }

    #[test]
    fn test_chacha20_encrypt_algorithm() {
        let key: [u8; 32] = KEY;
        let nonce: [u8; 12] = NONCE;
        let plaintext = PLAINTEXT.to_vec();
        let counter = 0;
        let ciphertext = chacha20_encrypt(&key, counter, &nonce, &plaintext);

        // Compute from chacha20 encryption
        // set counter to 0
        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        let mut buffer = plaintext.clone();
        // apply keystream (encrypt)
        cipher.apply_keystream(&mut buffer);

        assert_eq!(ciphertext, buffer);
    }
}
