pub(crate) const BINARY_LENGTH: usize = 32;

pub(crate) const ROTATION_LENGTHS: [usize; 4] = [7, 8, 12, 16];
pub(crate) const INIT_CONSTANTS: [u32; 4] = [1634760805, 857760878, 2036477234, 1797285236];

// bytes, we can change the PLAINTEXT_LENGTH value to different sizes of plaintext,
// the maximum value for a plaintext block is 64 bytes
// todo: consider multiple blocks
pub(crate) const CIPHERTEXT_LENGTH: usize = 30;
