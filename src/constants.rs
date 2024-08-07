pub(crate) const BINARY_LENGTH: usize = 32;

pub(crate) const ROTATION_LENGTHS: [usize; 4] = [7, 8, 12, 16];
pub(crate) const CONSTANTS: [u32; 4] = [1634760805, 857760878, 2036477234, 1797285236];

// 30 bytes ciphertext, we can change the CIPHERTEXT_LENGTH value to different sizes,
// the maximum value for a plaintext/ciphertext block is 64 bytes.
pub(crate) const CIPHERTEXT_LENGTH: usize = 30;

pub(crate) const COLUMN_QROUND_ARGS: &[(usize, usize, usize, usize)] =
    &[(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)];

pub(crate) const DIAGONAL_QROUND_ARGS: &[(usize, usize, usize, usize)] =
    &[(0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)];
