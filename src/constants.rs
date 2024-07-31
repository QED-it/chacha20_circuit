#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;
pub(crate) const BINARY_LENGTH: usize = 32;
pub(crate) const STATE_LENGTH: usize = 16;
pub(crate) const KEY_LENGTH: usize = 8;
pub(crate) const NONCE_LENGTH: usize = 3;
pub(crate) const CONSTANT_LENGTH: usize = 4;

pub(crate) const ROTATION_LENGTHS: [usize; 4] = [7, 8, 12, 16];
pub(crate) const INIT_CONSTANTS: [u32; 4] = [1634760805, 857760878, 2036477234, 1797285236];
