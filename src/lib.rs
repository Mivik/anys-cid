mod cid;

pub const BLOCK_SIZE: usize = 16 * 1024;

pub type Hash = [u8; 32];

pub use cid::{Cid, CidBuilder, CidDecodeError};
