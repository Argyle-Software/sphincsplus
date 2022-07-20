
#[cfg(feature = "f128")] mod f128;
#[cfg(feature = "f192")] mod f192;
#[cfg(feature = "f256")] mod f256;
#[cfg(feature = "s128")] mod s128;
#[cfg(feature = "s192")] mod s192;
#[cfg(feature = "s256")] mod s256;

#[cfg(feature = "f128")] 
pub use f128::*;
#[cfg(feature = "f192")] 
pub use f192::*;
#[cfg(feature = "f256")] 
pub use f256::*;
#[cfg(feature = "s128")] 
pub use s128::*;
#[cfg(feature = "s192")] 
pub use s192::*;
#[cfg(feature = "s256")] 
pub use s256::*;

pub const CRYPTO_SECRETKEYBYTES: usize = SPX_SK_BYTES;
pub const CRYPTO_PUBLICKEYBYTES: usize = SPX_PK_BYTES;
pub const CRYPTO_BYTES: usize = SPX_BYTES;
pub const CRYPTO_SEEDBYTES: usize = 3*SPX_N;

/* Winternitz parameter, */
pub const SPX_WOTS_W: usize = 16;

/* For clarity */
pub const SPX_ADDR_BYTES: usize = 32;

/* WOTS parameters. */
pub const SPX_WOTS_LOGW: usize = if SPX_WOTS_W == 256 {
  8 
} else { // if SPX_WOTS_W == 16
  4
};

pub const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
pub const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;
pub const SPX_WOTS_PK_BYTES: usize = SPX_WOTS_BYTES;

/* Subtree size. */
pub const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D;

/* FORS parameters. */
pub const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8;
pub const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;
pub const SPX_FORS_PK_BYTES: usize = SPX_N;

/* Resulting SPX sizes. */
pub const SPX_BYTES: usize = SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
pub const SPX_PK_BYTES: usize = 2 * SPX_N;
pub const SPX_SK_BYTES: usize = 2 * SPX_N + SPX_PK_BYTES;

pub const WOTS_SIG_LEN: usize = SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES;

pub const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT * (SPX_D - 1);
pub const SPX_TREE_BYTES: usize = (SPX_TREE_BITS + 7) / 8;
pub const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT;
pub const SPX_LEAF_BYTES: usize = (SPX_LEAF_BITS + 7) / 8;
pub const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES;

pub const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
pub const SPX_WOTS_LEN2: usize = if SPX_WOTS_W == 256 {
  if SPX_N <= 1 {
    1
  } else { // if SPX_N <= 256
    2
  } 
} else { //if SPX_WOTS_W == 16
  if SPX_N <= 8 {
    2
  } else if SPX_N <= 136 {
    3
  } else  { // if SPX_N <= 256
    4
  }
};

// #[cfg(any(feature = "sha2", feature = "sha512"))]
pub const SPX_SHA256_BLOCK_BYTES: usize = 64;
pub const SPX_SHA256_OUTPUT_BYTES: usize = 32;  /* This does not necessarily equal SPX_N */

pub const SPX_SHA512_BLOCK_BYTES: usize = 128;
pub const SPX_SHA512_OUTPUT_BYTES: usize = 64;

pub const SPX_SHA256_ADDR_BYTES: usize = 22;

pub const SPX_SHAX_OUTPUT_BYTES: usize = if SPX_N >= 24 { 
  SPX_SHA512_OUTPUT_BYTES 
} else { 
  SPX_SHA256_OUTPUT_BYTES
};

pub const SPX_SHAX_BLOCK_BYTES: usize = if SPX_N >= 24 { 
  SPX_SHA512_BLOCK_BYTES 
} else {
  SPX_SHA256_BLOCK_BYTES 
};