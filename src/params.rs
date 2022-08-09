
#[cfg(feature = "f128")] mod f128;
#[cfg(feature = "f192")] mod f192;
#[cfg(feature = "f256")] mod f256;
#[cfg(feature = "s128")] mod s128;
#[cfg(feature = "s192")] mod s192;
#[cfg(feature = "s256")] mod s256;

#[cfg(feature = "f128")] pub use f128::*;
#[cfg(feature = "f192")] pub use f192::*;
#[cfg(feature = "f256")] pub use f256::*;
#[cfg(feature = "s128")] pub use s128::*;
#[cfg(feature = "s192")] pub use s192::*;
#[cfg(feature = "s256")] pub use s256::*;

#[macro_export]
macro_rules! build_consts {
  () => {
    const CRYPTO_SECRETKEYBYTES: usize = Self::SPX_SK_BYTES;
    const CRYPTO_PUBLICKEYBYTES: usize = Self::SPX_PK_BYTES;
    const CRYPTO_BYTES: usize = Self::SPX_BYTES;
    const CRYPTO_SEEDBYTES: usize = 3*Self::SPX_N;

    /// Winternitz parameter,
    const SPX_WOTS_W: usize = 16;

    /// For clarity
    #[cfg(any(feature = "haraka", feature = "shake"))]
    const SPX_ADDR_BYTES: usize = 32;

    /// WOTS parameters.
    const SPX_WOTS_LOGW: usize = if Self::SPX_WOTS_W == 256 {
      8 
    } else { // if SPX_WOTS_W == 16
      4
    };

    const SPX_WOTS_LEN: usize = Self::SPX_WOTS_LEN1 + Self::SPX_WOTS_LEN2;
    const SPX_WOTS_BYTES: usize = Self::SPX_WOTS_LEN * Self::SPX_N;
    // const SPX_WOTS_PK_BYTES: usize = SPX_WOTS_BYTES;

    /// Subtree size.
    const SPX_TREE_HEIGHT: usize = Self::SPX_FULL_HEIGHT / Self::SPX_D;

    /// FORS parameters.
    const SPX_FORS_MSG_BYTES: usize = (Self::SPX_FORS_HEIGHT * Self::SPX_FORS_TREES + 7) / 8;
    const SPX_FORS_BYTES: usize = (Self::SPX_FORS_HEIGHT + 1) * Self::SPX_FORS_TREES * Self::SPX_N;
    // const SPX_FORS_PK_BYTES: usize = SPX_N;

    /// Resulting SPX sizes.
    const SPX_BYTES: usize = Self::SPX_N + Self::SPX_FORS_BYTES + Self::SPX_D * Self::SPX_WOTS_BYTES + Self::SPX_FULL_HEIGHT * Self::SPX_N;
    const SPX_PK_BYTES: usize = 2 * Self::SPX_N;
    const SPX_SK_BYTES: usize = 2 * Self::SPX_N + Self::SPX_PK_BYTES;

    // const WOTS_SIG_LEN: usize = SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES;

    const SPX_TREE_BITS: usize = Self::SPX_TREE_HEIGHT * (Self::SPX_D - 1);
    const SPX_TREE_BYTES: usize = (Self::SPX_TREE_BITS + 7) / 8;
    const SPX_LEAF_BITS: usize = Self::SPX_TREE_HEIGHT;
    const SPX_LEAF_BYTES: usize = (Self::SPX_LEAF_BITS + 7) / 8;
    const SPX_DGST_BYTES: usize = Self::SPX_FORS_MSG_BYTES + Self::SPX_TREE_BYTES + Self::SPX_LEAF_BYTES;

    const SPX_WOTS_LEN1: usize = 8 * Self::SPX_N / Self::SPX_WOTS_LOGW;

    /// SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute
    const SPX_WOTS_LEN2: usize = if Self::SPX_WOTS_W == 256 {
      if Self::SPX_N <= 1 {
        1
      } else { // if SPX_N <= 256
        2
      } 
    } else { //if SPX_WOTS_W == 16
      if Self::SPX_N <= 8 {
        2
      } else if Self::SPX_N <= 136 {
        3
      } else  { // if SPX_N <= 256
        4
      }
    };
  };
}



// pub const HASH: &str = if cfg!(feature = "sha2") { "sha2" } 
// else if cfg!(feature = "shake") { "shake" } 
// else { "haraka" };

// pub const MODE: &str = if cfg!(feature = "s128") { "128s" }
// else if cfg!(feature = "f128") { "128f" } 
// else if cfg!(feature = "s192") { "192s" } 
// else if cfg!(feature = "f192") { "192f" } 
// else if cfg!(feature = "s256") { "256s" } 
// else { "256f" };

// pub const THASH: &str = if cfg!(feature = "simple") { "simple" } 
// else { "robust" }; 