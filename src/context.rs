use crate::params::{SPX_N, SPX_FORS_TREES, SPX_WOTS_LEN};
use crate::fors::ForsGenLeafInfo;
use crate::wotsx1::LeafInfoX1;

pub struct SpxCtx {
  pub pub_seed: [u8; SPX_N],
  pub sk_seed: [u8; SPX_N],
  
  #[cfg(feature="sha2")]
  pub state_seeded: [u8; 40],
  
  #[cfg(feature="sha512")]
  pub state_seeded: [u8; 72],
  
  #[cfg(feature="haraka")]
  pub tweaked512_rc64: [[u64; 8]; 10],
  #[cfg(feature="haraka")]
  pub tweaked256_rc32: [[u32; 8]; 10],
}

impl Default for SpxCtx {
  fn default() -> Self {
      Self { 
        pub_seed: [0u8; SPX_N], 
        sk_seed: [0u8; SPX_N],
        #[cfg(feature="sha2")]
        state_seeded: [0u8; 40],
        #[cfg(feature="sha512")]
        state_seeded: [0u8; 72], 
        #[cfg(feature="haraka")]
        tweaked512_rc64: [[0u64; 8]; 10], 
        #[cfg(feature="haraka")]
        tweaked256_rc32: [[0u32; 8]; 10] 
    }
  }
}

pub enum Info {
  Fors(ForsGenLeafInfo),
  Wots(LeafInfoX1)
}

pub struct Inblocks;

impl Inblocks {
  pub const ONE: usize = 1;
  pub const TWO: usize = 2;
  pub const WOTS: usize = SPX_WOTS_LEN;
  pub const FORS: usize = SPX_FORS_TREES;
}