use crate::params::SPX_N;

/// Sphincs context
pub struct SpxCtx {
  pub pub_seed: [u8; SPX_N],
  pub sk_seed: [u8; SPX_N],
  
  #[cfg(feature="sha2")]
  pub state_seeded: [u8; 40],
  
  #[cfg(all(feature="sha2", not(any(feature="f128", feature="s128"))))]
  pub state_seeded_512: [u8; 72],
  
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

        #[cfg(all(feature="sha2", not(any(feature="f128", feature="s128"))))]
        state_seeded_512: [0u8; 72],

        #[cfg(feature="haraka")]
        tweaked512_rc64: [[0u64; 8]; 10], 

        #[cfg(feature="haraka")]
        tweaked256_rc32: [[0u32; 8]; 10] 
    }
  }
}
