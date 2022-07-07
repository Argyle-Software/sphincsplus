#[cfg(all(feature = "haraka", feature = "robust"))]
mod thash_haraka_robust;
#[cfg(all(feature = "haraka", feature = "simple"))]
mod thash_haraka_simple;
#[cfg(all(feature = "sha2", feature = "robust"))]
mod thash_sha2_robust;
#[cfg(all(feature = "sha2", feature = "simple"))]
mod thash_sha2_simple;
#[cfg(all(feature = "shake", feature = "robust"))]
mod thash_shake_robust;
#[cfg(all(feature = "shake", feature = "simple"))]
mod thash_shake_simple;


#[cfg(all(feature = "haraka", feature = "simple"))]
pub use thash_haraka_simple::*; 

#[cfg(all(feature = "haraka", feature = "robust"))]
pub use thash_haraka_robust::*; 

#[cfg(all(feature = "sha2", feature = "simple"))]
pub use thash_sha2_simple::*; 

#[cfg(all(feature = "sha2", feature = "robust"))]
pub use thash_sha2_robust::*; 

#[cfg(all(feature = "shake", feature = "simple"))]
pub use thash_shake_simple::*; 

#[cfg(all(feature = "shake", feature = "robust"))]
pub use thash_shake_robust::*; 