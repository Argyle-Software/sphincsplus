#[cfg(feature = "haraka")]
mod hash_haraka; 

#[cfg(feature = "sha2")]
mod hash_sha2; 

#[cfg(feature = "shake")]
mod hash_shake;

#[cfg(feature = "haraka")]
pub use hash_haraka::*; 

#[cfg(feature = "sha2")]
pub use hash_sha2::*; 

#[cfg(feature = "shake")]
pub use hash_shake::*; 
