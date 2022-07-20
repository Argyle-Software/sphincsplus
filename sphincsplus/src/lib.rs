#![feature(generic_const_exprs)]

  // #[cfg(all(
  //   any(feature = "haraka", feature = "shake", feature = "sha2"),
  //   any(feature = "f128", feature = "f192", feature = "f256",
  //       feature = "s128", feature = "s192", feature = "s256"),
  //   any(feature = "robust", feature = "simple") 
  // ))] 
  // compile_error!("Must choose from the feature set to build");

// TODO: Compile error for conflicting features to prevent misuse

mod address;
mod context;
mod fors;
mod hash;
mod merkle;
mod offsets;
mod params;
mod sign;
mod thash;
mod utils;
mod utilsx1;
mod wots;
mod wotsx1;
mod randombytes;

#[cfg(feature = "shake")] 
mod fips202;

#[cfg(any(feature = "sha2", feature = "sha512"))] 
mod sha2;

#[cfg(feature = "haraka")] 
mod haraka;

pub use params::{
  CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_SEEDBYTES
};
pub use sign::{crypto_sign_keypair, crypto_sign, crypto_sign_open};