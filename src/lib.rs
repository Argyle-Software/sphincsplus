#![no_std]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// TODO: Compile error for conflicting features to prevent misuse
#[cfg(not(all(
  any(feature = "haraka", feature = "shake", feature = "sha2"),
  any(feature = "f128", feature = "f192", feature = "f256",
      feature = "s128", feature = "s192", feature = "s256"),
  any(feature = "robust", feature = "simple") 
)))] 
compile_error!("Must choose one from each category of the feature set to build");

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

#[cfg(feature = "sha2")] 
mod sha2;

#[cfg(feature = "haraka")] 
mod haraka;

pub use sign::{
  crypto_sign_keypair, 
  crypto_sign, 
  crypto_sign_open
};

pub use params::{
  CRYPTO_BYTES, 
  CRYPTO_PUBLICKEYBYTES, 
  CRYPTO_SECRETKEYBYTES, 
  CRYPTO_SEEDBYTES,
  HASH,
  MODE,
  THASH
};
