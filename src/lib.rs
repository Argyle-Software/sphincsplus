#![feature(generic_const_exprs)]

mod address;
mod context;
#[cfg(feature = "shake")]
mod fips202;
mod fors;
#[cfg(feature = "haraka")]
mod haraka;
mod hash;
// mod hash_haraka;
// mod hash_sha2;
// mod hash_shake;
mod merkle;
mod offsets;
mod params;
#[cfg(any(feature = "sha2", feature = "sha512"))]
mod sha2;
mod sign;
mod thash;
mod utils;
mod utilsx1;
mod wots;
mod wotsx1;
mod randombytes;

pub use params::{
  CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_SEEDBYTES
};
pub use sign::{crypto_sign_keypair, crypto_sign, crypto_sign_open};