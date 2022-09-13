//! # SPHINCS<sup>+</sup>
//!
//! A rust implementation of the SPHINCS<sup>+</sup> stateless hash-based signature scheme, 
//! which has been included in NIST's post-quantum cryptographic standard.
//! 
//! It is highly recommended to use SPHINCS<sup>+</sup> in a hybrid system alongside a 
//! traditional signature algorithm such as RSA or ed25519. 
//! 
//! ---
//! 
//! ## Usage 
//! ```no_run
//!  # use pqc_sphincsplus::*;
//!  let keys = keypair();
//!  let msg = [0u8; 32];
//!  let sig = sign(&msg, &keys);
//!  let sig_verify = verify(&sig, &msg, &keys);
//!  assert!(sig_verify.is_ok());
//! ```
//! To compile this library needs one from each of the following categories to be 
//! enabled, using more than one from each group will result in a compile error. 
//! 
//! The security levels target 128, 192 and 256 bit equivalents, corresponding to NIST
//! levels 1,3,5 respectively. They are also separated into **fast** (f) and **small** 
//! (s) subtypes, which make the tradeoff between either quicker signing or smaller 
//! signatures sizes.
//! 
//! 
//! * ### Hash
//!   * `haraka`
//!   * `sha2`
//!   * `shake`
//! 
//! * ### Security Level
//!   * `f128`
//!   * `f192`
//!   * `f256`
//!   * `s128`
//!   * `s192`
//!   * `s256`
//! * ### TreeHash
//!   * `simple`
//!   * `robust`
//! 
//! For example: 
//! 
//! ```toml
//! [dependencies]
//! pqc_sphincsplus = {version = "0.1.0", features = ["haraka", "f128", "simple"]}
//! ```
//! 
//! A comparison of the different security levels is below.
//! 
//! 
//! |               | n  | h  | d  | log(t) | k  |  w  | bit security | pk bytes | sk bytes | sig bytes |
//! | :------------ | -: | -: | -: | -----: | -: | --: | -----------: | -------: | -------: | --------: |
//! | SPHINCS+-128s | 16 | 63 |  7 |     12 | 14 |  16 |          133 |       32 |       64 |     7,856 |
//! | SPHINCS+-128f | 16 | 66 | 22 |      6 | 33 |  16 |          128 |       32 |       64 |    17,088 |
//! | SPHINCS+-192s | 24 | 63 |  7 |     14 | 17 |  16 |          193 |       48 |       96 |    16,224 |
//! | SPHINCS+-192f | 24 | 66 | 22 |      8 | 33 |  16 |          194 |       48 |       96 |    35,664 |
//! | SPHINCS+-256s | 32 | 64 |  8 |     14 | 22 |  16 |          255 |       64 |      128 |    29,792 |
//! | SPHINCS+-256f | 32 | 68 | 17 |      9 | 35 |  16 |          255 |       64 |      128 |    49,856 |
//! 


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

mod api;
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

pub use api::*;

#[cfg(feature = "KAT")]
pub use sign::*;

pub use params::{
  CRYPTO_BYTES, 
  CRYPTO_PUBLICKEYBYTES, 
  CRYPTO_SECRETKEYBYTES, 
  CRYPTO_SEEDBYTES,
  HASH,
  MODE,
  THASH
};
