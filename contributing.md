# Contributing 

Running tests can be slow in debug mode, you might want to alter the optimisations at the expense of opaque debugging, in `Cargo.toml`:
```toml
[profile.test]
opt-level = 3
```

By contributing to this repo you agree to it being licensed under dual MIT/Apache 2.0.

TODO list:

- [ ] Benchmarking
- [ ] BYO RNG
- [ ] RustCrypto traits
- [ ] haraka-aesni
- [ ] sha2-avx2 
- [ ] shake avx2 / shake-a64
- [ ] WASM
- [ ] Refactor
- [ ] Serde
- [ ] Zeroize

### Benchmarking

Add a benchmarking suite, preferably criterion. 


### BYO RNG

Crate hardcodes using OsRng at the moment, this should be pluggable with RngCore + CryptoRng trait bounds

### RustCrypto traits

Implement traits for Keypair, Signature and Verifier. 

https://docs.rs/signature/latest/signature/


### haraka-aesni

Handle all the marshalling into x4 types. Write the intrinsics for haraka.rs OR 
use the aes crate fixsliced implementation for the primitives.

https://github.com/sphincs/sphincsplus/tree/master/haraka-aesni

https://docs.rs/aes/latest/aes/struct.Aes256.html



### sha2-avx2

The sha2 crate already uses the intrinsics on appropriate hardware, need to get the x8 types written. 

https://github.com/sphincs/sphincsplus/tree/master/sha2-avx2


### Shake 

The sha3 crate already uses intrinsics too, need to get the x2 and x4 types written. 

https://github.com/sphincs/sphincsplus/tree/master/sha2-avx2

https://github.com/sphincs/sphincsplus/tree/master/shake-a64

### WASM

Expose the api for wasm build. 

Example: 

https://github.com/Argyle-Software/kyber/blob/master/src/wasm.rs

### Refactor

Currently the crate only can use one variant at a time due the how cargo handles 
mutually exclusive features. There's a few ways around this some far more messy 
than others. 

Including the core functions in individual crates will duplicate thousands of 
lines of code and become a nightmare to maintain. 

Work is ongoing into moving everything feature gated into generics, the downside 
to this approach is the codebase becomes messy. So while it works for the end 
user, readability and coherence go out the window. 

For example this is the function signature for signing: 

```rust
pub fn  crypto_sign(
  sig: &mut[u8], m: &[u8], sk: &[u8], seed: Option<&[u8]>
)
```

The same function using generics to set the parameters rather than features: 

```rust
pub fn  crypto_sign<H: HashMode, L: SecLevel, T: TreeHash>(
  sig: &mut[u8], m: &[u8], sk: &[u8], seed: Option<&[u8]>
)
  where [(); L::SPX_N]:,
        [(); L::SPX_DGST_BYTES]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); L::SPX_FORS_MSG_BYTES]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); L::SPX_FORS_HEIGHT]:,
        [(); L::FORS_STACK_LEN]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_FORS_TREES * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
```
This possibly can be fixed with generic associated types. A good place to start.

Check the refactor branch for progress. 


### Serde

Implement serialisation behind a feature gate using serde. 


### Zeroise

Add a zeroise feature for the secret part of a keypair