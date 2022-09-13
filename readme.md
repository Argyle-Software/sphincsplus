# SPHINCS<sup>+</sup>
[![Build Status](https://github.com/Argyle-Software/pqc_sphincsplus/actions/workflows/ci.yml/badge.svg)](https://github.com/Argyle-Software/pqc_sphincsplus/actions)
[![Crates](https://img.shields.io/crates/v/pqc_sphincsplus)](https://crates.io/crates/pqc_sphincsplus)
[![License](https://img.shields.io/crates/l/pqc_sphincsplus)](https://github.com/Argyle-Software/pqc_sphincsplus/blob/master/LICENSE-MIT)


A rust implementation of the SPHINCS<sup>+</sup> stateless hash-based signature scheme, 
which has been included in NIST's post-quantum cryptographic standard.


It is highly recommended to use SPHINCS<sup>+</sup> in a hybrid system alongside a 
traditional signature algorithm such as RSA or ed25519. 

---

## Usage

In Cargo.toml

```toml
[dependencies]
pqc_sphincsplus = {version = "0.1.0", features = ["haraka", "f128", "simple"]}
```

```rust
 let keys = keypair();
 let msg = [0u8; 32];
 let sig = sign(&msg, &keys);
 let sig_verify = verify(&sig, &msg, &keys);
 assert(sig_verify.is_ok());
```
To compile this library needs one from each of the following categories to be 
enabled, using more than one from each group will result in a compile error. 

The security levels target 128, 192 and 256 bit equivalents, corresponding to NIST
levels 1,3,5 respectively. They are also separated into **fast** (f) and **small** (s) 
subtypes, which make the tradeoff between either quicker signing or smaller signatures sizes.

SPHINCS+ introduces a split of the signature schemes into a simple and a robust 
variant for each choice of hash function. The robust variant is from the original
NIST PQC first round submission and comes with all the conservative security 
guarantees given before. The simple variants are pure random oracle instantiations. 
These instantiations achieve about a factor three speed-up compared to the robust 
counterparts. This comes at the cost of a purely heuristic security argument.

* ### Hash
  * `haraka`
  * `sha2`
  * `shake`

* ### Security Level
  * `f128`
  * `f192`
  * `f256`
  * `s128`
  * `s192`
  * `s256`
* ### TreeHash
  * `simple`
  * `robust`


A comparison of the different security levels is below.

|               | n  | h  | d  | log(t) | k  |  w  | bit security | pk bytes | sk bytes | sig bytes |
| :------------ | -: | -: | -: | -----: | -: | --: | -----------: | -------: | -------: | --------: |
| SPHINCS+-128s | 16 | 63 |  7 |     12 | 14 |  16 |          133 |       32 |       64 |     7,856 |
| SPHINCS+-128f | 16 | 66 | 22 |      6 | 33 |  16 |          128 |       32 |       64 |    17,088 |
| SPHINCS+-192s | 24 | 63 |  7 |     14 | 17 |  16 |          193 |       48 |       96 |    16,224 |
| SPHINCS+-192f | 24 | 66 | 22 |      8 | 33 |  16 |          194 |       48 |       96 |    35,664 |
| SPHINCS+-256s | 32 | 64 |  8 |     14 | 22 |  16 |          255 |       64 |      128 |    29,792 |
| SPHINCS+-256f | 32 | 68 | 17 |      9 | 35 |  16 |          255 |       64 |      128 |    49,856 |

---

## Testing

The [run_all_tests](tests/run_all_tests.sh) script will traverse all valid feature sets by running a matrix of the security levels and variants.

The test vectors are pre-built and located in the [KAT folder](./tests/KAT/). There is a bash script to generate these locally. 

See the [testing readme](./tests/readme.md) for more comprehensive info.

---

## About

The official website: https://sphincs.org/

The Sphincs+ Team: 

* Jean-Philippe Aumasson
* Daniel J. Bernstein 
* Ward Beullens
* Christoph Dobraunig
* Maria Eichlseder
* Scott Fluhrer
* Stefan-Lukas Gazdag
* Andreas Hülsing
* Panos Kampanakis
* Stefan Kölbl
* Tanja Lange
* Martin M. Lauridsen
* Florian Mendel
* Ruben Niederhagen
* Christian Rechberger
* Joost Rijneveld
* Peter Schwabe
* Bas Westerbaan
---

### Contributing 

For pull requests create a feature fork and submit it to the development branch. 
By contributing to this crate you agree for it to be dual licensed under MIT/Apache 2.0 

More information is available on the [contributing page](./contributing.md)


