# SPHINCS<sup>+</sup>
[![Build Status](https://github.com/Argyle-Software/kyber/actions/workflows/ci.yml/badge.svg)](https://github.com/Argyle-Software/kyber/actions)
[![Crates](https://img.shields.io/crates/v/pqc-kyber)](https://crates.io/crates/pqc-kyber)
[![NPM](https://img.shields.io/npm/v/pqc-kyber)](https://www.npmjs.com/package/pqc-kyber)
[![dependency status](https://deps.rs/repo/github/Argyle-Software/kyber/status.svg)](https://deps.rs/repo/github/Argyle-Software/kyber)
[![License](https://img.shields.io/crates/l/pqc_kyber)](https://github.com/Argyle-Software/kyber/blob/master/LICENSE-MIT)

A rust implementation of the SPHINCS<sup>+</sup> stateless hash-based signature scheme, which has been included in NIST's post-quantum cryptographic standard.



See the [**features**](#features) section for different options regarding security levels and modes of operation.

It is recommended to use SPHINCS<sup>+</sup> in a hybrid system alongside a traditional signature algorithm such as ed25519. 

Please also read the [**security considerations**](#security-considerations) before use.

---

## Usage 

In `Cargo.toml`:

```toml
[dependencies]
pqc_kyber = "0.2.1"
```

---

## Errors

---

## Features

To compile this library needs one from each of the following categories to be enabled: 

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


For example: 

```toml
[dependencies]
pqc_sphincsplus = {version = "0.1.0", features = ["haraka", "f128", "simple"]}
```


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

## Benchmarking

Uses criterion for benchmarking. If you have GNUPlot installed it will generate statistical graphs in `target/criterion/`.

See the [benchmarking readme](./benches/readme.md) for information on correct usage.

---

## Fuzzing

The fuzzing suite uses honggfuzz, installation and instructions are on the [fuzzing](./fuzz/readme.md) page. 

---

## WebAssembly



---

## Security Considerations 


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


