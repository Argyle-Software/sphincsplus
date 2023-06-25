# SPHINCS<sup>+</sup>
[![Build Status](https://github.com/Argyle-Software/sphincsplus/actions/workflows/ci.yml/badge.svg)](https://github.com/Argyle-Software/sphincsplus/actions)
[![Crates](https://img.shields.io/crates/v/pqc_sphincsplus)](https://crates.io/crates/pqc_sphincsplus)
[![License](https://img.shields.io/crates/l/pqc_sphincsplus)](https://github.com/Argyle-Software/sphincsplus/blob/master/LICENSE-MIT)


A rust implementation of the SPHINCS<sup>+</sup> stateless hash-based signature scheme, 
which has been included in NIST's post-quantum cryptographic standard.


It is highly recommended to use SPHINCS<sup>+</sup> in a hybrid system alongside a 
traditional signature algorithm such as RSA or Ed25519. 

---

## Usage

To compile, this library needs one from each of the below three categories (Hash, Security Level, Treehash) needs to be 
enabled, using more than one from each group will result in a compile error.

For example in Cargo.toml:

```toml
[dependencies]
pqc_sphincsplus = {version = "0.1.0", features = ["haraka", "f128", "simple"]}
```

To generate a keypair and sign some arbitrary bytes:

```rust
 let keys = keypair();
 let some_msg = [1u8; 42];
 let sig = sign(&some_msg, &keys);
 let sig_verify = verify(&sig, &some_msg, &keys);
 assert(sig_verify.is_ok());
```

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


A comparison of the different security levels:

|               	| bit security 	| public key bytes 	| secret key bytes 	| signature bytes 	|
|---------------	|-------------:	|---------:	|---------:	|----------:	|
| SPHINCS+-128s 	|          133 	|       32 	|       64 	|     7,856 	|
| SPHINCS+-128f 	|          128 	|       32 	|       64 	|    17,088 	|
| SPHINCS+-192s 	|          193 	|       48 	|       96 	|    16,224 	|
| SPHINCS+-192f 	|          194 	|       48 	|       96 	|    35,664 	|
| SPHINCS+-256s 	|          255 	|       64 	|      128 	|    29,792 	|
| SPHINCS+-256f 	|          255 	|       64 	|      128 	|    49,856 	|

---

## Testing

The [test_matrix](tests/test_matrix.sh) script will traverse all valid feature sets.

The test vectors are pre-built and located in the [KAT folder](./tests/KAT/). There is a bash script to generate these locally. 

See the [testing readme](./tests/readme.md) for more comprehensive info.

---

### Contributing 

For pull requests create a feature fork and submit it to the development branch. 
By contributing to this crate you agree for it to be dual licensed under MIT/Apache 2.0 

More information is available on the [contributing page](./contributing.md)

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
