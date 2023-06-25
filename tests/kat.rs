use std::path::PathBuf;
use pqc_core::{load, Kat};
use pqc_sphincsplus::*;

// Only use a subset of test vectors, usage: 
// SPHINCS_FAST_TEST=1 cargo test --release
const FAST: bool = option_env!("SPHINCS_FAST_TEST").is_some();
const SHORT_RUN: usize = 3;

fn filename() -> String {
  format!("PQCsignKAT_sphincs-{}-{}-{}.rsp", HASH, MODE, THASH)
}

fn buf1() -> String {
  format!("SeedBufferKeygen_{}", CRYPTO_SEEDBYTES)
}

fn buf2() -> String {
  format!("SeedBufferSign_{}", CRYPTO_SEEDBYTES / 3)
}

fn parse_files(buf_file: Option<&str>) -> (Vec<Kat>, Vec<Vec<u8>>) {
  let mut basepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let kats = load::kats(&mut basepath.clone(), &filename());
  let mut bufs = Vec::new();
  if let Some(path) = buf_file {
    bufs = load::bufs(&mut basepath, path);
  }
  (kats, bufs)
}

#[test]
#[cfg(feature = "KAT")]
pub fn keygen() {
  let (kats, bufs) = parse_files(Some(&buf1()));
  for (i, kat) in kats.iter().enumerate() {
    let pk = kat.pk.clone();
    let sk = kat.sk.clone();
    let mut pk2 = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk2 = [0u8; CRYPTO_SECRETKEYBYTES];
    
    crypto_sign_keypair(&mut pk2, &mut sk2,  Some(&bufs[i]));
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
    
    if FAST && i == SHORT_RUN {
      break
    }
  }
}

#[test]
#[cfg(feature = "KAT")]
pub fn sign() {
  let (kats, bufs) = parse_files(Some(&buf2()));
  // kats.par_iter().enumerate().for_each(|(i, kat)|
  for (i, kat) in kats.iter().enumerate() 
  {
    let sm = kat.sm.clone();
    let msg = kat.msg.clone();
    let sk = kat.sk.clone();
    let mut sig = vec![0u8; CRYPTO_BYTES];
    
    crypto_sign_signature(&mut sig, &msg, &sk, Some(&bufs[i]));
    assert_eq!(sm[..CRYPTO_BYTES], sig);
    
    if FAST && i == SHORT_RUN {
      return
    }
  }
}

#[test]
#[cfg(feature = "KAT")]
pub fn sign_open() {
  let (kats, _) = parse_files(None);
  for (i, kat) in kats.iter().enumerate() {
    let sm = kat.sm.clone();
    let pk = kat.pk.clone();
    
    let res = crypto_sign_verify(&sm[..CRYPTO_BYTES], &sm[CRYPTO_BYTES..], &pk);
    assert!(res.is_ok());
    
    if FAST && i == SHORT_RUN {
      break
    }
  }
}
