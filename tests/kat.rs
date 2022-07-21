use std::path::PathBuf;
use pqc_core::{load, Kat};
use pqc_sphincsplus::*;
use rayon::prelude::*;

// Only do a subset of test vectors, usage: 
// QUICK_TEST=1 cargo test --release
const QUICK: bool = option_env!("QUICK_TEST").is_some();
const SHORT_RUN: usize = 10;

const BUF1_LEN: usize = CRYPTO_SEEDBYTES;
const BUF2_LEN: usize = CRYPTO_SEEDBYTES / 3;


fn filename() -> String {
  format!("PQCsignKAT_sphincs-{}-{}-{}.rsp", HASH, MODE, THASH)
}

fn buf1() -> String {
  format!("SeedBufferKeygen_{}", BUF1_LEN)
}

fn buf2() -> String {
  format!("SeedBufferSign_{}", BUF2_LEN)
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
    
    if QUICK && i == SHORT_RUN {
      break
    }
  }
}

#[test]
pub fn sign() {
  let (kats, bufs) = parse_files(Some(&buf2()));
  // TODO: Check Rayon iter performing worse?
  // kats.par_iter().enumerate().for_each(|(i, kat)| 
  for (i, kat) in kats.iter().enumerate()
  {
    let sm = kat.sm.clone();
    let smlen = kat.smlen;
    let msg = kat.msg.clone();
    let mlen = kat.mlen;
    let sk = kat.sk.clone();
    let mut sm2 = vec![0u8; CRYPTO_BYTES + mlen];
    let mut smlen2 = 0usize;
    
    crypto_sign(&mut sm2, &mut smlen2, &msg, mlen, &sk, Some(&bufs[i]));
    assert_eq!(sm, sm2);
    assert_eq!(smlen, smlen2);
    
    if QUICK && i == SHORT_RUN {
      return
    }
  }
  // });
}

#[test]
pub fn sign_open() {
  let (kats, _) = parse_files(None);
  for (i, kat) in kats.iter().enumerate() {
    let mut sm = kat.sm.clone();
    let smlen = kat.smlen;
    let msg = kat.msg.clone();
    let mut mlen = kat.mlen;
    let pk = kat.pk.clone();
    let mut msg2 = vec![0u8; CRYPTO_BYTES + mlen as usize];

    crypto_sign_open(&mut msg2, &mut mlen, &mut sm, smlen, &pk);
    assert_eq!(msg, msg2[..mlen as usize]);
    
    if QUICK && i == SHORT_RUN {
      break
    }
  }
}
