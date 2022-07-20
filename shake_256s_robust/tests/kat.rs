use std::path::PathBuf;
use pqc_core::load;
use sphincs_shake_256s_robust::*;

const BUF1: &str = "SeedBufferKeygen";
const BUF2: &str = "SeedBufferSign";

fn filename() -> String {
  format!("PQCsignKAT_{}.rsp", env!("CARGO_PKG_NAME").replace("_", "-"))
}

#[test]
pub fn keygen() {
  let mut basepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let kats = load::kats(&mut basepath.clone(), &filename());
  let bufs = load::bufs(&mut basepath, BUF1);
  for (i, kat) in kats.iter().enumerate() {
    let pk = kat.pk.clone();
    let sk = kat.sk.clone();
    let mut pk2 = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut sk2 = [0u8; CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(&mut pk2, &mut sk2,  Some(&bufs[i]));
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
  }
}

#[test]
pub fn sign() {
  let mut basepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let kats = load::kats(&mut basepath.clone(), &filename());
  let bufs = load::bufs(&mut basepath, BUF2);
  for (i, kat) in kats.iter().enumerate() {
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
  }
}

#[test]
pub fn sign_open() {
  let mut basepath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let kats = load::kats(&mut basepath, &filename());
  for kat in kats {
    let mut sm = kat.sm.clone();
    let smlen = kat.smlen;
    let msg = kat.msg.clone();
    let mut mlen = kat.mlen;
    let pk = kat.pk.clone();
    let mut msg2 = vec![0u8; CRYPTO_BYTES + mlen as usize];
    crypto_sign_open(&mut msg2, &mut mlen, &mut sm, smlen, &pk);
    assert_eq!(msg, msg2[..mlen as usize]);
  }
}
