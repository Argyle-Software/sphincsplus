use std::path::PathBuf;
use pqc_core::{load, Kat};
use pqc_sphincsplus::*;
use rayon::prelude::*;

// Only do a subset of test vectors, breaks after QUICK_LEN tests, eg: 
// QUICK_TEST=1 cargo test --release
const QUICK: bool = option_env!("QUICK_TEST").is_some();
const QUICK_LEN: usize = 10;

// const BUF1_LEN: usize = CRYPTO_SEEDBYTES;
// const BUF2_LEN: usize = CRYPTO_SEEDBYTES / 3;


fn filename() -> String {
  // format!("PQCsignKAT_sphincs-{}-{}-{}.rsp", HASH, MODE, THASH)
  format!("PQCsignKAT_sphincs-haraka-128f-simple.rsp")
}

fn buf1() -> String {
  format!("SeedBufferKeygen_{}", 48 ) // BUF1_LEN
}

fn buf2() -> String {
  format!("SeedBufferSign_{}", 16) // BUF2_LEN
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

// #[test]
// pub fn keygen() {
//   let (kats, bufs) = parse_files(Some(&buf1()));
//   for (i, kat) in kats.iter().enumerate() {
//     let pk = kat.pk.clone();
//     let sk = kat.sk.clone();
//     let mut pk2 = [0u8; 32]; // CRYPTO_PUBLICKEYBYTES
//     let mut sk2 = [0u8; 64]; //CRYPTO_SECRETKEYBYTES
    
//     crypto_sign_keypair::<Haraka, F128, Simple<Haraka>>(
//       &mut pk2, &mut sk2,  Some(&bufs[i])
//     );
//     assert_eq!(pk, pk2);
//     assert_eq!(sk, sk2);
    
//     if QUICK && i == SHORT_RUN {
//       break
//     }
//   }
// }

// #[test]
// pub fn sign() {
//   let (kats, bufs) = parse_files(Some(&buf2()));
//   // TODO: Check Rayon iter performance?
//   // kats.par_iter().enumerate().for_each(|(i, kat)| 
//   for (i, kat) in kats.iter().enumerate()
//   {
//     let sm = kat.sm.clone();
//     // let smlen = kat.smlen;
//     let msg = kat.msg.clone();
//     let mlen = kat.mlen;
//     let sk = kat.sk.clone();
//     let mut sig = vec![0u8; F128::CRYPTO_BYTES];
//     // let mut smlen2 = 0usize;
    
//     crypto_sign::<Haraka, F128, Simple<Haraka>>(
//       &mut sig, &msg, &sk, Some(&bufs[i])
//     );
//     assert_eq!(sm[..F128::CRYPTO_BYTES], sig);
    
    
//     if QUICK && i == SHORT_RUN {
//       return
//     }
//   }
// }

#[test]
pub fn sign_open() {
  let (kats, _) = parse_files(None);
  for (i, kat) in kats.iter().enumerate() {
    let mut sm = kat.sm.clone();
    let smlen = kat.smlen;
    let msg = kat.msg.clone();
    let mut mlen = kat.mlen;
    let pk = kat.pk.clone();
    // let mut msg2 = vec![0u8; CRYPTO_BYTES + mlen as usize];

    let res = crypto_sign_verify::<Haraka, F128, Simple<Haraka>>(
      &sm[..F128::CRYPTO_BYTES], &msg, &pk
    );
    // assert_eq!(msg, msg2[..mlen as usize]);
    assert!(res == 0);
    if QUICK && i == QUICK_LEN {
      break
    }
  }
}
