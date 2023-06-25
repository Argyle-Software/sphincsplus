use pqc_sphincsplus::*;


#[test]
#[cfg(all(
  any(feature = "haraka", feature = "shake", feature = "sha2"),
  any(feature = "f128", feature = "f192", feature = "f256",
      feature = "s128", feature = "s192", feature = "s256"),
  any(feature = "robust", feature = "simple") 
))]
fn valid_sig() {
  let keys = keypair();
  let msg = [27u8; 64];
  let sig = sign(&msg, &keys);
  let sig_verify = verify(&sig, &msg, &keys);
  assert!(sig_verify.is_ok());
}


#[test]
#[cfg(all(
  any(feature = "haraka", feature = "shake", feature = "sha2"),
  any(feature = "f128", feature = "f192", feature = "f256",
      feature = "s128", feature = "s192", feature = "s256"),
  any(feature = "robust", feature = "simple") 
))]
fn invalid_sig() {
  let keys = keypair();
  let msg = [27u8; 64];
  let mut sig = sign(&msg, &keys);
  sig[..4].copy_from_slice(&[255; 4]);
  let sig_verify = verify(&sig, &msg, &keys);
  assert!(sig_verify.is_err());
}