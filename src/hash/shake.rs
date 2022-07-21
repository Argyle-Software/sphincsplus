use crate::context::SpxCtx;
use crate::utils::*;
use crate::params::*;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// For SHAKE256, there is no immediate reason to initialize at the start,
/// so this function is an empty operation.
pub fn initialize_hash_function(_ctx: &mut SpxCtx) { () }

///Computes PRF(pk_seed, sk_seed, addr)
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx, addr: &mut[u32])
{
  let mut idx = SPX_N; 
  let mut buf = [0u8; 2*SPX_N + SPX_ADDR_BYTES];
  buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..idx + SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  idx += SPX_ADDR_BYTES;
  buf[idx..idx + SPX_N].copy_from_slice(&ctx.sk_seed);

  let mut hasher = Shake256::default();
  hasher.update(&buf[..2*SPX_N + SPX_ADDR_BYTES]); 
  let mut reader = hasher.finalize_xof();
  reader.read(&mut out[..SPX_N]);
}

/// Computes the message-dependent randomness R, using a secret seed and an
/// optional randomization value as well as the message.
pub fn gen_message_random(
  r: &mut[u8], sk_prf: &[u8], optrand: &[u8], 
  m: &[u8], mlen: usize, _ctx: &SpxCtx
)
{
  let mut hasher = Shake256::default();
  hasher.update(&sk_prf[..SPX_N]); 
  hasher.update(&optrand[..SPX_N]);
  hasher.update(&m[..mlen as usize]);
  let mut reader = hasher.finalize_xof();
  reader.read(&mut r[..SPX_N]);
}

/// Computes the message hash using R, the public key, and the message.
/// Outputs the message digest and the index of the leaf. The index is split in
/// the tree index and the leaf index, for convenient copying to an address.
pub fn hash_message(
  digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, 
  r: &[u8], pk: &[u8], m: &[u8], mlen: usize, _ctx: &SpxCtx
)
{
  let mut buf = [0u8; SPX_DGST_BYTES];
  let mut idx  = 0;

  let mut hasher = Shake256::default();
  hasher.update(&r[..SPX_N]); 
  hasher.update(&pk[..SPX_PK_BYTES]);
  hasher.update(&m[..mlen as usize]);
  let mut reader = hasher.finalize_xof();
  reader.read(&mut buf[..SPX_DGST_BYTES]);

  digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
  idx += SPX_FORS_MSG_BYTES;

  *tree = bytes_to_ull(&buf[idx..], SPX_TREE_BYTES);
  *tree &= !0 >> (64 - SPX_TREE_BITS);
  idx += SPX_TREE_BYTES;

  *leaf_idx = bytes_to_ull(&buf[idx..], SPX_LEAF_BYTES) as u32;
  *leaf_idx &= !0 >> (32 - SPX_LEAF_BITS);
}
