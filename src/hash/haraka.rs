use crate::utils::*;
use crate::params::*;
use crate::haraka::*;
use crate::context::SpxCtx;

pub fn initialize_hash_function(ctx: &mut SpxCtx)
{
  tweak_constants(ctx);
}

/// Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx, addr: &mut[u32])
{
  // Since SPX_N may be smaller than 32, we need temporary buffers.
  let mut outbuf = [0u8; 32];
  let mut buf = [0u8; 64];

  buf[..SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  buf[SPX_ADDR_BYTES..SPX_ADDR_BYTES+SPX_N].copy_from_slice(&ctx.sk_seed[..SPX_N]);

  haraka512(&mut outbuf, &buf, ctx);
  out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

/// Computes the message-dependent randomness R, using a secret seed and an
/// optional randomization value as well as the message.
pub fn gen_message_random(
  r: &mut[u8], sk_prf: &[u8], optrand: &[u8], m: &[u8], mlen: usize, ctx: &SpxCtx
)
{
  let mut s_inc = [0u8; 65]; // haraka_S_inc_init
  haraka_s_inc_absorb(&mut s_inc, &sk_prf, SPX_N, ctx);
  haraka_s_inc_absorb(&mut s_inc, &optrand, SPX_N, ctx);
  haraka_s_inc_absorb(&mut s_inc, &m, mlen, ctx);
  haraka_s_inc_finalize(&mut s_inc);
  haraka_s_inc_squeeze(r, SPX_N, &mut s_inc, ctx);
}

/// Computes the message hash using R, the public key, and the message.
/// Outputs the message digest and the index of the leaf. The index is split in
/// the tree index and the leaf index, for convenient copying to an address.
pub fn hash_message(
  digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], 
  m: &[u8], mlen: usize, ctx: &SpxCtx
)
{
  let mut buf = [0u8; SPX_DGST_BYTES];
  let mut s_inc = [0u8; 65]; // haraka_S_inc_init
  let mut idx = 0usize;

  haraka_s_inc_absorb(&mut s_inc, r, SPX_N, ctx);
  // Only absorb root part of pk
  haraka_s_inc_absorb(&mut s_inc, &pk[SPX_N..], SPX_N, ctx); 
  haraka_s_inc_absorb(&mut s_inc, m, mlen, ctx);
  haraka_s_inc_finalize(&mut s_inc);
  haraka_s_inc_squeeze(&mut buf, SPX_DGST_BYTES, &mut s_inc, ctx);

  digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
  idx += SPX_FORS_MSG_BYTES;

  *tree = bytes_to_ull(&buf[idx..], SPX_TREE_BYTES);
  *tree &= !0 >> (64 - SPX_TREE_BITS);
  idx += SPX_TREE_BYTES;

  *leaf_idx = bytes_to_ull(&buf[idx..], SPX_LEAF_BYTES) as u32;
  *leaf_idx &= !0 >> (32 - SPX_LEAF_BITS);
}
