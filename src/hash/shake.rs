use crate::context::SpxCtx;
use crate::utils::*;
use crate::params::*;
use crate::fips202::*;

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
pub fn initialize_hash_function(ctx: &mut SpxCtx)
{
  ()
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx, addr: &mut[u32])
{
  let mut idx = SPX_N; 
  let mut buf = [0u8; 2*SPX_N + SPX_ADDR_BYTES];
  buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..idx + SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  idx += SPX_ADDR_BYTES;
  buf[idx..idx + SPX_N].copy_from_slice(&ctx.sk_seed);

  shake256(out, SPX_N, &buf, 2*SPX_N + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
pub fn gen_message_random(
  r: &mut[u8], sk_prf: &[u8], optrand: &[u8], m: &[u8], mlen: usize, ctx: &SpxCtx
)
{
  let mut s_inc = [0u64; 26];
  shake256_inc_absorb(&mut s_inc, sk_prf, SPX_N);
  shake256_inc_absorb(&mut s_inc, optrand, SPX_N);
  shake256_inc_absorb(&mut s_inc, m, mlen as usize);
  shake256_inc_finalize(&mut s_inc);
  shake256_inc_squeeze(R, SPX_N, &mut s_inc);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
pub fn hash_message(
  digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, R: &[u8], pk: &[u8], 
  m: &[u8], mlen: usize, _ctx: &SpxCtx
)
{

  let mut buf = [0u8; SPX_DGST_BYTES];
  let mut idx  = 0;
  let mut s_inc = [0u64; 26];

  shake256_inc_absorb(&mut s_inc, R, SPX_N);
  shake256_inc_absorb(&mut s_inc, pk, SPX_PK_BYTES);
  shake256_inc_absorb(&mut s_inc, m, mlen as usize);
  shake256_inc_finalize(&mut s_inc);
  shake256_inc_squeeze(&mut buf, SPX_DGST_BYTES, &mut s_inc);

  digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
  idx += SPX_FORS_MSG_BYTES;

  *tree = bytes_to_ull(&buf[idx..], SPX_TREE_BYTES);
  *tree &= !0 >> (64 - SPX_TREE_BITS);
  idx += SPX_TREE_BYTES;

  *leaf_idx = bytes_to_ull(&buf[idx..], SPX_LEAF_BYTES) as u32;
  *leaf_idx &= !0 >> (32 - SPX_LEAF_BITS);
}

fn shake128_inc_absorb(s: &mut [u64], input: &[u8], inlen: usize) {
  keccak_inc_absorb(s, SHAKE128_RATE, input, inlen);
}

fn shake128_inc_finalize(s: &mut[u64]) {
  keccak_inc_finalize(s, SHAKE128_RATE, 0x1F);
}

fn shake128_inc_squeeze(output: &mut[u8], outlen: usize, s_inc: &mut[u64]) {
  keccak_inc_squeeze(output, outlen, s_inc, SHAKE128_RATE);
}


fn shake256_inc_absorb(s: &mut [u64], input: &[u8], inlen: usize) {
  keccak_inc_absorb(s, SHAKE256_RATE, input, inlen);
}

fn shake256_inc_finalize(s: &mut[u64]) {
  keccak_inc_finalize(s, SHAKE256_RATE, 0x1F);
}

fn shake256_inc_squeeze(output: &mut[u8], outlen: usize, s_inc: &mut[u64]) {
  keccak_inc_squeeze(output, outlen, s_inc, SHAKE256_RATE);
}