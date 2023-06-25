use crate::context::SpxCtx;
use crate::utils::*;
use crate::thash::*;
use crate::address::*;
use crate::params::*;

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/// Computes the chaining function.
/// out and in have to be n-byte arrays.
/// Interprets in as start-th value of the chain.
/// addr has to contain the address of the chain.
pub fn gen_chain(
  out: &mut[u8], input: &[u8], start: u32, 
  steps: u32, ctx: &SpxCtx, addr: &mut[u32]
)
{
  out[..SPX_N].copy_from_slice(&input[..SPX_N]);

  // Iterate 'steps' calls to the hash function.
  let mut i = start;
  while i < (start+steps) && i < SPX_WOTS_W as u32 {
    set_hash_addr(addr, i);
    thash::<1>(out, None, ctx, addr);
    i += 1;
  }
}

/// base_w algorithm as described in draft.
/// Interprets an array of bytes as integers in base w.
/// This only works when log_w is a divisor of 8.
pub fn base_w(output: &mut[u32], out_len: u32, input: &[u8])
{
  let mut idx = 0;
  let mut out = 0;
  let mut total = 0u8;
  let mut bits = 0;

  for _ in 0..out_len {
    if bits == 0 {
      total = input[idx];
      idx += 1;
      bits += 8;
    }
    bits -= SPX_WOTS_LOGW;
    output[out] = (((total >> bits) & (SPX_WOTS_W - 1) as u8)) as u32;
    out += 1;
  }
}

/// Computes the WOTS+ checksum over a message (in base_w).
pub fn wots_checksum(csum_base_w: &mut[u32])
{
  let mut csum =  0u32;
  let mut csum_bytes = [0u8; (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];

  // Compute checksum.
  for i in 0..SPX_WOTS_LEN1  {
    csum += SPX_WOTS_W as u32 - 1 - csum_base_w[i] as u32;
  }

  // Convert checksum to base_w.
  // Make sure expected empty zero bits are the least significant bits.
  csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
  let csum_sizeof = csum_bytes.len();
  ull_to_bytes(&mut csum_bytes, csum_sizeof, csum as u64);
  base_w(
    &mut csum_base_w[SPX_WOTS_LEN1..], SPX_WOTS_LEN2 as u32, &csum_bytes
  );
}

/// Takes a message and derives the matching chain lengths.
pub fn chain_lengths(lengths: &mut[u32], msg: &[u8])
{
  base_w(lengths, SPX_WOTS_LEN1 as u32, msg);
  wots_checksum(lengths);
}

/// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
/// Writes the computed public key to 'pk'.
pub fn wots_pk_from_sig(
  pk: &mut[u8], sig: &[u8], msg: &[u8], ctx: &SpxCtx, addr: &mut[u32]
)
{
  let mut lengths = [0u32;  SPX_WOTS_LEN];
  chain_lengths(&mut lengths, msg);

  for i in 0..SPX_WOTS_LEN  {
    set_chain_addr(addr, i as u32);
    let steps = SPX_WOTS_W as u32 - 1 - lengths[i];
    gen_chain(&mut pk[i*SPX_N..], &sig[i*SPX_N..], lengths[i], steps, ctx, addr);
  }
}
