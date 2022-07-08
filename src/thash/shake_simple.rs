
use crate::context::SpxCtx;
use crate::params::*;
use crate::utils::*;

use crate::fips202::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash<const N: usize>(
  out: &mut[u8], input: &[u8], ctx: &SpxCtx, addr: &mut [u32; 8]
)
  where [(); SPX_N + SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut idx = SPX_N; 
  let mut buf = [0u8; SPX_N + SPX_ADDR_BYTES + N * SPX_N ];
  buf[..idx].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..idx + SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  idx += SPX_ADDR_BYTES;
  buf[idx..idx + N*SPX_N].copy_from_slice(&input[..N*SPX_N]);

  shake256(out, SPX_N, &buf, SPX_N + SPX_ADDR_BYTES + N*SPX_N);
}


/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &mut [u32; 8]
)
  where [(); SPX_N + SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut idx = SPX_N; 
  let mut buf = [0u8; SPX_N + SPX_ADDR_BYTES + N * SPX_N ];
  buf[..idx].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..idx + SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  idx += SPX_ADDR_BYTES;
  buf[idx..idx + N*SPX_N].copy_from_slice(&out[..N*SPX_N]);

  shake256(out, SPX_N, &buf, SPX_N + SPX_ADDR_BYTES + N*SPX_N);
}