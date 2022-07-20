use crate::context::SpxCtx;
use crate::params::*;
use crate::utils::*;
use crate::fips202::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash<const N: usize>(
  out: &mut[u8], input: &[u8],  ctx: &SpxCtx, addr: &[u32; 8]
)
  where [(); SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut buf = [0u8; SPX_ADDR_BYTES + N * SPX_N];
  let mut bitmask = [0u8; N * SPX_N];

  buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
  &buf[SPX_N..].copy_from_slice(&address_to_bytes(addr));

  shake256(&mut bitmask, N * SPX_N, &buf, SPX_N + SPX_ADDR_BYTES);

  for i in 0..N * SPX_N {
    buf[SPX_N + SPX_ADDR_BYTES + i] = input[i] ^ bitmask[i];
  }

  shake256(out, SPX_N, &buf, SPX_N + SPX_ADDR_BYTES + N*SPX_N);
}


pub fn thash_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &[u32; 8]
)
  where [(); SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut buf = [0u8; SPX_ADDR_BYTES + N * SPX_N];
  let mut bitmask = [0u8; N * SPX_N];

  buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
  &buf[SPX_N..].copy_from_slice(&address_to_bytes(addr));

  shake256(&mut bitmask, N * SPX_N, &buf, SPX_N + SPX_ADDR_BYTES);

  for i in 0..N * SPX_N {
    buf[SPX_N + SPX_ADDR_BYTES + i] = out[i] ^ bitmask[i];
  }

  shake256(out, SPX_N, &buf, SPX_N + SPX_ADDR_BYTES + N*SPX_N);
}