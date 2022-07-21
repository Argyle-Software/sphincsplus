use crate::{
  params::*,
  utils::*,
  context::SpxCtx
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
pub fn thash<const N: usize>(
  out: &mut[u8], input: Option<&[u8]>, ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut idx = SPX_N; 
  let mut buf = [0u8; SPX_N + SPX_ADDR_BYTES + N * SPX_N ];
  buf[..idx].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..idx + SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
  idx += SPX_ADDR_BYTES;
  buf[idx..idx + N*SPX_N].copy_from_slice(&input.unwrap_or(out)[..N*SPX_N]);

  let mut hasher = Shake256::default();
  hasher.update(&buf[..SPX_N + SPX_ADDR_BYTES + N*SPX_N]); 
  let mut reader = hasher.finalize_xof();
  reader.read(&mut out[..SPX_N]);
}