use crate::{
  params::*,
  utils::*,
  context::SpxCtx
};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
pub fn thash<const N: usize>(
  out: &mut[u8], input: Option<&[u8]>,  ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_ADDR_BYTES + (N + 1) * SPX_N]:, [(); N * SPX_N]: Sized
{
  const N_PLUS_ADDR: usize = SPX_N + SPX_ADDR_BYTES; 
  let mut buf = [0u8; SPX_ADDR_BYTES + (N + 1) * SPX_N];
  let mut bitmask = [0u8; N * SPX_N];
  
  buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
  buf[SPX_N..SPX_N+32].copy_from_slice(&address_to_bytes(addr));

  let mut hasher = Shake256::default();
  hasher.update(&buf[..N_PLUS_ADDR]); 
  let mut reader = hasher.finalize_xof();
  reader.read(&mut bitmask[..N * SPX_N]);

  for i in 0..N * SPX_N {
    buf[N_PLUS_ADDR + i] = input.unwrap_or(out)[i] ^ bitmask[i];
  }

  hasher = Shake256::default();
  hasher.update(&buf[..N_PLUS_ADDR + N*SPX_N]);
  let mut reader = hasher.finalize_xof();
  reader.read(&mut out[..SPX_N]);
}