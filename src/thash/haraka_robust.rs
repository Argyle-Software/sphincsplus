use crate::{
  params::*,
  utils::*,
  haraka::*,
  context::SpxCtx
};


/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
pub fn thash<const N: usize>(
  out: &mut[u8], input: Option<&[u8]>,  ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_ADDR_BYTES + N * SPX_N]: Sized
{
  let mut buf = [0u8; SPX_ADDR_BYTES + N * SPX_N];
  let mut bitmask = [0u8; N * SPX_N];
  let mut outbuf = [0u8; 32];
  let mut buf_tmp = [0u8; 64];

  if N == 1 {
    // F function
    // Since SPX_N may be smaller than 32, we need a temporary buffer.
    buf_tmp[..32].copy_from_slice(&address_to_bytes(addr));

    haraka256(&mut outbuf, &buf_tmp, ctx);
    for i in 0..N * SPX_N {
        buf_tmp[SPX_ADDR_BYTES + i] = input.unwrap_or(out)[i] ^ outbuf[i];
    }
    haraka512(&mut outbuf, &buf_tmp, ctx);
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
  } else {
    // All other tweakable hashes
    buf[..32].copy_from_slice(&address_to_bytes(addr));
    haraka_s(&mut bitmask, N * SPX_N, &buf, SPX_ADDR_BYTES, ctx);

    for i in 0..N * SPX_N {
        buf[SPX_ADDR_BYTES + i] = input.unwrap_or(out)[i] ^ bitmask[i];
    }

    haraka_s(out, SPX_N, &buf, SPX_ADDR_BYTES + N *SPX_N, ctx);
  }
}