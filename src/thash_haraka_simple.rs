
use crate::context::SpxCtx;
// use crate::thash::*;
use crate::address::*;
use crate::params::*;
use crate::utils::*;

use crate::haraka::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash(out: &mut[u8], input: &[u8], inblocks: u32, buf: &mut [u8],
           ctx: &SpxCtx, addr: [u32; 8])
{
    // SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
    // let mut buf = [0u8; SPX_ADDR_BYTES + inblocks * SPX_N];
    let mut outbuf = [0u8; 32];
    let mut buf_tmp = [0u8; 64];

    if inblocks == 1 {
        /* F function */
        /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
        buf_tmp.fill(0);
        buf_tmp[..32].copy_from_slice(&u32_to_u8_arr(addr));
        buf_tmp[SPX_ADDR_BYTES..SPX_ADDR_BYTES + SPX_N].copy_from_slice(&input[..SPX_N]);

        haraka512(&mut outbuf, &buf_tmp, ctx);
        out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
    } else {
        /* All other tweakable hashes*/
        buf[..32].copy_from_slice(&u32_to_u8_arr(addr));
        buf[SPX_ADDR_BYTES..].copy_from_slice(&input[..inblocks as usize * SPX_N]);
        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks as usize * SPX_N, ctx);
    }
}

// Input is in the output slice
pub fn thash_inplace(
  out: &mut[u8], inblocks: u32,
  ctx: &SpxCtx, addr: [u32; 8], buf: &mut [u8]
)
{
  // SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
  // let mut buf = [0u8; SPX_ADDR_BYTES + inblocks * SPX_N];
  let mut outbuf = [0u8; 32];
  let mut buf_tmp = [0u8; 64];

  if inblocks == 1 {
    /* F function */
    /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
    buf_tmp.fill(0);
    buf_tmp[..32].copy_from_slice(&u32_to_u8_arr(addr));
    buf_tmp[SPX_ADDR_BYTES..SPX_ADDR_BYTES + SPX_N].copy_from_slice(&out[..SPX_N]);

    haraka512(&mut outbuf, &buf_tmp, ctx);
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
  } else {
    /* All other tweakable hashes*/
    buf[..32].copy_from_slice(&u32_to_u8_arr(addr));
    buf[SPX_ADDR_BYTES..].copy_from_slice(&out[..inblocks as usize * SPX_N]);
    haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks as usize * SPX_N, ctx);
  }
}

fn u32_to_u8_arr(input: [u32; 8]) -> [u8; 32] {
  let mut out = [0u8; 32];
  for i in 0..8 {
    out[i*4..i*4+4].copy_from_slice(&input[i].to_ne_bytes());
  }
  out
}