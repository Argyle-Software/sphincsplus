use crate::thash::*;
use crate::address::*;
use crate::params::*;
use crate::utils::*;

use crate::fips202::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash(out: &mut[u8], input: &[u8], inblocks: u32
           ctx: &SpxCtx, addr: &mut [u32; 8])
{
    SPX_VLA(uint8_t, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);

    memcpy(buf, ctx.pub_seed, SPX_N);
    &buf[SPX_N..].copy_from_slice(&addr[..SPX_ADDR_BYTES]);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, input, inblocks * SPX_N);

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
}
