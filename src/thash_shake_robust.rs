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
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);

    memcpy(buf, ctx.pub_seed, SPX_N);
    &buf[SPX_N..].copy_from_slice(&addr[..SPX_ADDR_BYTES]);

    shake256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_ADDR_BYTES + i] = input[i] ^ bitmask[i];
    }

    shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
}
