


use crate::thash::*;
use crate::address::*;
use crate::params::*;
use crate::utils::*;

use crate::haraka::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash(out: &mut[u8], input: &[u8], inblocks: u32
           ctx: &SpxCtx, addr: &mut [u32; 8])
{
    SPX_VLA(uint8_t, buf, SPX_ADDR_BYTES + inblocks*SPX_N);
    SPX_VLA(uint8_t, bitmask, inblocks*SPX_N);
    let mut outbuf = [0u8; 32];
    let mut buf_tmp = [0u8; 64];

    if (inblocks == 1) {
        /* F function */
        /* Since SPX_N may be smaller than 32, we need a temporary buffer. */
        memset(buf_tmp, 0, 64);
        &buf_tmp[..32].copy_from_slice(&addr[..32]);

        haraka256(outbuf, buf_tmp, ctx);
        for (i = 0; i < inblocks * SPX_N; i++) {
            buf_tmp[SPX_ADDR_BYTES + i] = input[i] ^ outbuf[i];
        }
        haraka512(outbuf, buf_tmp, ctx);
        &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
    } else {
        /* All other tweakable hashes*/
        &buf[..32].copy_from_slice(&addr[..32]);
        haraka_S(bitmask, inblocks * SPX_N, buf, SPX_ADDR_BYTES, ctx);

        for (i = 0; i < inblocks * SPX_N; i++) {
            buf[SPX_ADDR_BYTES + i] = input[i] ^ bitmask[i];
        }

        haraka_S(out, SPX_N, buf, SPX_ADDR_BYTES + inblocks*SPX_N, ctx);
    }
}
