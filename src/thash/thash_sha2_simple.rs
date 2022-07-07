


use crate::thash::*;
use crate::address::*;
use crate::params::*;
use crate::utils::*;
use crate::sha2::*;

#if SPX_SHA512
pub fn thash_512(out: &mut[u8], input: &[u8], inblocks: u32
           ctx: &SpxCtx, addr: &mut [u32; 8]);
#endif

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash(out: &mut[u8], input: &[u8], inblocks: u32
           ctx: &SpxCtx, addr: &mut [u32; 8])
{
#if SPX_SHA512
    if (inblocks > 1) {
	thash_512(out, input, inblocks, ctx, addr);
        return;
    }
#endif

    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 40]
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx.state_seeded, 40 * sizeof(uint8_t));

    &buf[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&addr[..SPX_SHA256_ADDR_BYTES]);
    &buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&input[..inblocks * SPX_N]);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

#if SPX_SHA512
pub fn thash_512(out: &mut[u8], input: &[u8], inblocks: u32
           ctx: &SpxCtx, addr: &mut [u32; 8])
{
    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 72]
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx.state_seeded_512, 72 * sizeof(uint8_t));

    &buf[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&addr[..SPX_SHA256_ADDR_BYTES]);
    &buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&input[..inblocks * SPX_N]);

    sha512_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}
#endif
