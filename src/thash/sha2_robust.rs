use crate::context::SpxCtx;
use crate::thash::*;
use crate::address::*;
use crate::params::*;
use crate::utils::*;

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash<const N: usize>(
  out: &mut[u8], input: &[u8], ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
  #[cfg(feature = "sha512")] {
    if (N > 1) {
      thash_512::<N>(out, input, ctx, addr);
      return;
    }
  }
    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];
    let mut bitmask = [0u8; N * SPX_N];
    let mut sha2_state = [0u8; 40]
;
    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    &buf[SPX_N..].copy_from_slice(&address_to_bytes(&addr));
    mgf1_256(bitmask, N * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    sha2_state.copy_from_slice(&ctx.state_seeded[..40]);

    for i in 0..N * SPX_N {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = input[i] ^ bitmask[i];
    }

    sha256_inc_finalize(&mut outbuf, sha2_state, &buf[SPX_N..],
                        SPX_SHA256_ADDR_BYTES + N*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

#[cfg(feature = "sha512")]
pub fn thash_512<const N: usize>(
  out: &mut[u8], input: &[u8], ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut bitmask = [0u8; N * SPX_N];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];
    let mut sha2_state = [0u8; 72];

    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    &buf[SPX_N..].copy_from_slice(&addr[..SPX_SHA256_ADDR_BYTES]);
    mgf1_512(&mut bitmask, N * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    sha2_state[..72].copy_from_slice(&ctx.state_seeded_512);

    for i in 0..N * SPX_N {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = input[i] ^ bitmask[i];
    }

    sha512_inc_finalize(&mut outbuf, sha2_state, &buf[SPX_N..],
                        SPX_SHA256_ADDR_BYTES + N*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

pub fn thash_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
  #[cfg(feature = "sha512")] {
    if (N > 1) {
      thash_512_inplace::<N>(out, ctx, addr);
      return;
    }
  }
    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];
    let mut bitmask = [0u8; N * SPX_N];
    let mut sha2_state = [0u8; 40]
;
    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    &buf[SPX_N..].copy_from_slice(&address_to_bytes(&addr));
    mgf1_256(bitmask, N * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    sha2_state.copy_from_slice(&ctx.state_seeded[..40]);

    for i in 0..N * SPX_N {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = out[i] ^ bitmask[i];
    }

    sha256_inc_finalize(&mut outbuf, sha2_state, &buf[SPX_N..],
                        SPX_SHA256_ADDR_BYTES + N*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

#[cfg(feature = "sha512")]
pub fn thash_512_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut bitmask = [0u8; N * SPX_N];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];
    let mut sha2_state = [0u8; 72];

    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    &buf[SPX_N..].copy_from_slice(&addr[..SPX_SHA256_ADDR_BYTES]);
    mgf1_512(&mut bitmask, N * SPX_N, buf, SPX_N + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    sha2_state[..72].copy_from_slice(&ctx.state_seeded_512);

    for i in 0..N * SPX_N {
        buf[SPX_N + SPX_SHA256_ADDR_BYTES + i] = out[i] ^ bitmask[i];
    }

    sha512_inc_finalize(&mut outbuf, sha2_state, &buf[SPX_N..],
                        SPX_SHA256_ADDR_BYTES + N*SPX_N);
    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}