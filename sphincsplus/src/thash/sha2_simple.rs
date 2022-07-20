use crate::context::SpxCtx;
use crate::sha2::sha256_inc_finalize;
use crate::params::*;
use crate::utils::*;
// use


/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash<const N: usize>(
  out: &mut[u8], input: &[u8], ctx: &SpxCtx, addr: &[u32]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
  #[cfg(feature = "sha512")] 
  {
    if N > 1 {
	    thash_512::<N>(out, input, ctx, addr);
      return;
    }
  }

    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 40];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];

    /* Retrieve precomputed state containing pub_seed */
    sha2_state.copy_from_slice(&ctx.state_seeded);

    buf[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&address_to_bytes(&addr));
    buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&input[..N * SPX_N]);

    sha256_inc_finalize(
      &mut outbuf, &mut sha2_state, &buf, SPX_SHA256_ADDR_BYTES + N*SPX_N
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

#[cfg(feature = "sha512")]
pub fn thash_512<const N: usize>(
  out: &mut[u8], input: &[u8], ctx: &SpxCtx, addr: &[u32; 8]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
    use crate::sha2::sha512_inc_finalize;

    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 72];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];

    /* Retrieve precomputed state containing pub_seed */
    sha2_state[..72].copy_from_slice(&ctx.state_seeded_512);

    buf[..SPX_SHA256_ADDR_BYTES]
    .copy_from_slice(&address_to_bytes(addr));
    buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&input[..N * SPX_N]);

    sha512_inc_finalize(
      &mut outbuf, &mut sha2_state, &buf, SPX_SHA256_ADDR_BYTES + N * SPX_N
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}


/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
pub fn thash_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &[u32; 8]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
  #[cfg(feature = "sha512")] 
  {
    if N > 1 {
	    thash_512_inplace::<N>(out, ctx, addr);
      return;
    }
  }

    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 40];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];

    /* Retrieve precomputed state containing pub_seed */
    sha2_state.copy_from_slice(&ctx.state_seeded);

    buf[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
    buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&out[..N * SPX_N]);

    sha256_inc_finalize(
      &mut outbuf, &mut sha2_state, &buf, SPX_SHA256_ADDR_BYTES + N*SPX_N
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

#[cfg(feature = "sha512")]
pub fn thash_512_inplace<const N: usize>(
  out: &mut[u8], ctx: &SpxCtx, addr: &[u32; 8]
)
  where [(); SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N]: Sized
{
    use crate::sha2::sha512_inc_finalize;

    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    let mut sha2_state = [0u8; 72];
    let mut buf = [0u8; SPX_N + SPX_SHA256_ADDR_BYTES + N * SPX_N];

    /* Retrieve precomputed state containing pub_seed */
    sha2_state[..72].copy_from_slice(&ctx.state_seeded_512);

    buf[..SPX_SHA256_ADDR_BYTES]
    .copy_from_slice(&address_to_bytes(addr));
    buf[SPX_SHA256_ADDR_BYTES..].copy_from_slice(&out[..N * SPX_N]);

    sha512_inc_finalize(
      &mut outbuf, &mut sha2_state, &buf, SPX_SHA256_ADDR_BYTES + N * SPX_N
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}