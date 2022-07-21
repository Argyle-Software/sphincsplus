#![allow(non_snake_case)]
use crate::context::SpxCtx;
use crate::utils::*;
use crate::params::*;
use crate::sha2::*;

fn  shaX_inc_init(state: &mut[u8]) {
  if SPX_N >= 24 {
    sha512_inc_init(state);
  } else {
    sha256_inc_init(state);
  }
}

pub fn shaX_inc_blocks(state: &mut [u8], input: &[u8], inblocks: usize) {
  if SPX_N >= 24 {
    sha512_inc_blocks(state, input, inblocks);
  } else {
    sha256_inc_blocks(state, input, inblocks);
  }
}

pub fn shaX_inc_finalize(out: &mut[u8], state: &mut[u8], input: &[u8], inlen: usize) {
  if SPX_N >= 24 {
    sha512_inc_finalize(out, state, input, inlen);
  } else {
    sha256_inc_finalize(out, state, input, inlen);
  }
}

pub fn shaX(out: &mut [u8], input: &[u8], inlen: usize) {
  if SPX_N >= 24 {
    sha512(out, input, inlen);
  } else {
    sha256(out, input, inlen);
  }
}

pub fn mgf1_X(out: &mut[u8], outlen: usize, input: &[u8]) {
  if SPX_N >= 24 {
    mgf1_512_2(out, outlen, input);
  } else {
    mgf1_256_2(out, outlen, input);
  }
}

/// For SHA, there is no immediate reason to initialize at the start,
/// so this function is an empty operation.
pub fn initialize_hash_function(ctx: &mut SpxCtx) { 
  seed_state(ctx);
}


// Computes PRF(pk_seed, sk_seed, addr).
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx, addr: &mut[u32])
{
  let mut sha2_state = [0u8; 40];
  let mut buf = [0u8; SPX_SHA256_ADDR_BYTES + SPX_N];
  let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];

  // Retrieve precomputed state containing pub_seed
  sha2_state.copy_from_slice(&ctx.state_seeded);

  // Remainder: ADDR^c ‖ SK.seed
  let addr_bytes = address_to_bytes(&addr);
  buf[..SPX_SHA256_ADDR_BYTES]
    .copy_from_slice(&addr_bytes[..SPX_SHA256_ADDR_BYTES]);
  buf[SPX_SHA256_ADDR_BYTES..SPX_SHA256_ADDR_BYTES+SPX_N]
    .copy_from_slice(&ctx.sk_seed);
  sha256_inc_finalize(
    &mut outbuf, &mut sha2_state, &buf, SPX_SHA256_ADDR_BYTES + SPX_N
  );
  out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);

}
// Computes the message-dependent randomness R, using a secret seed as a key
// for HMAC, and an optional randomization value prefixed to the message.
// This requires m to have at least SPX_SHAX_BLOCK_BYTES + SPX_N space
// available in front of the pointer, i.e. before the message to use for the
// prefix. This is necessary to prevent having to move the message around (and
// allocate memory for it).
pub fn gen_message_random(
  r: &mut[u8], sk_prf: &[u8], optrand: &[u8], 
  m: &[u8], mut mlen: usize, _ctx: &SpxCtx
)
{
    let mut buf = [0u8; SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
    let mut state = [0u8; 8 + SPX_SHAX_OUTPUT_BYTES];
    let mut idx = 0; 

    // This implements HMAC-SHA
    for i in 0..SPX_N  {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    buf[SPX_N..SPX_SHAX_BLOCK_BYTES].fill(0x36);

    shaX_inc_init(&mut state);
    shaX_inc_blocks(&mut state, &buf, 1);

    buf[..SPX_N].copy_from_slice(&optrand[..SPX_N]);

    // If optrand + message cannot fill up an entire block
    if SPX_N + mlen < SPX_SHAX_BLOCK_BYTES {
        buf[SPX_N..SPX_N + mlen].copy_from_slice(&m[..mlen]);
        let tmp_buf = buf.clone();
        shaX_inc_finalize(
          &mut buf[SPX_SHAX_BLOCK_BYTES..], &mut state, &tmp_buf, mlen + SPX_N
        );
    }
    // Otherwise first fill a block, so that finalize only uses the message
    else {
        buf[SPX_N..SPX_SHAX_BLOCK_BYTES]
          .copy_from_slice(&m[..SPX_SHAX_BLOCK_BYTES - SPX_N]);
        shaX_inc_blocks(&mut state, &buf, 1);

        idx += SPX_SHAX_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHAX_BLOCK_BYTES - SPX_N;
        shaX_inc_finalize(
          &mut buf[SPX_SHAX_BLOCK_BYTES..], &mut state, &m[idx..], mlen
        );
    }

    for i in 0..SPX_N  {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    buf[SPX_N..SPX_SHAX_BLOCK_BYTES].fill(0x5c);
    let tmp_buf = buf.clone();
    shaX(&mut buf, &tmp_buf, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
    r[..SPX_N].copy_from_slice(&buf[..SPX_N]);
}


/// Computes the message hash using R, the public key, and the message.
/// Outputs the message digest and the index of the leaf. The index is split in
/// the tree index and the leaf index, for convenient copying to an address.
pub fn hash_message(
  digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, R: &[u8], pk: &[u8], 
  m: &[u8], mut mlen: usize, _ctx: &SpxCtx
)
{
  let mut seed = [0u8; 2*SPX_N + SPX_SHAX_OUTPUT_BYTES];

  /// Round to nearest multiple of SPX_SHAX_BLOCK_BYTES
  // TODO: cleanup this monstrosity
  const SPX_INBLOCKS: usize = (((SPX_N + SPX_PK_BYTES + SPX_SHAX_BLOCK_BYTES - 1) as isize &
  -(SPX_SHAX_BLOCK_BYTES as isize)) / SPX_SHAX_BLOCK_BYTES as isize) as usize;
  
  let mut inbuf = [0u8; SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES];

  let mut buf = [0u8; SPX_DGST_BYTES];
  let mut state = [0u8; 8 + SPX_SHAX_OUTPUT_BYTES];
  let mut buf_idx = 0;
  let mut m_idx = 0;
  
  shaX_inc_init(&mut state);

  // seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
  inbuf[..SPX_N].copy_from_slice(&R[..SPX_N]);
  inbuf[SPX_N..SPX_N + SPX_PK_BYTES].copy_from_slice(&pk[..SPX_PK_BYTES]);

  // If R + pk + message cannot fill up an entire block
  const START: usize = SPX_N + SPX_PK_BYTES; 
  if START + mlen < SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES {
    inbuf[START..START + mlen].copy_from_slice(&m[..mlen]);
    shaX_inc_finalize(
      &mut seed[2*SPX_N..], &mut state, &inbuf, SPX_N + SPX_PK_BYTES + mlen
    );
  }
  // Otherwise first fill a block, so that finalize only uses the message
  else {
    const END: usize = SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
    inbuf[START..START+END].copy_from_slice(&m[..END]);
    shaX_inc_blocks(&mut state, &inbuf, SPX_INBLOCKS);

    m_idx += END;
    mlen -= END;
    shaX_inc_finalize(&mut seed[2*SPX_N..], &mut state, &m[m_idx..], mlen);
  }

  // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
  seed[..SPX_N].copy_from_slice(&R[..SPX_N]);
  seed[SPX_N..SPX_N*2].copy_from_slice(&pk[..SPX_N]);

  // By doing this in two steps, we prevent hashing the message twice;
  // otherwise each iteration in MGF1 would hash the message again.
  
  mgf1_X(&mut buf, SPX_DGST_BYTES, &seed);  

  digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
  buf_idx += SPX_FORS_MSG_BYTES;

  *tree = bytes_to_ull(&buf[buf_idx..], SPX_TREE_BYTES);
  *tree &= !0u64 >> (64 - SPX_TREE_BITS);
  buf_idx += SPX_TREE_BYTES;

  *leaf_idx = bytes_to_ull(&buf[buf_idx..], SPX_LEAF_BYTES) as u32;
  *leaf_idx &= !0u32 >> (32 - SPX_LEAF_BITS);
}


