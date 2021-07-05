


use crate::address::*;
use crate::utils::*;
use crate::params::*;
use crate::hash::*;
use crate::sha2::*;

#[cfg(SPX_N >= 24)]
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA512_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA512_BLOCK_BYTES
#define shaX_inc_init sha512_inc_init
#define shaX_inc_blocks sha512_inc_blocks
#define shaX_inc_finalize sha512_inc_finalize
#define shaX sha512
#define mgf1_X mgf1_512
#else
#define SPX_SHAX_OUTPUT_BYTES SPX_SHA256_OUTPUT_BYTES
#define SPX_SHAX_BLOCK_BYTES SPX_SHA256_BLOCK_BYTES
#define shaX_inc_init sha256_inc_init
#define shaX_inc_blocks sha256_inc_blocks
#define shaX_inc_finalize sha256_inc_finalize
#define shaX sha256
#define mgf1_X mgf1_256
#endif


/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
pub fn initialize_hash_function(spx_ctx *ctx)
{
    seed_state(ctx);
}

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx,
              const addr: &mut [u32; 8])
{
    let mut sha2_state = [0u8; 40]
    let mut buf = [0u8; SPX_SHA256_ADDR_BYTES + SPX_N];
    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx.state_seeded, 40 * sizeof(uint8_t));

    /* Remainder: ADDR^c ‖ SK.seed */
    &buf[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&addr[..SPX_SHA256_ADDR_BYTES]);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx.sk_seed, SPX_N);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);

    &out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least SPX_SHAX_BLOCK_BYTES + SPX_N space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
pub fn gen_message_random(R: &mut[u8], sk_prf: &[u8],
                        optrand: &[u8],
                        m: &[u8], mlen: u32
                        ctx: &SpxCtx)
{
    (void)ctx;

    let mut buf = [0u8; SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES];
    uint8_t state[8 + SPX_SHAX_OUTPUT_BYTES];
    let mut i;

#if SPX_N > SPX_SHAX_BLOCK_BYTES
    #error "Currently only supports SPX_N of at most SPX_SHAX_BLOCK_BYTES"
#endif

    /* This implements HMAC-SHA */
    for i in 0..SPX_N  {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x36, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX_inc_init(state);
    shaX_inc_blocks(state, buf, 1);

    &buf[..SPX_N].copy_from_slice(&optrand[..SPX_N]);

    /* If optrand + message cannot fill up an entire block */
    if (SPX_N + mlen < SPX_SHAX_BLOCK_BYTES) {
        &buf[SPX_N..].copy_from_slice(&m[..mlen]);
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, state,
                            buf, mlen + SPX_N);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        &buf[SPX_N..].copy_from_slice(&m[..SPX_SHAX_BLOCK_BYTES - SPX_N]);
        shaX_inc_blocks(state, buf, 1);

        m += SPX_SHAX_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SHAX_BLOCK_BYTES - SPX_N;
        shaX_inc_finalize(buf + SPX_SHAX_BLOCK_BYTES, state, m, mlen);
    }

    for i in 0..SPX_N  {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + SPX_N, 0x5c, SPX_SHAX_BLOCK_BYTES - SPX_N);

    shaX(buf, buf, SPX_SHAX_BLOCK_BYTES + SPX_SHAX_OUTPUT_BYTES);
    &R[..SPX_N].copy_from_slice(&buf[..SPX_N]);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
pub fn hash_message(digest: &mut[u8], &mut[u64], leaf_idx: &mut[u32],
                  R: &[u8], pk: &[u8],
                  m: &[u8], mlen: u32
                  ctx: &SpxCtx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    let mut seed = [0u8; 2*SPX_N + SPX_SHAX_OUTPUT_BYTES];

    /* Round to nearest multiple of SPX_SHAX_BLOCK_BYTES */
#if (SPX_SHAX_BLOCK_BYTES & (SPX_SHAX_BLOCK_BYTES-1)) != 0
    #error "Assumes that SPX_SHAX_BLOCK_BYTES is a power of 2"
#endif
#define SPX_INBLOCKS (((SPX_N + SPX_PK_BYTES + SPX_SHAX_BLOCK_BYTES - 1) & \
                        -SPX_SHAX_BLOCK_BYTES) / SPX_SHAX_BLOCK_BYTES)
    let mut inbuf = [0u8; SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES];

    let mut buf = [0u8; SPX_DGST_BYTES];
    bufp: &mut[u8] = buf;
    uint8_t state[8 + SPX_SHAX_OUTPUT_BYTES];

    shaX_inc_init(state);

    // seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
    &inbuf[..SPX_N].copy_from_slice(&R[..SPX_N]);
    &inbuf[SPX_N..].copy_from_slice(&pk[..SPX_PK_BYTES]);

    /* If R + pk + message cannot fill up an entire block */
    if (SPX_N + SPX_PK_BYTES + mlen < SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES) {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m, mlen);
        shaX_inc_finalize(seed + 2*SPX_N, state, inbuf, SPX_N + SPX_PK_BYTES + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + SPX_N + SPX_PK_BYTES, m,
               SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES);
        shaX_inc_blocks(state, inbuf, SPX_INBLOCKS);

        m += SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        mlen -= SPX_INBLOCKS * SPX_SHAX_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
        shaX_inc_finalize(seed + 2*SPX_N, state, m, mlen);
    }

    // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
    &seed[..SPX_N].copy_from_slice(&R[..SPX_N]);
    &seed[SPX_N..].copy_from_slice(&pk[..SPX_N]);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1_X(bufp, SPX_DGST_BYTES, seed, 2*SPX_N + SPX_SHAX_OUTPUT_BYTES);

    &digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&bufp[..SPX_FORS_MSG_BYTES]);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}


