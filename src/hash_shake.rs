


use crate::address::*;
use crate::utils::*;
use crate::params::*;
use crate::hash::*;
use crate::fips202::*;

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
pub fn initialize_hash_function(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
pub fn prf_addr(out: &mut[u8], ctx: &SpxCtx,
              const addr: &mut [u32; 8])
{
    let mut buf = [0u8; 2*SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, ctx.pub_seed, SPX_N);
    &buf[SPX_N..].copy_from_slice(&addr[..SPX_ADDR_BYTES]);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx.sk_seed, SPX_N);

    shake256(out, SPX_N, buf, 2*SPX_N + SPX_ADDR_BYTES);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
pub fn gen_message_random(R: &mut[u8], sk_prf: &[u8],
                        optrand: &[u8],
                        m: &[u8], mlen: u32
                        ctx: &SpxCtx)
{
    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(s_inc, optrand, SPX_N);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, SPX_N, s_inc);
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

    let mut buf = [0u8; SPX_DGST_BYTES];
    bufp: &mut[u8] = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, SPX_N);
    shake256_inc_absorb(s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);

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
