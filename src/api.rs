// use signature::Keypair;

use core::hash::Hash;

use crate::{sign::*, build_consts, context::SpxCtx, haraka::*, 
  utils::*, }; // , CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES
// use crate::sha2::SPX_SHA256_ADDR_BYTES;
pub trait HashMode {

  const SPX_OFFSET_LAYER: usize;   // The byte used to specify the Merkle tree layer
  const SPX_OFFSET_TREE: usize;   // The start of the 8 byte field used to specify the tree
  const SPX_OFFSET_TYPE: usize;  // The byte used to specify the hash type (reason)
  const SPX_OFFSET_KP_ADDR2: usize;  // The high byte used to specify the key pair (which one-time signature)
  const SPX_OFFSET_KP_ADDR1: usize;  // The low byte used to specify the key pair
  const SPX_OFFSET_CHAIN_ADDR: usize;  // The byte used to specify the chain address (which Winternitz chain)
  const SPX_OFFSET_HASH_ADDR: usize;  // The byte used to specify the hash address (where in the Winternitz chain)
  const SPX_OFFSET_TREE_HGT: usize;  // The byte used to specify the height of this node in the FORS or Merkle tree
  const SPX_OFFSET_TREE_INDEX: usize; // The start of the 4 byte field used to specify the node in the FORS or Merkle tree

  fn initialize_hash_function<L: SecLevel>(ctx: &mut SpxCtx<L>) 
    where [(); L::SPX_N]:;
  
  // Computes PRF(key, addr), given a secret key of L::SPX_N bytes and an address
  fn prf_addr<L: SecLevel>(out: &mut[u8], ctx: &SpxCtx<L>, addr: &mut[u32])
    where [(); L::SPX_N]:;

  
  // Computes the message-dependent randomness R, using a secret seed and an
  // optional randomization value as well as the message.
  fn gen_message_random<L: SecLevel>(
    r: &mut[u8], sk_prf: &[u8], optrand: &[u8], 
    m: &[u8], mlen: usize, ctx: &SpxCtx<L>
  ) where [(); L::SPX_N]:;
  
  // Computes the message hash using R, the public key, and the message.
  // Outputs the message digest and the index of the leaf. The index is split in
  // the tree index and the leaf index, for convenient copying to an address.
  fn hash_message<L: SecLevel> (
    digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, 
    r: &[u8], pk: &[u8], m: &[u8], mlen: usize, ctx: &SpxCtx<L>
  )
    where [(); L::SPX_DGST_BYTES]:,
          [(); L::SPX_N]:;
}

pub trait SecLevel {
  const SPX_N: usize;
  /// Height of the hypertree.
  const SPX_FULL_HEIGHT: usize;
  /// Number of subtree layer.
  const SPX_D: usize;
  /// FORS tree dimensions.
  const SPX_FORS_HEIGHT: usize;
  const SPX_FORS_TREES: usize;

  const CRYPTO_SECRETKEYBYTES: usize;
  const CRYPTO_PUBLICKEYBYTES: usize;
  const CRYPTO_BYTES: usize;
  const CRYPTO_SEEDBYTES: usize;

  /// Winternitz parameter,
  const SPX_WOTS_W: usize;

  /// For clarity
  // #[cfg(any(feature = "haraka", feature = "shake"))]
  const SPX_ADDR_BYTES: usize;

  /// WOTS parameters.
  const SPX_WOTS_LOGW: usize;

  const SPX_WOTS_LEN: usize;
  const SPX_WOTS_BYTES: usize;
  // const SPX_WOTS_PK_BYTES: usize;

  /// Subtree size.
  const SPX_TREE_HEIGHT: usize;

  /// FORS parameters.
  const SPX_FORS_MSG_BYTES: usize;
  const SPX_FORS_BYTES: usize;
  // const SPX_FORS_PK_BYTES: usize;

  /// Resulting SPX sizes.
  const SPX_BYTES: usize;
  const SPX_PK_BYTES: usize;
  const SPX_SK_BYTES: usize;

  // const WOTS_SIG_LEN: usize;

  const SPX_TREE_BITS: usize;
  const SPX_TREE_BYTES: usize;
  const SPX_LEAF_BITS: usize;
  const SPX_LEAF_BYTES: usize;
  const SPX_DGST_BYTES: usize;

  const SPX_WOTS_LEN1: usize;

  /// SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute
  const SPX_WOTS_LEN2: usize;

  const FORS_STACK_LEN: usize;
  const WOTS_STACK_LEN: usize;

  // const SHA2_INLEN: usize;
  // const SHA2_INLENX2: usize;
}

pub trait TreeHash {
  fn thash<const N: usize, L: SecLevel>(
    out: &mut[u8], input: Option<&[u8]>,  ctx: &SpxCtx<L>, addr: &[u32]
  )
  where [(); L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + N * L::SPX_N]:;
}

pub struct Keypair<L: SecLevel> 
  where [(); L::CRYPTO_PUBLICKEYBYTES]:,
        [(); L::CRYPTO_SECRETKEYBYTES]:,
{
  public: [u8; L::CRYPTO_PUBLICKEYBYTES],
  secret: [u8; L::CRYPTO_SECRETKEYBYTES]
}

pub struct Haraka { }

pub struct F128 { }

pub struct Simple<H: HashMode> { 
  _hash: H 
}

impl HashMode for Haraka {

  const SPX_OFFSET_LAYER: usize = 3;   // The byte used to specify the Merkle tree layer
  const SPX_OFFSET_TREE: usize = 8;   // The start of the 8 byte field used to specify the tree
  const SPX_OFFSET_TYPE: usize = 19;  // The byte used to specify the hash type (reason)
  const SPX_OFFSET_KP_ADDR2: usize = 22;  // The high byte used to specify the key pair (which one-time signature)
  const SPX_OFFSET_KP_ADDR1: usize = 23;  // The low byte used to specify the key pair
  const SPX_OFFSET_CHAIN_ADDR: usize = 27;  // The byte used to specify the chain address (which Winternitz chain)
  const SPX_OFFSET_HASH_ADDR: usize = 31;  // The byte used to specify the hash address (where in the Winternitz chain)
  const SPX_OFFSET_TREE_HGT: usize = 27;  // The byte used to specify the height of this node in the FORS or Merkle tree
  const SPX_OFFSET_TREE_INDEX: usize = 28; // The start of the 4 byte field used to specify the node in the FORS or Merkle tree


  fn initialize_hash_function<L: SecLevel>(ctx: &mut SpxCtx<L>)
    where [(); L::SPX_N]:
  {
      tweak_constants::<L>(ctx);
  }
  
  /// Computes PRF(key, addr), given a secret key of L::SPX_N bytes and an address
  fn prf_addr<L: SecLevel>(out: &mut[u8], ctx: &SpxCtx<L>, addr: &mut[u32])
    where [(); L::SPX_N]:
  {
    // Since L::SPX_N may be smaller than 32, we need temporary buffers.
    let mut outbuf = [0u8; 32];
    let mut buf = [0u8; 64];
  
    buf[..L::SPX_ADDR_BYTES].copy_from_slice(&address_to_bytes(addr));
    buf[L::SPX_ADDR_BYTES..L::SPX_ADDR_BYTES+L::SPX_N].copy_from_slice(&ctx.sk_seed[..L::SPX_N]);
  
    haraka512::<L>(&mut outbuf, &buf, ctx);
    out[..L::SPX_N].copy_from_slice(&outbuf[..L::SPX_N]);
  }
  
  /// Computes the message-dependent randomness R, using a secret seed and an
  /// optional randomization value as well as the message.
  fn gen_message_random<L: SecLevel>(
    r: &mut[u8], sk_prf: &[u8], optrand: &[u8], m: &[u8], mlen: usize, ctx: &SpxCtx<L>
  )
    where [(); L::SPX_N]:
  {
    let mut s_inc = [0u8; 65]; // haraka_S_inc_init
    haraka_s_inc_absorb::<L>(&mut s_inc, &sk_prf, L::SPX_N, ctx);
    haraka_s_inc_absorb::<L>(&mut s_inc, &optrand, L::SPX_N, ctx);
    haraka_s_inc_absorb::<L>(&mut s_inc, &m, mlen, ctx);
    haraka_s_inc_finalize(&mut s_inc);
    haraka_s_inc_squeeze::<L>(r, L::SPX_N, &mut s_inc, ctx);
  }
  
  /// Computes the message hash using R, the public key, and the message.
  /// Outputs the message digest and the index of the leaf. The index is split in
  /// the tree index and the leaf index, for convenient copying to an address.
  fn hash_message<L: SecLevel>(
    digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], 
    m: &[u8], mlen: usize, ctx: &SpxCtx<L>
  )
    where [(); L::SPX_DGST_BYTES]:,
          [(); L::SPX_N]:,
  {
    let mut buf = [0u8; L::SPX_DGST_BYTES];
    let mut s_inc = [0u8; 65]; // haraka_S_inc_init
    let mut idx = 0usize;
  
    haraka_s_inc_absorb::<L>(&mut s_inc, r, L::SPX_N, ctx);
    // Only absorb root part of pk
    haraka_s_inc_absorb::<L>(&mut s_inc, &pk[L::SPX_N..], L::SPX_N, ctx); 
    haraka_s_inc_absorb::<L>(&mut s_inc, m, mlen, ctx);
    haraka_s_inc_finalize(&mut s_inc);
    haraka_s_inc_squeeze::<L>(&mut buf, L::SPX_DGST_BYTES, &mut s_inc, ctx);
  
    digest[..L::SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..L::SPX_FORS_MSG_BYTES]);
    idx += L::SPX_FORS_MSG_BYTES;
  
    *tree = bytes_to_ull(&buf[idx..], L::SPX_TREE_BYTES);
    *tree &= !0 >> (64 - L::SPX_TREE_BITS);
    idx += L::SPX_TREE_BYTES;
  
    *leaf_idx = bytes_to_ull(&buf[idx..], L::SPX_LEAF_BYTES) as u32;
    *leaf_idx &= !0 >> (32 - L::SPX_LEAF_BITS);
  }
}

impl TreeHash for Simple<Haraka> {
  fn thash<const N: usize, L: SecLevel>(
    out: &mut[u8], input: Option<&[u8]>,  ctx: &SpxCtx<L>, addr: &[u32]
  )
    where [(); L::SPX_N]:,
          [(); L::SPX_ADDR_BYTES + N * L::SPX_N]:,
  {
    let mut buf = [0u8; L::SPX_ADDR_BYTES + N * L::SPX_N];
    let mut outbuf = [0u8; 32];
    let mut buf_tmp = [0u8; 64];
  
    if N == 1 {
      // F function
      // Since SPX_N may be smaller than 32, we need a temporary buffer.
      buf_tmp[..32].copy_from_slice(&address_to_bytes(addr));
      buf_tmp[L::SPX_ADDR_BYTES..L::SPX_ADDR_BYTES + L::SPX_N]
        .copy_from_slice(&input.unwrap_or(out)[..L::SPX_N]);
  
      haraka512::<L>(&mut outbuf, &buf_tmp, ctx);
      out[..L::SPX_N].copy_from_slice(&outbuf[..L::SPX_N]);
    } else {
      // All other tweakable hashes
      buf[..32].copy_from_slice(&address_to_bytes(addr));
      buf[L::SPX_ADDR_BYTES..]
        .copy_from_slice(&input.unwrap_or(out)[..N * L::SPX_N]);
      haraka_s::<L>(out, L::SPX_N, &buf, L::SPX_ADDR_BYTES + N * L::SPX_N, ctx);
    }
  }

}


pub struct Sphincs <H: HashMode, L: SecLevel, T: TreeHash> {
  hash: H,
  level: L,
  thash: T
}

impl<Haraka, F128, Simple> Sphincs <Haraka, F128 , Simple> 
  where Haraka: HashMode,
        F128: SecLevel,
        Simple: TreeHash,
{
  fn keypair() -> Keypair<F128>
    where [(); F128::CRYPTO_PUBLICKEYBYTES]:,
          [(); F128::CRYPTO_SECRETKEYBYTES]:,
          [(); F128::CRYPTO_SEEDBYTES]:,
          [(); F128::SPX_N]:,
          [(); 2*F128::SPX_N]:,
          [(); F128::SPX_WOTS_LEN]:,
          [(); F128::WOTS_STACK_LEN]:,
          [(); F128::CRYPTO_SEEDBYTES]:,
          [(); F128::SPX_TREE_HEIGHT * F128::SPX_N + F128::SPX_WOTS_BYTES]:,
          [(); (F128::SPX_WOTS_LEN2 * F128::SPX_WOTS_LOGW + 7) / 8]:,
          [(); F128::SPX_ADDR_BYTES + F128::SPX_WOTS_LEN * F128::SPX_N]:,
          [(); F128::SPX_ADDR_BYTES + 1 * F128::SPX_N]:,
          [(); F128::SPX_ADDR_BYTES + 2 * F128::SPX_N]:,
  {
    let mut public = [0u8; F128::CRYPTO_PUBLICKEYBYTES];
    let mut secret = [0u8; F128::CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair::<Haraka, F128, Simple>(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  fn sign(sig: &mut[u8], msg: &[u8], keypair: Keypair<F128>) 
  where [(); F128::CRYPTO_PUBLICKEYBYTES]:,
        [(); F128::CRYPTO_SECRETKEYBYTES]:,
        [(); F128::SPX_BYTES]:,
        [(); F128::SPX_N]:,
        [(); 2*F128::SPX_N]:,
        [(); F128::SPX_WOTS_LEN]:,
        [(); F128::SPX_DGST_BYTES]:,
        [(); F128::WOTS_STACK_LEN]:,
        [(); F128::SPX_FORS_MSG_BYTES]:,
        [(); F128::SPX_TREE_HEIGHT * F128::SPX_N + F128::SPX_WOTS_BYTES]:,
        [(); F128::SPX_FORS_HEIGHT]:,
        [(); F128::FORS_STACK_LEN]:,
        [(); F128::SPX_ADDR_BYTES + 2 * F128::SPX_N]:,
        [(); F128::SPX_ADDR_BYTES + 1 * F128::SPX_N]:,
        [(); F128::SPX_ADDR_BYTES + F128::SPX_FORS_TREES * F128::SPX_N]:,
        [(); F128::SPX_ADDR_BYTES + F128::SPX_WOTS_LEN * F128::SPX_N]:,
        [(); (F128::SPX_WOTS_LEN2 * F128::SPX_WOTS_LOGW + 7) / 8]:,
  {
    let mut sig = [0u8; F128::SPX_BYTES];
    crypto_sign::<Haraka, F128, Simple>(&mut sig, msg, &keypair.secret, None);
  }

  fn verify(sig: &[u8], msg: &[u8], keypair: Keypair<F128>) -> i32
    where [(); F128::CRYPTO_PUBLICKEYBYTES]:,
          [(); F128::CRYPTO_SECRETKEYBYTES]:,
          [(); F128::SPX_N]:,
          [(); F128::SPX_DGST_BYTES]:,
          [(); F128::SPX_FORS_MSG_BYTES]:,
          [(); F128::SPX_TREE_HEIGHT * F128::SPX_N + F128::SPX_WOTS_BYTES]:,
          [(); F128::SPX_ADDR_BYTES + 2 * F128::SPX_N]:,
          [(); F128::SPX_ADDR_BYTES + 1 * F128::SPX_N]:,
          [(); F128::SPX_ADDR_BYTES + F128::SPX_FORS_TREES * F128::SPX_N]:,
          [(); F128::SPX_ADDR_BYTES + F128::SPX_WOTS_LEN * F128::SPX_N]:,
          [(); (F128::SPX_WOTS_LEN2 * F128::SPX_WOTS_LOGW + 7) / 8]:,
  {
    crypto_sign_verify::<Haraka, F128, Simple>(&sig, &msg, &keypair.public)
  }
}

impl SecLevel for F128 {
  /// Hash output length in bytes.
  const SPX_N: usize = 16;
  /// Height of the hypertree.
  const SPX_FULL_HEIGHT: usize = 66;
  /// Number of subtree layer.
  const SPX_D: usize = 22;
  /// FORS tree dimensions.
  const SPX_FORS_HEIGHT: usize = 6;
  const SPX_FORS_TREES: usize = 33;

  /// For clarity
  const SPX_ADDR_BYTES: usize = 32;

  const FORS_STACK_LEN: usize = Self::SPX_FORS_HEIGHT * Self::SPX_N;
  const WOTS_STACK_LEN: usize = Self::SPX_TREE_HEIGHT * Self::SPX_N;

  // const SHA2_INLEN: usize = Self::SPX_N + SPX_SHA256_ADDR_BYTES;
  // const SHA2_INLENX2: usize = 2 * Self::SPX_N + SPX_SHA256_ADDR_BYTES;


  build_consts!();
}

