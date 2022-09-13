use core::hash::Hash;

use crate::api::HashMode;
use crate::api::SecLevel;
use crate::api::TreeHash;
use crate::context::SpxCtx;
use crate::params::*;
use crate::wots::*;
use crate::fors::*;
use crate::hash::*;
use crate::thash::*;
use crate::address::*;
use crate::utils::*;
use crate::merkle::*;
use crate::randombytes::*;

/// Generates an SPX key pair given a seed of length
/// Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
/// Format pk: [PUB_SEED || root]
fn crypto_sign_seed_keypair<H: HashMode, L: SecLevel, T: TreeHash>(
  pk: &mut[u8], sk: &mut[u8], seed: &[u8]
) -> i32
  where [(); L::SPX_N]:,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_WOTS_LEN]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); L::CRYPTO_SEEDBYTES]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
{
  let mut ctx = SpxCtx::<L>::default();

  // Initialize SK_SEED, SK_PRF and PUB_SEED from seed.
  sk[..L::CRYPTO_SEEDBYTES].copy_from_slice(&seed[..L::CRYPTO_SEEDBYTES]);

  pk[..L::SPX_N].copy_from_slice(&sk[2*L::SPX_N..3*L::SPX_N]);

  ctx.sk_seed.copy_from_slice(&sk[..L::SPX_N]);
  ctx.pub_seed.copy_from_slice(&pk[..L::SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  H::initialize_hash_function(&mut ctx);

  // Compute root node of the top-most subtree.
  merkle_gen_root::<H, L, T>(&mut sk[3*L::SPX_N..], &ctx);

  pk[L::SPX_N..2*L::SPX_N].copy_from_slice(&sk[3*L::SPX_N..4*L::SPX_N]);

  return 0;
}

/// Generates an SPX key pair.
/// Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
/// Format pk: [PUB_SEED || root]
pub fn  crypto_sign_keypair<H:HashMode, L: SecLevel, T: TreeHash>(
  pk: &mut[u8], sk: &mut[u8], seed: Option<&[u8]>
) -> i32
  where [(); L::SPX_N]:,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_WOTS_LEN]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); L::CRYPTO_SEEDBYTES]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
{
  if let Some(deterministic) = seed {
    crypto_sign_seed_keypair::<H, L, T>(pk, sk, deterministic);
  } else {
    let mut seed = [0u8; L::CRYPTO_SEEDBYTES];
    randombytes(&mut seed, L::CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair::<H, L, T>(pk, sk, &seed);
  }

  return 0;
}

/// Returns an array containing a detached signature.
pub fn  crypto_sign<H: HashMode, L: SecLevel, T: TreeHash>(
  sig: &mut[u8], m: &[u8], sk: &[u8], seed: Option<&[u8]>
)
  where [(); L::SPX_N]:,
        [(); L::SPX_DGST_BYTES]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); L::SPX_FORS_MSG_BYTES]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); L::SPX_FORS_HEIGHT]:,
        [(); L::FORS_STACK_LEN]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_FORS_TREES * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
{
  let mut ctx = SpxCtx::<L>::default();

  let mut sk_prf = [0u8; L::SPX_N];
  sk_prf.copy_from_slice(&sk[L::SPX_N..L::SPX_N*2]);
  let mut pk = [0u8; 2*L::SPX_N];
  pk[..2*L::SPX_N].copy_from_slice(&sk[L::SPX_N*2..L::SPX_N*4]);

  let mut optrand = [0u8; L::SPX_N];
  let mut mhash = [0u8; L::SPX_FORS_MSG_BYTES];
  let mut root = [0u8; L::SPX_N];

  let mut tree = 0u64;
  let mut idx_leaf =  0u32;
  let mut wots_addr = [0u32; 8];
  let mut tree_addr = [0u32; 8];

  let mut idx = 0usize;

  ctx.sk_seed.copy_from_slice(&sk[..L::SPX_N]);
  ctx.pub_seed.copy_from_slice(&pk[..L::SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  H::initialize_hash_function(&mut ctx);

  set_type::<H>(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type::<H>(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);

  // Optionally, signing can be made non-deterministic using optrand.
  // This can help counter side-channel attacks that would benefit from
  // getting a large number of traces when the signer uses the same nodes.
  match seed {
    Some(deterministic) => optrand.copy_from_slice(&deterministic),
    None => randombytes(&mut optrand, L::SPX_N)
  }
  
  // Compute the digest randomization value.
  H::gen_message_random(sig, &sk_prf, &optrand, m, m.len(), &ctx);

  // Derive the message digest and leaf index from R, PK and M.
  H::hash_message(
    &mut mhash, &mut tree, &mut idx_leaf, sig, &pk, m, m.len(), &ctx
  );
  idx += L::SPX_N;

  set_tree_addr::<H>(&mut wots_addr, tree);
  set_keypair_addr::<H, L>(&mut wots_addr, idx_leaf);

  // Sign the message hash using FORS.
  fors_sign::<H, L, T>(&mut sig[idx..], &mut root, &mhash, &ctx, &mut wots_addr);
  idx += L::SPX_FORS_BYTES;

  for i in 0..L::SPX_D  {
      set_layer_addr::<H>(&mut tree_addr, i as u32);
      set_tree_addr::<H>(&mut tree_addr, tree);

      copy_subtree_addr::<H>(&mut wots_addr, &mut tree_addr);
      set_keypair_addr::<H, L>(&mut wots_addr, idx_leaf);

      merkle_sign::<H, L, T>(
        &mut sig[idx..], &mut root, &ctx, 
        &mut wots_addr, &mut tree_addr, idx_leaf
      );
      idx += L::SPX_WOTS_BYTES + L::SPX_TREE_HEIGHT * L::SPX_N;

      // Update the indices for the next layer.
      idx_leaf = (tree & ((1 << L::SPX_TREE_HEIGHT)-1)) as u32;
      tree = tree >> L::SPX_TREE_HEIGHT;
  }
}

/// Verifies a detached signature and message under a given public key.
pub fn crypto_sign_verify<H: HashMode, L: SecLevel, T: TreeHash>(
  sig: &[u8], msg: &[u8], pk: &[u8]
) -> i32
where [(); L::SPX_N]:,
      [(); L::SPX_DGST_BYTES]:,
      [(); L::SPX_FORS_MSG_BYTES]:,
      [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
      [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
      [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
      [(); L::SPX_ADDR_BYTES + L::SPX_FORS_TREES * L::SPX_N]:,
      [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
      [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,

{
  let mut ctx = SpxCtx::default();
  let pub_root: &[u8] = &pk[L::SPX_N..];
  let mut mhash = [0u8; L::SPX_FORS_MSG_BYTES];
  let mut wots_pk = [0u8; L::SPX_WOTS_BYTES];
  let (mut root, mut leaf) = ([0u8; L::SPX_N], [0u8; L::SPX_N]);
  let mut tree = 0u64;
  let mut idx_leaf =  0u32;
  let (mut wots_addr, mut tree_addr, mut wots_pk_addr) = ([0u32; 8], [0u32; 8], [0u32; 8]);
  let mut idx = 0usize;

  // TODO: return Result + impl error struct
  // if siglen != SPX_BYTES as u64 {
  //     return -1;
  // }
  
  ctx.pub_seed[..].copy_from_slice(&pk[..L::SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  H::initialize_hash_function(&mut ctx);

  set_type::<H>(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type::<H>(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type::<H>(&mut wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

  // Derive the message digest and leaf index from R || PK || M.
  // The additional L::SPX_N is a result of the hash domain separator.
  H::hash_message(
    &mut mhash, &mut tree, &mut idx_leaf, sig, 
    pk, &msg, msg.len(), &ctx
  );
  idx += L::SPX_N;

  // Layer correctly defaults to 0, so no need to set_layer_addr
  set_tree_addr::<H>(&mut wots_addr, tree);
  set_keypair_addr::<H, L>(&mut wots_addr, idx_leaf);

  fors_pk_from_sig::<H, L, T>(&mut root, &sig[idx..], &mhash, &ctx, &mut wots_addr);
  idx += L::SPX_FORS_BYTES;

  // For each subtree..
  for i in 0..L::SPX_D  {
    set_layer_addr::<H>(&mut tree_addr, i as u32);
    set_tree_addr::<H>(&mut tree_addr, tree);
    copy_subtree_addr::<H>(&mut wots_addr, &mut tree_addr);
    set_keypair_addr::<H, L>(&mut wots_addr, idx_leaf);

    copy_keypair_addr::<H, L>(&mut wots_pk_addr, &mut wots_addr);

    // The WOTS public key is only correct if the signature was correct.
    // Initially, root is the FORS pk, but on subsequent iterations it is
    // the root of the subtree below the currently processed subtree.
    wots_pk_from_sig::<H, L, T>(&mut wots_pk, &sig[idx..], &root, &ctx, &mut wots_addr);
    idx += L::SPX_WOTS_BYTES;

    // Compute the leaf node using the WOTS public key.
    T::thash::<{L::SPX_WOTS_LEN}, L>(&mut leaf, Some(&wots_pk), &ctx, &wots_pk_addr);

    // Compute the root node of this subtree.
    compute_root::<H, L, T>(
      &mut root, &leaf, idx_leaf, 0, &sig[idx..], 
      L::SPX_TREE_HEIGHT as u32, &ctx, &mut tree_addr
    );
    idx += L::SPX_TREE_HEIGHT * L::SPX_N;

    // Update the indices for the next layer.
    idx_leaf = (tree & ((1 << L::SPX_TREE_HEIGHT)-1)) as u32;
    tree = tree >> L::SPX_TREE_HEIGHT;
  }

  // Check if the root node equals the root node in the public key.
  if root == pub_root {
      return -1;
  }

  return 0;
}

// Returns an array containing the signature followed by the message.
// pub fn crypto_sign(
//   sm: &mut[u8], m: &[u8], sk: &[u8], seed: Option<&[u8]>
// ) -> i32
// {
//   crypto_sign_signature(sm, m, sk, seed);

//   // sm[SPX_BYTES..].copy_from_slice(&m);
//   // *smlen = SPX_BYTES + mlen;

//   return 0;
// }

// // Verifies a given signature-message pair under a given public key.
// pub fn crypto_sign_open(sm: &mut [u8], pk: &[u8]) -> i32
// {
//   // The API caller does not necessarily know what size a signature should be
//   // but SPHINCS+ signatures are always exactly SPX_BYTES.
//   // if smlen < SPX_BYTES {
//   //   m.fill(0);
//   //   *mlen = 0;
//   //   return -1;
//   // }

//   // *mlen = smlen - SPX_BYTES;

//   crypto_sign_verify(sm, msg, pk);

//   // if (crypto_sign_verify(sm, *mlen as usize, pk)) != 0 {
//     // m.fill(0);
//     // *mlen = 0;
//     // return -1;
//   // }

//   // If verification was successful, move the message to the right place.
//   // let end = *mlen as usize + SPX_BYTES;
//   // let end2 = *mlen;
//   // m[..end2 as usize].copy_from_slice(&sm[SPX_BYTES..end]);

//   return 0
// }
