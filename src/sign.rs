use crate::api::SigError;
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
fn crypto_sign_seed_keypair(
  pk: &mut[u8], sk: &mut[u8], seed: &[u8]
) -> i32
{
  let mut ctx = SpxCtx::default();

  // Initialize SK_SEED, SK_PRF and PUB_SEED from seed.
  sk[..CRYPTO_SEEDBYTES].copy_from_slice(&seed[..CRYPTO_SEEDBYTES]);

  pk[..SPX_N].copy_from_slice(&sk[2*SPX_N..3*SPX_N]);

  ctx.sk_seed.copy_from_slice(&sk[..SPX_N]);
  ctx.pub_seed.copy_from_slice(&pk[..SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  initialize_hash_function(&mut ctx);

  // Compute root node of the top-most subtree.
  merkle_gen_root(&mut sk[3*SPX_N..], &ctx);

  pk[SPX_N..2*SPX_N].copy_from_slice(&sk[3*SPX_N..4*SPX_N]);

  return 0; // TODO: Use rust semantics
}

/// Generates an SPX key pair.
/// Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
/// Format pk: [PUB_SEED || root]
pub fn  crypto_sign_keypair(
  pk: &mut[u8], sk: &mut[u8], seed: Option<&[u8]>
) -> i32
{
  if let Some(deterministic) = seed {
    crypto_sign_seed_keypair(pk, sk, deterministic);
  } else {
    let mut seed = [0u8; CRYPTO_SEEDBYTES];
    randombytes(&mut seed, CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair(pk, sk, &seed);
  }
  return 0; // TODO: Use rust semantics
}

/// Returns an array containing a detached signature.
pub fn  crypto_sign_signature(
  sig: &mut[u8], m: &[u8], sk: &[u8], seed: Option<&[u8]>
)
{
  let mut ctx = SpxCtx::default();

  let mut sk_prf = [0u8; SPX_N];
  sk_prf.copy_from_slice(&sk[SPX_N..SPX_N*2]);
  let mut pk = [0u8; SPX_N * 2];
  pk[..SPX_N*2].copy_from_slice(&sk[SPX_N*2..SPX_N*4]);

  let mut optrand = [0u8; SPX_N];
  let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
  let mut root = [0u8; SPX_N];

  let mut tree = 0u64;
  let mut idx_leaf =  0u32;
  let mut wots_addr = [0u32; 8];
  let mut tree_addr = [0u32; 8];

  let mut idx = 0usize;

  ctx.sk_seed.copy_from_slice(&sk[..SPX_N]);
  ctx.pub_seed.copy_from_slice(&pk[..SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  initialize_hash_function(&mut ctx);

  set_type(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);

  // Optionally, signing can be made non-deterministic using optrand.
  // This can help counter side-channel attacks that would benefit from
  // getting a large number of traces when the signer uses the same nodes.
  match seed {
    Some(deterministic) => optrand.copy_from_slice(&deterministic),
    None => randombytes(&mut optrand, SPX_N)
  }
  
  // Compute the digest randomization value.
  gen_message_random(sig, &sk_prf, &optrand, m, m.len(), &ctx);

  // Derive the message digest and leaf index from R, PK and M.
  hash_message(
    &mut mhash, &mut tree, &mut idx_leaf, sig, &pk, m, m.len(), &ctx
  );
  idx += SPX_N;

  set_tree_addr(&mut wots_addr, tree);
  set_keypair_addr(&mut wots_addr, idx_leaf);

  // Sign the message hash using FORS.
  fors_sign(&mut sig[idx..], &mut root, &mhash, &ctx, &mut wots_addr);
  idx += SPX_FORS_BYTES;

  for i in 0..SPX_D  {
      set_layer_addr(&mut tree_addr, i as u32);
      set_tree_addr(&mut tree_addr, tree);

      copy_subtree_addr(&mut wots_addr, &mut tree_addr);
      set_keypair_addr(&mut wots_addr, idx_leaf);

      merkle_sign(
        &mut sig[idx..], &mut root, &ctx, 
        &mut wots_addr, &mut tree_addr, idx_leaf
      );
      idx += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

      // Update the indices for the next layer.
      idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1)) as u32;
      tree = tree >> SPX_TREE_HEIGHT;
  }
}

/// Verifies a detached signature and message under a given public key.
pub fn crypto_sign_verify(sig: &[u8], msg: &[u8], pk: &[u8]) -> Result<(), SigError>
{
  if sig.len() != SPX_BYTES {
    return Err(SigError::Input)
  }
  let mut ctx = SpxCtx::default();
  let pub_root: &[u8] = &pk[SPX_N..];
  let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
  let mut wots_pk = [0u8; SPX_WOTS_BYTES];
  let (mut root, mut leaf) = ([0u8; SPX_N], [0u8; SPX_N]);
  let mut tree = 0u64;
  let mut idx_leaf =  0u32;
  let (mut wots_addr, mut tree_addr, mut wots_pk_addr) = ([0u32; 8], [0u32; 8], [0u32; 8]);
  let mut idx = 0usize;
  
  ctx.pub_seed[..].copy_from_slice(&pk[..SPX_N]);

  // This hook allows the hash function instantiation to do whatever
  // preparation or computation it needs, based on the public seed.
  initialize_hash_function(&mut ctx);

  set_type(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
  set_type(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type(&mut wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

  // Derive the message digest and leaf index from R || PK || M.
  // The additional SPX_N is a result of the hash domain separator.
  hash_message(
    &mut mhash, &mut tree, &mut idx_leaf, sig, 
    pk, &msg, msg.len(), &ctx
  );
  idx += SPX_N;

  // Layer correctly defaults to 0, so no need to set_layer_addr
  set_tree_addr(&mut wots_addr, tree);
  set_keypair_addr(&mut wots_addr, idx_leaf);

  fors_pk_from_sig(&mut root, &sig[idx..], &mhash, &ctx, &mut wots_addr);
  idx += SPX_FORS_BYTES;

  // For each subtree..
  for i in 0..SPX_D  {
    set_layer_addr(&mut tree_addr, i as u32);
    set_tree_addr(&mut tree_addr, tree);
    copy_subtree_addr(&mut wots_addr, &mut tree_addr);
    set_keypair_addr(&mut wots_addr, idx_leaf);

    copy_keypair_addr(&mut wots_pk_addr, &mut wots_addr);

    // The WOTS public key is only correct if the signature was correct.
    // Initially, root is the FORS pk, but on subsequent iterations it is
    // the root of the subtree below the currently processed subtree.
    wots_pk_from_sig(&mut wots_pk, &sig[idx..], &root, &ctx, &mut wots_addr);
    idx += SPX_WOTS_BYTES;

    // Compute the leaf node using the WOTS public key.
    thash::<SPX_WOTS_LEN>(&mut leaf, Some(&wots_pk), &ctx, &wots_pk_addr);

    // Compute the root node of this subtree.
    compute_root(
      &mut root, &leaf, idx_leaf, 0, &sig[idx..], 
      SPX_TREE_HEIGHT as u32, &ctx, &mut tree_addr
    );
    idx += SPX_TREE_HEIGHT * SPX_N;

    // Update the indices for the next layer.
    idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1)) as u32;
    tree = tree >> SPX_TREE_HEIGHT;
  }

  // Check if the root node equals the root node in the public key.
  if root != pub_root {
    return Err(SigError::Verify);
  }

  return Ok(());
}