use core::hash::Hash;

use crate::api::HashMode;
use crate::api::SecLevel;
use crate::api::TreeHash;
use crate::context::*;
use crate::utilsx1::*;
use crate::wots::*;
use crate::wotsx1::*;
use crate::address::*;
use crate::params::*;


/// This generates a Merkle signature (WOTS signature followed by the Merkle
/// authentication path).  This is in this file because most of the complexity
/// is involved with the WOTS signature; the Merkle authentication path logic
/// is mostly hidden in treehashx4
pub fn merkle_sign<H: HashMode, L: SecLevel, T: TreeHash>(
  sig: &mut[u8], root: &mut[u8], ctx: &SpxCtx<L>, wots_addr: &mut[u32], 
  tree_addr: &mut[u32], idx_leaf: u32
)
  where [(); L::SPX_N]:,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_WOTS_LEN]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
{
  let mut info = LeafInfoX1::default();
  let mut steps = [0u32; L::SPX_WOTS_LEN];
  chain_lengths::<L>(&mut steps, root);
  info.wots_steps = steps;

  set_type::<H>(tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type::<H>(&mut info.pk_addr, SPX_ADDR_TYPE_WOTSPK);
  copy_subtree_addr::<H>(&mut info.leaf_addr, wots_addr);
  copy_subtree_addr::<H>(&mut info.pk_addr, wots_addr);

  info.wots_sign_leaf = idx_leaf;

  wots_treehashx1::<{L::SPX_TREE_HEIGHT}, {L::WOTS_STACK_LEN}, H, L, T>(
    root, &mut sig[L::SPX_WOTS_BYTES..], ctx, idx_leaf, 0,tree_addr, &mut info
  );
  sig[..L::SPX_WOTS_BYTES].clone_from_slice(&info.wots_sig[..L::SPX_WOTS_BYTES]);
}

/// Compute root node of the top-most subtree.
pub fn merkle_gen_root<H:HashMode, L: SecLevel, T: TreeHash>(
  root: &mut[u8], ctx: &SpxCtx<L>
)
  where [(); L::SPX_N]:,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_WOTS_LEN]:,
        [(); L::WOTS_STACK_LEN]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); (L::SPX_WOTS_LEN2 * L::SPX_WOTS_LOGW + 7) / 8]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
{
  // We do not need the auth path in key generation, but it simplifies the
  // code to have just one treehash routine that computes both root and path
  // in one function.
  let mut auth_path = [0u8; L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES];
  let mut top_tree_addr = [0u32; 8];
  let mut wots_addr = [0u32; 8];

  set_layer_addr::<H>(&mut top_tree_addr, L::SPX_D as u32 - 1);
  set_layer_addr::<H>(&mut wots_addr, L::SPX_D as u32 - 1);

  merkle_sign::<H, L, T>(
    &mut auth_path, root, ctx,
    &mut wots_addr, &mut top_tree_addr, 
    !0 // ~0 means "don't bother generating an auth path
  ); 
}
