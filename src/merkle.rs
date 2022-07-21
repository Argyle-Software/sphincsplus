use crate::context::*;
use crate::utilsx1::*;
use crate::wots::*;
use crate::wotsx1::*;
use crate::address::*;
use crate::params::*;

const STACK_LEN: usize = SPX_TREE_HEIGHT * SPX_N;

/// This generates a Merkle signature (WOTS signature followed by the Merkle
/// authentication path).  This is in this file because most of the complexity
/// is involved with the WOTS signature; the Merkle authentication path logic
/// is mostly hidden in treehashx4
pub fn merkle_sign(sig: &mut[u8], root: &mut[u8],
                 ctx: &SpxCtx,
                 wots_addr: &mut[u32], tree_addr: &mut[u32],
                 idx_leaf: u32)
{
  let mut info = LeafInfoX1::default();
  let mut steps = [0u32; SPX_WOTS_LEN];
  chain_lengths(&mut steps, root);
  info.wots_steps = steps;

  set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
  set_type(&mut info.pk_addr, SPX_ADDR_TYPE_WOTSPK);
  copy_subtree_addr(&mut info.leaf_addr, wots_addr);
  copy_subtree_addr(&mut info.pk_addr, wots_addr);

  info.wots_sign_leaf = idx_leaf;

  wots_treehashx1::<SPX_TREE_HEIGHT, STACK_LEN>(
    root, &mut sig[SPX_WOTS_BYTES..], ctx, idx_leaf, 0,tree_addr, &mut info
  );
  sig[..SPX_WOTS_BYTES].clone_from_slice(&info.wots_sig[..SPX_WOTS_BYTES]);
}

/// Compute root node of the top-most subtree.
pub fn merkle_gen_root(root: &mut[u8], ctx: &SpxCtx)
{
  // We do not need the auth path in key generation, but it simplifies the
  // code to have just one treehash routine that computes both root and path
  // in one function.
  let mut auth_path = [0u8; SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
  let mut top_tree_addr = [0u32; 8];
  let mut wots_addr = [0u32; 8];

  set_layer_addr(&mut top_tree_addr, SPX_D as u32 - 1);
  set_layer_addr(&mut wots_addr, SPX_D as u32 - 1);

  merkle_sign(
    &mut auth_path, root, ctx,
    &mut wots_addr, &mut top_tree_addr, 
    !0 // ~0 means "don't bother generating an auth path
  ); 
}
