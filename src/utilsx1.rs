use crate::api::{HashMode, SecLevel, TreeHash};
use crate::context::SpxCtx;
use crate::fors::{ ForsGenLeafInfo, fors_gen_leafx1 };
use crate::params::*;
use crate::address::*;
use crate::thash::*;
use crate::wotsx1::{ LeafInfoX1, wots_gen_leafx1 };

// TODO: dedup treehash functions

/// Generate the entire Merkle tree, computing the authentication path for
/// leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
/// Expects the layer and tree parts of the tree_addr to be set, as well as the
/// tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE)
/// This expects tree_addr to be initialized to the addr structures for the 
/// Merkle tree nodes.
/// 
/// Applies the offset idx_offset to indices before building addresses, so that
/// it is possible to continue counting indices across trees.
/// This works by using the standard Merkle tree building algorithm.
/// T: tree_height
/// S: stack.len()
pub fn wots_treehashx1<const TH: usize, const S: usize, H, L, T>(
  root: &mut[u8], auth_path: &mut[u8], ctx: &SpxCtx<L>, leaf_idx: u32, 
  idx_offset: u32, tree_addr: &mut[u32], info: &mut LeafInfoX1<L>
)
  where H: HashMode,
        L: SecLevel,
        T: TreeHash,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_TREE_HEIGHT * L::SPX_N + L::SPX_WOTS_BYTES]:,
        [(); L::SPX_WOTS_LEN]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + L::SPX_WOTS_LEN * L::SPX_N]:
{
  let mut idx =  0u32;
  let max_idx = (1 << TH) - 1;
  let mut stack = [0u8; S];
  loop {
    // Current logical node is at index[L::SPX_N].
    // We do this to minimize the number of copies needed during a thash
    let mut current = [0u8; 2*L::SPX_N];    

    wots_gen_leafx1::<H, L, T>( &mut current[L::SPX_N..], ctx, idx + idx_offset, info);

    // Now combine the freshly generated right node with previously
    //  generated left ones
    let mut internal_idx_offset = idx_offset; //TODO: Refactor 
    let mut internal_idx = idx;
    let mut internal_leaf = leaf_idx;
    // The height we are in the Merkle tree
    let mut h =  0u32;      
    loop {

      // Check if we hit the top of the tree
      if h == TH as u32 {
        // We hit the root; return it
        root[..L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
        return;
      }
      // Check if the node we have is a part of the
      //authentication path; if it is, write it out
      let start = h as usize * L::SPX_N;
      if (internal_idx ^ internal_leaf) == 0x01 {
        auth_path[start..start + L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
      }

       // Check if we're at a left child; if so, stop going up the stack
       // Exception: if we've reached the end of the tree, keep on going
       // (so we combine the last 4 nodes into the one root node in two
       // more iterations)
      if (internal_idx & 1) == 0 && idx < max_idx {
        break;
      }

      // Ok, we're at a right node
      // Now combine the left and right logical nodes together
      // Set the address of the node we're creating.
      internal_idx_offset >>= 1;
      set_tree_height::<H>(tree_addr, h + 1);
      set_tree_index::<H>(tree_addr, internal_idx/2 + internal_idx_offset );

      current[  ..L::SPX_N].copy_from_slice(&stack[start..start + L::SPX_N]);
      let tmp_current = current.clone();
      T::thash::<2, L>( &mut current[L::SPX_N..], Some(&tmp_current), ctx, tree_addr);
      h += 1; 
      internal_idx >>= 1;
      internal_leaf >>= 1;
    }

    // We've hit a left child; save the current for when we get the
    // corresponding right right
    let start = h as usize * L::SPX_N;
    stack[start..start + L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
    idx += 1
  }
}

pub fn fors_treehashx1<const TH: usize, const S: usize, H, L, T>(
  root: &mut[u8], auth_path: &mut[u8], ctx: &SpxCtx<L>, leaf_idx: u32, 
  idx_offset: u32, tree_addr: &mut[u32; 8], info: &mut ForsGenLeafInfo
)
  where H: HashMode,
        L: SecLevel,
        T: TreeHash,
        [(); L::SPX_N]:,
        [(); 2*L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 2 * L::SPX_N]:,
        [(); L::SPX_ADDR_BYTES + 1 * L::SPX_N]:,
{
  let mut idx =  0u32;
  let max_idx = (1 << TH) - 1;
  let mut stack = [0u8; S];
  loop {
    let mut current = [0u8; 2*L::SPX_N];    

    fors_gen_leafx1::<H, L, T>(&mut current[L::SPX_N..], ctx, idx + idx_offset, info);

    let mut internal_idx_offset = idx_offset; //TODO: Refactor 
    let mut internal_idx = idx;
    let mut internal_leaf = leaf_idx;
    let mut h =  0u32;      
    loop {
      if h == TH as u32 {
        root[..L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
        return;
      }
      let start = h as usize * L::SPX_N;
      if (internal_idx ^ internal_leaf) == 0x01 {
        auth_path[start..start + L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
      }

      if (internal_idx & 1) == 0 && idx < max_idx {
        break;
      }

      internal_idx_offset >>= 1;
      set_tree_height::<H>(tree_addr, h + 1);
      set_tree_index::<H>(tree_addr, internal_idx/2 + internal_idx_offset );

      current[..L::SPX_N].copy_from_slice(&stack[start..start + L::SPX_N]);
      let tmp_current = current.clone();
      T::thash::<2, L>( &mut current[L::SPX_N..], Some(&tmp_current), ctx, tree_addr);
      h += 1; 
      internal_idx >>= 1;
      internal_leaf >>= 1;
    }

    let start = h as usize * L::SPX_N;
    stack[start..start + L::SPX_N].copy_from_slice(&current[L::SPX_N..L::SPX_N*2]);
    idx += 1
  }
}