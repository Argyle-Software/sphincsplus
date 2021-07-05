use crate::context::SpxCtx;
use crate::params::*;
// use crate::hash::*;
// use crate::thash::*;
use crate::address::*;
use crate::thash_haraka_simple::thash;
use crate::thash_haraka_simple::thash_inplace;


// Converts the value of 'in' to 'outlen' bytes in big-endian byte order
pub fn ull_to_bytes(out: &mut[u8], outlen: usize,
                  mut input: u64)
{
    /* Iterate over out in decreasing order, for big-endianness. */
    // for (i = outlen - 1; i >= 0; i -= 1)
    for i in (0..outlen).rev() {
        out[i] = (input & 0xff) as u8;
        input = input >> 8;
    }
}

pub fn u32_to_bytes(out: &mut[u8], input: u32)
{
    out[0] = (input >> 24) as u8;
    out[1] = (input >> 16) as u8;
    out[2] = (input >> 8) as u8;
    out[3] = input as u8;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
pub fn bytes_to_ull(input: &[u8], inlen: usize ) -> u64
{
    let mut retval = 0u64;

    for i in 0..inlen  {
        retval |= (input[i] as u64) << (8*(inlen - 1 - i));
    }
    return retval;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
pub fn compute_root(root: &mut[u8], leaf: &[u8],
                  mut leaf_idx: u32, mut idx_offset: u32,
                  auth_path: &[u8], tree_height: u32,
                  ctx: &SpxCtx, addr: &mut [u32; 8])
{
    let mut buffer = [0u8; 2 * SPX_N];
    let mut idx = 0usize;

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) != 0 {
        buffer[SPX_N..].copy_from_slice(&leaf[..SPX_N]);
        buffer[..SPX_N].copy_from_slice(&auth_path[..SPX_N]);
    }
    else {
        buffer[..SPX_N].copy_from_slice(&leaf[..SPX_N]);
        buffer[SPX_N..].copy_from_slice(&auth_path[..SPX_N]);
    }
    idx += SPX_N;

    for i in 0..(tree_height - 1) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        
        if (leaf_idx & 1) != 0 {
          let tmp_buffer = buffer.clone();
          let mut buf = [0u8; SPX_ADDR_BYTES + 2 * SPX_N];
            thash(&mut buffer[SPX_N..], &tmp_buffer, 2, &mut buf, ctx, *addr);
            buffer[..SPX_N].copy_from_slice(&auth_path[idx..idx + SPX_N]);
        }
        else {
          let mut buf = [0u8; SPX_ADDR_BYTES + 2 * SPX_N];
            thash_inplace(&mut buffer, 2, ctx, *addr, &mut buf);
            buffer[SPX_N..].copy_from_slice(&auth_path[idx..idx + SPX_N]);
        }
        idx += SPX_N;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    let mut buf = [0u8; SPX_ADDR_BYTES + 2 * SPX_N];
    thash(root, &buffer, 2, &mut buf, ctx, *addr);
}

// /**
//  * For a given leaf index, computes the authentication path and the resulting
//  * root node using Merkle's TreeHash algorithm.
//  * Expects the layer and tree parts of the tree_addr to be set, as well as the
//  * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
//  * Applies the offset idx_offset to indices before building addresses, so that
//  * it is possible to continue counting indices across trees.
//  */
// pub fn treehash(root: &mut[u8], auth_path: &mut[u8], ctx: &SpxCtx,
//               leaf_idx: u32, idx_offset: u32, tree_height: u32,
//               gen_leaf: FnMut,
//               tree_addr: [u32; 8])
// {
//     // SPX_VLA(uint8_t, stack, (tree_height+1)*SPX_N);
//     // SPX_VLA(unsigned int, heights, tree_height+1);
//     let mut heights = 
//     let mut offset =  0u32;
//     let mut idx =  0u32;
//     let mut tree_idx =  0u32;

//     for idx in 0..tree_height {
//         /* Add the next leaf node to the stack. */
//         gen_leaf(stack + offset*SPX_N, ctx, idx + idx_offset, tree_addr);
//         offset += 1;
//         heights[offset - 1] = 0;

//         /* If this is a node we need for the auth path.. */
//         if ((leaf_idx ^ 0x1) == idx) {
//             memcpy(auth_path, stack + (offset - 1)*SPX_N, SPX_N);
//         }

//         /* While the top-most nodes are of equal height.. */
//         while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
//             /* Compute index of the new node, in the next layer. */
//             tree_idx = (idx >> (heights[offset - 1] + 1));

//             /* Set the address of the node we're creating. */
//             set_tree_height(tree_addr, heights[offset - 1] + 1);
//             set_tree_index(tree_addr,
//                            tree_idx + (idx_offset >> (heights[offset-1] + 1)));
//             /* Hash the top-most nodes from the stack together. */
//             thash(stack + (offset - 2)*SPX_N,
//                   stack + (offset - 2)*SPX_N, 2, ctx, tree_addr);
//             offset -= 1;
//             /* Note that the top-most node is now one layer higher. */
//             heights[offset - 1] += 1;

//             /* If this is a node we need for the auth path.. */
//             if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
//                 memcpy(auth_path + heights[offset - 1]*SPX_N,
//                        stack + (offset - 1)*SPX_N, SPX_N);
//             }
//         }
//     }
//     &root[..SPX_N].copy_from_slice(&stack[..SPX_N]);
// }
