use crate::context::SpxCtx;
use crate::params::*;
use crate::thash::*;
use crate::address::*;

/// Converts the value of 'in' to 'outlen' bytes in big-endian byte order
pub fn ull_to_bytes(out: &mut[u8], outlen: usize, mut input: u64)
{
  // Iterate over out in decreasing order, for big-endianness.
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

/// Converts the inlen bytes in 'in' from big-endian byte order to an integer.
pub fn bytes_to_ull(input: &[u8], inlen: usize ) -> u64
{
  let mut retval = 0u64;
  for i in 0..inlen  {
    retval |= (input[i] as u64) << (8*(inlen - 1 - i));
  }
  return retval;
}

/// Computes a root node given a leaf and an auth path.
/// Expects address to be complete other than the tree_height and tree_index.
pub fn compute_root(
  root: &mut[u8], leaf: &[u8], mut leaf_idx: u32, mut idx_offset: u32,
  auth_path: &[u8], tree_height: u32, ctx: &SpxCtx, addr: &mut[u32; 8]
)
{
  let mut buffer = [0u8; 2 * SPX_N];
  let mut idx = 0usize;

  // If leaf_idx is odd (last bit = 1), current path element is a right child
  // and auth_path has to go left. Otherwise it is the other way around.
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
    // Set the address of the node we're creating.
    set_tree_height(addr, i + 1);
    set_tree_index(addr, leaf_idx + idx_offset);

    // Pick the right or left neighbour, depending on parity of the node.
    if (leaf_idx & 1) != 0 {
      let tmp_buffer = buffer.clone();
      thash::<2>(&mut buffer[SPX_N..], Some(&tmp_buffer), ctx, addr);
      buffer[..SPX_N].copy_from_slice(&auth_path[idx..][..SPX_N]);
  }
    else {
      thash::<2>(&mut buffer, None, ctx, addr);
      buffer[SPX_N..].copy_from_slice(&auth_path[idx..][..SPX_N]);
    }
    idx += SPX_N;
  }

  // The last iteration is exceptional; we do not copy an auth_path node.
  leaf_idx >>= 1;
  idx_offset >>= 1;
  set_tree_height(addr, tree_height);
  set_tree_index(addr, leaf_idx + idx_offset);
  thash::<2>(root, Some(&buffer), ctx, addr);
}

pub fn bytes_to_address(addr: &mut[u32], bytes: &[u8; 32])
{
  for i in 0..8 {
    let mut addr_i = [0u8; 4];
    addr_i.copy_from_slice(&bytes[i*4..][..4]);
    addr[i] = u32::from_ne_bytes(addr_i);
  }
}

pub fn address_to_bytes(addr: &[u32]) -> [u8; 32] 
{
  let mut out = [0u8; 32];
  for i in 0..8 {
    out[i*4..][..4].copy_from_slice(&addr[i].to_ne_bytes()); //TODO: Check on BE in QEMU
  }
  out
}