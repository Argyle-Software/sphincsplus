use crate::{ params::*, utils::*, offsets::* };

// This could probably be better represented as an enum with associated constants 
pub const SPX_ADDR_TYPE_WOTS: u32 = 0;
pub const SPX_ADDR_TYPE_WOTSPK: u32 = 1;
pub const SPX_ADDR_TYPE_HASHTREE: u32 = 2;
pub const SPX_ADDR_TYPE_FORSTREE: u32 = 3;
pub const SPX_ADDR_TYPE_FORSPK: u32 = 4;
pub const SPX_ADDR_TYPE_WOTSPRF: u32 = 5;
pub const SPX_ADDR_TYPE_FORSPRF: u32 = 6;

// Replaces the uint8_t addr cast in C reference implementation
fn set_addr(addr: &mut[u32], offset: usize, value: u32) 
{
  let mut addr_bytes = address_to_bytes(addr); 
  addr_bytes[offset] = value as u8;
  bytes_to_address(addr, &addr_bytes);
}

/// Specify which level of Merkle tree (the "layer") we're working on
pub fn set_layer_addr(addr: &mut [u32], layer: u32)
{ 
  set_addr(addr, SPX_OFFSET_LAYER, layer);
}

/// Specify which Merkle tree within the level (the "tree address") we're working on
pub fn set_tree_addr(addr: &mut [u32], tree: u64)
{
  let be64 = tree.to_be_bytes();
  let mut tmp_addr = address_to_bytes(&addr);
  tmp_addr[SPX_OFFSET_TREE..SPX_OFFSET_TREE+8].copy_from_slice(&be64);
  bytes_to_address(addr, &tmp_addr);
}

/// Specify the reason we'll use this address structure for, that is, what
/// hash will we compute with it.  This is used so that unrelated types of
/// hashes don't accidentally get the same address structure.  The type will be
/// one of the SPX_ADDR_TYPE constants
pub fn set_type(addr: &mut [u32], addr_type: u32)
{
  set_addr(addr, SPX_OFFSET_TYPE, addr_type);
}

/// Copy the layer and tree fields of the address structure.  This is used
/// when we're doing multiple types of hashes within the same Merkle tree
pub fn copy_subtree_addr(out: &mut [u32], input: &mut [u32])
{   
  let buf = address_to_bytes(input);
  let mut out_bytes = address_to_bytes(out);
  out_bytes[..SPX_OFFSET_TREE + 8 ]
    .copy_from_slice(&buf[..SPX_OFFSET_TREE + 8]);
  bytes_to_address(out, &out_bytes);
}

/// OTS ADDRESS FUNCTIONS

/// Specify which Merkle leaf we're working on; that is, which OTS keypair
/// we're talking about.
pub fn set_keypair_addr(addr: &mut [u32], keypair: u32)
{
  // We have > 256 OTS at the bottom of the Merkle tree; to specify 
  // which one, we'd need to express it input two bytes  
  if SPX_FULL_HEIGHT/SPX_D > 8 {
    set_addr(addr, SPX_OFFSET_KP_ADDR2, keypair >> 8);
  }
  set_addr(addr, SPX_OFFSET_KP_ADDR1, keypair);
}

/// Copy the layer, tree and keypair fields of the address structure.  This is
/// used when we're doing multiple things within the same OTS keypair
pub fn copy_keypair_addr(out: &mut [u32], input: &[u32])
{ 
  let in_buf = address_to_bytes(input);
  let mut out_buf = address_to_bytes(out);
  out_buf[..SPX_OFFSET_TREE + 8].copy_from_slice(&in_buf[..SPX_OFFSET_TREE + 8]);

  if SPX_FULL_HEIGHT / SPX_D > 8 {
    out_buf[SPX_OFFSET_KP_ADDR2] = in_buf[SPX_OFFSET_KP_ADDR2];
  }
  out_buf[SPX_OFFSET_KP_ADDR1] = in_buf[SPX_OFFSET_KP_ADDR1];
  bytes_to_address(out, &out_buf);
}

/// Specify which Merkle chain within the OTS we're working with the chain address
pub fn set_chain_addr(addr: &mut [u32], chain: u32)
{
  set_addr(addr, SPX_OFFSET_CHAIN_ADDR, chain);
}

/// Specify where in the Merkle chain we are the hash address
pub fn set_hash_addr(addr: &mut [u32], hash: u32)
{
  set_addr(addr, SPX_OFFSET_HASH_ADDR, hash);
}

/// These functions are used for all hash tree addresses (including FORS).

/// Specify the height of the node in the Merkle/FORS tree we are in the tree height
pub fn set_tree_height(addr: &mut [u32], tree_height: u32)
{
  set_addr(addr, SPX_OFFSET_TREE_HGT, tree_height);
}

///Specify the distance from the left edge of the node in the Merkle/FORS tree
pub fn set_tree_index(addr: &mut [u32], tree_index: u32)
{
  let mut tmp_addr = address_to_bytes(&addr);
  u32_to_bytes(&mut tmp_addr[SPX_OFFSET_TREE_INDEX..], tree_index);
  bytes_to_address(addr, &tmp_addr);
}
