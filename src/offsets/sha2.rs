/// Offsets of various fields in the address structure when we use SHA2 as
/// the Sphincs+ hash function

pub const SPX_OFFSET_LAYER: usize = 0;   //The byte used to specify the Merkle tree layer
pub const SPX_OFFSET_TREE: usize = 1;   //The start of the 8 byte field used to specify the tree
pub const SPX_OFFSET_TYPE: usize = 9;   //The byte used to specify the hash type (reason)
pub const SPX_OFFSET_KP_ADDR2: usize = 12;  //The high byte used to specify the key pair (which one-time signature)
pub const SPX_OFFSET_KP_ADDR1: usize = 13;  //The low byte used to specify the key pair
pub const SPX_OFFSET_CHAIN_ADDR: usize = 17;  //The byte used to specify the chain address (which Winternitz chain)
pub const SPX_OFFSET_HASH_ADDR: usize = 21;  //The byte used to specify the hash address (where in the Winternitz chain)
pub const SPX_OFFSET_TREE_HGT: usize = 17;  //The byte used to specify the height of this node in the FORS or Merkle tree
pub const SPX_OFFSET_TREE_INDEX: usize = 18; //The start of the 4 byte field used to specify the node in the FORS or Merkle tree