use crate::context::SpxCtx;
use crate::hash::*;
use crate::thash::*;
use crate::address::*;
use crate::params::*;

/// This is here to provide an interface to the internal wots_gen_leafx1
/// routine.  While this routine is not referenced in the package outside of
/// wots.c, it is called from the stand-alone benchmark code to characterize
/// the performance
#[derive(Clone, Copy)]
pub struct LeafInfoX1 {
    pub wots_sig: [u8; SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES],
    pub wots_sign_leaf: u32, // The index of the WOTS we're using to sign
    pub wots_steps: [u32; SPX_WOTS_LEN],
    pub leaf_addr: [u32; 8],
    pub pk_addr: [u32; 8],
}

impl Default for LeafInfoX1 {
  fn default() -> Self {
      Self {
        wots_sig: [0u8; SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES],
        wots_sign_leaf: 0u32,
        wots_steps: [0u32; SPX_WOTS_LEN],
        leaf_addr: [0u32; 8],
        pk_addr: [0u32; 8],
      }
  }
}

/// This generates a WOTS public key
/// It also generates the WOTS signature if leaf_info indicates
/// that we're signing with this WOTS key
pub fn wots_gen_leafx1(
  dest: &mut[u8],
  ctx: &SpxCtx,
  leaf_idx: u32,
  v_info: &mut LeafInfoX1 
) 
{
  let mut leaf_addr = v_info.leaf_addr;
  let mut pk_addr = v_info.pk_addr;
  
  let mut pk_buffer = [0u8;  SPX_WOTS_BYTES ];
  let wots_k_mask;

  if leaf_idx == v_info.wots_sign_leaf {
    // We're traversing the leaf that's signing; generate the WOTS signature
    wots_k_mask = 0;
  } else {
    // Nope, we're just generating pk's; turn off the signature logic
    wots_k_mask = !0;
  }

  set_keypair_addr( &mut leaf_addr, leaf_idx );
  set_keypair_addr( &mut pk_addr, leaf_idx );

  let mut idx = 0usize;
  for i in 0 ..SPX_WOTS_LEN {
    // Set wots_k to the step if we're generating a signature, ~0 if we're not
    let wots_k = v_info.wots_steps[i] | wots_k_mask; 

    // Start with the secret seed
    set_chain_addr(&mut leaf_addr, i as u32);
    set_hash_addr(&mut leaf_addr, 0);
    set_type(&mut leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

    prf_addr(&mut pk_buffer[idx..], ctx, &mut leaf_addr);

    set_type(&mut leaf_addr, SPX_ADDR_TYPE_WOTS);

    // Iterate down the WOTS chain
    let mut k = 0;
    loop {
      // Check if this is the value that needs to be saved as a
      // part of the WOTS signature
      if k == wots_k {
        let start = i * SPX_N;
        v_info.wots_sig[start..start + SPX_N]
          .copy_from_slice(&pk_buffer[idx..idx+SPX_N]);
      }

      // Check if we hit the top of the chain
      if k == SPX_WOTS_W as u32 - 1 {
        break;
      } 

      // Iterate one step on the chain
      set_hash_addr(&mut leaf_addr, k);

      thash::<1>(&mut pk_buffer[idx..], None, ctx, &leaf_addr);

      k += 1;
    }
    idx += SPX_N; 
  }

  // Do the final thash to generate the public keys
  thash::<SPX_WOTS_LEN>(dest, Some(&pk_buffer), ctx, &pk_addr);
}
