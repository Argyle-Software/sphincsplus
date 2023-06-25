/// Constant time implementation of the Haraka hash function.
///
/// The bit-sliced implementation of the AES round functions are
/// based on the AES implementation in BearSSL written 
/// by Thomas Pornin <pornin@bolet.org>

use core::ops::{BitXor, BitAnd, Not};
use crate::context::SpxCtx;
use crate::params::SPX_N;

const HARAKAS_RATE: usize = 32;

const HARAKA512_RC64: [[u64; 8]; 10] = [
  [0x24cf0ab9086f628b, 0xbdd6eeecc83b8382, 0xd96fb0306cdad0a7, 0xaace082ac8f95f89, 0x449d8e8870d7041f, 0x49bb2f80b2b3e2f8, 0x0569ae98d93bb258, 0x23dc9691e7d6a4b1],
  [0xd8ba10ede0fe5b6e, 0x7ecf7dbe424c7b8e, 0x6ea9949c6df62a31, 0xbf3f3c97ec9c313e, 0x241d03a196a1861e, 0xead3a51116e5a2ea, 0x77d479fcad9574e3, 0x18657a1af894b7a0],
  [0x10671e1a7f595522, 0xd9a00ff675d28c7b, 0x2f1edf0d2b9ba661, 0xb8ff58b8e3de45f9, 0xee29261da9865c02, 0xd1532aa4b50bdf43, 0x8bf858159b231bb1, 0xdf17439d22d4f599],
  [0xdd4b2f0870b918c0, 0x757a81f3b39b1bb6, 0x7a5c556898952e3f, 0x7dd70a16d915d87a, 0x3ae61971982b8301, 0xc3ab319e030412be, 0x17c0033ac094a8cb, 0x5a0630fc1a8dc4ef],
  [0x17708988c1632f73, 0xf92ddae090b44f4f, 0x11ac0285c43aa314, 0x509059941936b8ba, 0xd03e152fa2ce9b69, 0x3fbcbcb63a32998b, 0x6204696d692254f7, 0x915542ed93ec59b4],
  [0xf4ed94aa8879236e, 0xff6cb41cd38e03c0, 0x069b38602368aeab, 0x669495b820f0ddba, 0xf42013b1b8bf9e3d, 0xcf935efe6439734d, 0xbc1dcf42ca29e3f8, 0x7e6d3ed29f78ad67],
  [0xf3b0f6837ffcddaa, 0x3a76faef934ddf41, 0xcec7ae583a9c8e35, 0xe4dd18c68f0260af, 0x2c0e5df1ad398eaa, 0x478df5236ae22e8c, 0xfb944c46fe865f39, 0xaa48f82f028132ba],
  [0x231b9ae2b76aca77, 0x292a76a712db0b40, 0x5850625dc8134491, 0x73137dd469810fb5, 0x8a12a6a202a474fd, 0xd36fd9daa78bdb80, 0xb34c5e733505706f, 0xbaf1cdca818d9d96],
  [0x2e99781335e8c641, 0xbddfe5cce47d560e, 0xf74e9bf32e5e040c, 0x1d7a709d65996be9, 0x670df36a9cf66cdd, 0xd05ef84a176a2875, 0x0f888e828cb1c44e, 0x1a79e9c9727b052c],
  [0x83497348628d84de, 0x2e9387d51f22a754, 0xb000068da2f852d6, 0x378c9e1190fd6fe5, 0x870027c316de7293, 0xe51a9d4462e047bb, 0x90ecf7f8c6251195, 0x655953bfbed90a9c],
];

fn br_dec32le(src: &[u8]) -> u32
{
  src[0] as u32
  | (src[1] as u32) << 8
  | (src[2] as u32) << 16
  | (src[3] as u32) << 24
}

fn br_range_dec32le(v: &mut [u32], mut num: usize, src: &[u8])
{
  let mut v_idx: usize = 0;
  let mut src_idx: usize = 0;
  while num > 0 { 
    num -= 1;
    v[v_idx] = br_dec32le(&src[src_idx..]);
    v_idx += 1;
    src_idx += 4;
  }
}

fn _br_swap32(mut x: u32) -> u32
{
  x = ((x & 0x00FF00FFu32 ) << 8) | ((x >> 8) & 0x00FF00FFu32);
  (x << 16) | (x >> 16)
}

fn  br_enc32le(dst: &mut [u8], x: u32) 
{
  dst[0] = x as u8;
  dst[1] = (x >> 8) as u8;
  dst[2] = (x >> 16) as u8;
  dst[3] = (x >> 24) as u8;
}

fn br_range_enc32le(dst: &mut [u8], v: &[u32], mut num: usize)
{
  let mut v_idx = 0;
  let mut dst_idx = 0;
  while num > 0 {
    br_enc32le(&mut dst[dst_idx..], v[v_idx]);
    v_idx += 1;
    dst_idx += 4;
    num -= 1;
  }
}

// Generic function for u32 and u64
fn br_aes_ct_bitslice_sbox<T>(q: &mut [T])
where T: BitXor<Output = T> + BitAnd<Output = T> + Not<Output = T> + Copy
{
  // This S-box implementation is a straightforward translation of
  // the circuit described by Boyar and Peralta in "A new
  // combinational logic minimization technique with applications
  // to cryptology" (https://eprint.iacr.org/2009/191.pdf).
  // Note that variables x(input) and s(output) are numbered
  // in "reverse" order (x0 is the high bit, x7 is the low bit).
  let (x0, x1, x2, x3, x4, x5, x6, x7): (T, T, T, T, T, T, T, T);
  let (y1, y2, y3, y4, y5, y6, y7, y8, y9): (T, T, T, T, T, T, T, T, T);
  let (y10, y11, y12, y13, y14, y15, y16, y17, y18, y19): (T, T, T, T, T, T, T, T, T, T) ;
  let (y20, y21): (T, T) ;
  let (z0, z1, z2, z3, z4, z5, z6, z7, z8, z9): (T, T, T, T, T, T, T, T, T, T);
  let (z10, z11, z12, z13, z14, z15, z16, z17): (T, T, T, T, T, T, T, T);
  let (t0, t1, t2, t3, t4, t5, t6, t7, t8, t9): (T, T, T, T, T, T, T, T, T, T);
  let (t10, t11, t12, t13, t14, t15, t16, t17, t18, t19): (T, T, T, T, T, T, T, T, T, T);
  let (t20, t21, t22, t23, t24, t25, t26, t27, t28, t29): (T, T, T, T, T, T, T, T, T, T);
  let (t30, t31, t32, t33, t34, t35, t36, t37, t38, t39): (T, T, T, T, T, T, T, T, T, T);
  let (t40, t41, t42, t43, t44, t45, t46, t47, t48, t49): (T, T, T, T, T, T, T, T, T, T);
  let (t50, t51, t52, t53, t54, t55, t56, t57, t58, t59): (T, T, T, T, T, T, T, T, T, T);
  let (t60, t61, t62, t63, t64, t65, t66, t67): (T, T, T, T, T, T, T, T);
  let (s0, s1, s2, s3, s4, s5, s6, s7): (T, T, T, T, T, T, T, T);

  x0 = q[7];
  x1 = q[6];
  x2 = q[5];
  x3 = q[4];
  x4 = q[3];
  x5 = q[2];
  x6 = q[1];
  x7 = q[0];

  // Top linear transformation.
  y14 = x3 ^ x5;
  y13 = x0 ^ x6;
  y9 = x0 ^ x3;
  y8 = x0 ^ x5;
  t0 = x1 ^ x2;
  y1 = t0 ^ x7;
  y4 = y1 ^ x3;
  y12 = y13 ^ y14;
  y2 = y1 ^ x0;
  y5 = y1 ^ x6;
  y3 = y5 ^ y8;
  t1 = x4 ^ y12;
  y15 = t1 ^ x5;
  y20 = t1 ^ x1;
  y6 = y15 ^ x7;
  y10 = y15 ^ t0;
  y11 = y20 ^ y9;
  y7 = x7 ^ y11;
  y17 = y10 ^ y11;
  y19 = y10 ^ y8;
  y16 = t0 ^ y11;
  y21 = y13 ^ y16;
  y18 = x0 ^ y16;

  // Non-linear section.
  t2 = y12 & y15;
  t3 = y3 & y6;
  t4 = t3 ^ t2;
  t5 = y4 & x7;
  t6 = t5 ^ t2;
  t7 = y13 & y16;
  t8 = y5 & y1;
  t9 = t8 ^ t7;
  t10 = y2 & y7;
  t11 = t10 ^ t7;
  t12 = y9 & y11;
  t13 = y14 & y17;
  t14 = t13 ^ t12;
  t15 = y8 & y10;
  t16 = t15 ^ t12;
  t17 = t4 ^ t14;
  t18 = t6 ^ t16;
  t19 = t9 ^ t14;
  t20 = t11 ^ t16;
  t21 = t17 ^ y20;
  t22 = t18 ^ y19;
  t23 = t19 ^ y21;
  t24 = t20 ^ y18;

  t25 = t21 ^ t22;
  t26 = t21 & t23;
  t27 = t24 ^ t26;
  t28 = t25 & t27;
  t29 = t28 ^ t22;
  t30 = t23 ^ t24;
  t31 = t22 ^ t26;
  t32 = t31 & t30;
  t33 = t32 ^ t24;
  t34 = t23 ^ t33;
  t35 = t27 ^ t33;
  t36 = t24 & t35;
  t37 = t36 ^ t34;
  t38 = t27 ^ t36;
  t39 = t29 & t38;
  t40 = t25 ^ t39;

  t41 = t40 ^ t37;
  t42 = t29 ^ t33;
  t43 = t29 ^ t40;
  t44 = t33 ^ t37;
  t45 = t42 ^ t41;
  z0 = t44 & y15;
  z1 = t37 & y6;
  z2 = t33 & x7;
  z3 = t43 & y16;
  z4 = t40 & y1;
  z5 = t29 & y7;
  z6 = t42 & y11;
  z7 = t45 & y17;
  z8 = t41 & y10;
  z9 = t44 & y12;
  z10 = t37 & y3;
  z11 = t33 & y4;
  z12 = t43 & y13;
  z13 = t40 & y5;
  z14 = t29 & y2;
  z15 = t42 & y9;
  z16 = t45 & y14;
  z17 = t41 & y8;

  // Bottom linear transformation.
  t46 = z15 ^ z16;
  t47 = z10 ^ z11;
  t48 = z5 ^ z13;
  t49 = z9 ^ z10;
  t50 = z2 ^ z12;
  t51 = z2 ^ z5;
  t52 = z7 ^ z8;
  t53 = z0 ^ z3;
  t54 = z6 ^ z7;
  t55 = z16 ^ z17;
  t56 = z12 ^ t48;
  t57 = t50 ^ t53;
  t58 = z4 ^ t46;
  t59 = z3 ^ t54;
  t60 = t46 ^ t57;
  t61 = z14 ^ t57;
  t62 = t52 ^ t58;
  t63 = t49 ^ t58;
  t64 = z4 ^ t59;
  t65 = t61 ^ t62;
  t66 = z1 ^ t63;
  s0 = t59 ^ t63;
  s6 = t56 ^ !t62;
  s7 = t48 ^ !t60;
  t67 = t64 ^ t65;
  s3 = t53 ^ t66;
  s4 = t51 ^ t66;
  s5 = t47 ^ t65;
  s1 = t64 ^ !s3;
  s2 = t55 ^ !t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}

fn br_aes_ct_ortho(q: &mut [u32]) 
{
  macro_rules! swapn_32 {
    ($cl: literal, $ch: literal, $s: literal, $x: literal, $y: literal ) => {
      let a = q[$x];
      let b = q[$y];
      q[$x] = (a & $cl) | ((b & $cl) << ($s));
      q[$y] = ((a & $ch) >> $s) | (b & $ch);
    };
  }
  
  macro_rules! swap2_32 {
    ($x: literal, $y: literal) => {
      swapn_32!(0x55555555u32, 0xAAAAAAAAu32, 1, $x, $y)
    };
  }
  
  macro_rules! swap4_32 {
    ($x: literal, $y: literal) => {
      swapn_32!(0x33333333u32, 0xCCCCCCCCu32, 2, $x, $y)
    };
  }
  
  macro_rules! swap8_32 {
    ($x: literal, $y: literal) => {
      swapn_32!(0x0F0F0F0Fu32, 0xF0F0F0F0u32, 4, $x, $y)
    };
  }

  swap2_32!(0, 1);
  swap2_32!(2, 3);
  swap2_32!(4, 5);
  swap2_32!(6, 7);

  swap4_32!(0, 2);
  swap4_32!(1, 3);
  swap4_32!(4, 6);
  swap4_32!(5, 7);

  swap8_32!(0, 4);
  swap8_32!(1, 5);
  swap8_32!(2, 6);
  swap8_32!(3, 7);
}

#[cfg(feature = "robust")]
pub fn add_round_key32(q: &mut[u32], sk: &[u32]) 
{
  q[0] ^= sk[0];
  q[1] ^= sk[1];
  q[2] ^= sk[2];
  q[3] ^= sk[3];
  q[4] ^= sk[4];
  q[5] ^= sk[5];
  q[6] ^= sk[6];
  q[7] ^= sk[7];
}

#[cfg(feature = "robust")]
pub fn shift_rows32(q: &mut[u32])
{
  for x in q.iter_mut() {
    *x = (*x & 0x000000FF)
        | ((*x & 0x0000FC00) >> 2) | ((*x & 0x00000300) << 6)
        | ((*x & 0x00F00000) >> 4) | ((*x & 0x000F0000) << 4)
        | ((*x & 0xC0000000) >> 6) | ((*x & 0x3F000000) << 2);
  }
}

#[cfg(feature = "robust")]
fn rotr16(x: u32) -> u32
{
  (x << 16) | (x >> 16)
}

#[cfg(feature = "robust")]
pub fn mix_columns32(q: &mut[u32])
{
  let q0 = q[0];
  let q1 = q[1];
  let q2 = q[2];
  let q3 = q[3];
  let q4 = q[4];
  let q5 = q[5];
  let q6 = q[6];
  let q7 = q[7];
  let r0 = (q0 >> 8) | (q0 << 24);
  let r1 = (q1 >> 8) | (q1 << 24);
  let r2 = (q2 >> 8) | (q2 << 24);
  let r3 = (q3 >> 8) | (q3 << 24);
  let r4 = (q4 >> 8) | (q4 << 24);
  let r5 = (q5 >> 8) | (q5 << 24);
  let r6 = (q6 >> 8) | (q6 << 24);
  let r7 = (q7 >> 8) | (q7 << 24);

  q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
  q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
  q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
  q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

fn br_aes_ct64_ortho(q: &mut [u64]) 
{
  macro_rules! swapn {
    ($cl: literal, $ch: literal, $s: literal, $x: literal, $y: literal ) => {
      let a = q[$x];
      let b = q[$y];
      q[$x] = (a & $cl) | ((b & $cl) << ($s));
      q[$y] = ((a & $ch) >> $s) | (b & $ch);
    };
  }
  
  macro_rules! swap2 {
    ($x: literal, $y: literal) => {
      swapn!(0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64, 1, $x, $y)
    };
  }
  
  macro_rules! swap4 {
    ($x: literal, $y: literal) => {
      swapn!(0x3333333333333333u64, 0xCCCCCCCCCCCCCCCCu64, 2, $x, $y)
    };
  }
  
  macro_rules! swap8 {
    ($x: literal, $y: literal) => {
      swapn!(0x0F0F0F0F0F0F0F0Fu64, 0xF0F0F0F0F0F0F0F0u64, 4, $x, $y)
    };
  }

  swap2!(0, 1);
  swap2!(2, 3);
  swap2!(4, 5);
  swap2!(6, 7);

  swap4!(0, 2);
  swap4!(1, 3);
  swap4!(4, 6);
  swap4!(5, 7);

  swap8!(0, 4);
  swap8!(1, 5);
  swap8!(2, 6);
  swap8!(3, 7);
}


fn br_aes_ct64_interleave_in(q0: &mut u64, q1: &mut u64, w: &[u32])
{
  let (mut x0, mut x1, mut x2, mut x3): (u64, u64, u64, u64);

  x0 = w[0].into();
  x1 = w[1].into();
  x2 = w[2].into();
  x3 = w[3].into();
  x0 |= x0 << 16;
  x1 |= x1 << 16;
  x2 |= x2 << 16;
  x3 |= x3 << 16;
  x0 &= 0x0000FFFF0000FFFFu64;
  x1 &= 0x0000FFFF0000FFFFu64;
  x2 &= 0x0000FFFF0000FFFFu64;
  x3 &= 0x0000FFFF0000FFFFu64;
  x0 |= x0 << 8;
  x1 |= x1 << 8;
  x2 |= x2 << 8;
  x3 |= x3 << 8;
  x0 &= 0x00FF00FF00FF00FFu64;
  x1 &= 0x00FF00FF00FF00FFu64;
  x2 &= 0x00FF00FF00FF00FFu64;
  x3 &= 0x00FF00FF00FF00FFu64;
  *q0 = x0 | (x2 << 8);
  *q1 = x1 | (x3 << 8);
}

fn br_aes_ct64_interleave_out(w: &mut[u32], q0: u64, q1: u64)
{
  let (mut x0, mut x1, mut x2, mut x3): (u64, u64, u64, u64);

  x0 = q0 & 0x00FF00FF00FF00FFu64;
  x1 = q1 & 0x00FF00FF00FF00FFu64;
  x2 = (q0 >> 8) & 0x00FF00FF00FF00FFu64;
  x3 = (q1 >> 8) & 0x00FF00FF00FF00FFu64;
  x0 |= x0 >> 8;
  x1 |= x1 >> 8;
  x2 |= x2 >> 8;
  x3 |= x3 >> 8;
  x0 &= 0x0000FFFF0000FFFFu64;
  x1 &= 0x0000FFFF0000FFFFu64;
  x2 &= 0x0000FFFF0000FFFFu64;
  x3 &= 0x0000FFFF0000FFFFu64;
  w[0] = x0 as u32 | (x0 >> 16) as u32 ;
  w[1] = x1 as u32 | (x1 >> 16) as u32 ;
  w[2] = x2 as u32 | (x2 >> 16) as u32 ;
  w[3] = x3 as u32 | (x3 >> 16) as u32 ;
}

pub fn add_round_key(q: &mut[u64], sk: &[u64]) 
{
  q[0] ^= sk[0];
  q[1] ^= sk[1];
  q[2] ^= sk[2];
  q[3] ^= sk[3];
  q[4] ^= sk[4];
  q[5] ^= sk[5];
  q[6] ^= sk[6];
  q[7] ^= sk[7];
}

pub fn shift_rows(q: &mut[u64]) 
{
  for x in q.iter_mut() {
    *x = (*x & 0x000000000000FFFF)
      | ((*x & 0x00000000FFF00000) >> 4)
      | ((*x & 0x00000000000F0000) << 12)
      | ((*x & 0x0000FF0000000000) >> 8)
      | ((*x & 0x000000FF00000000) << 8)
      | ((*x & 0xF000000000000000) >> 12)
      | ((*x & 0x0FFF000000000000) << 4)
    };
}


fn rotr32(x: u64) -> u64 
{
  (x << 32) | (x >> 32)
}

fn mix_columns(q: &mut [u64])
{
  let q0 = q[0];
  let q1 = q[1];
  let q2 = q[2];
  let q3 = q[3];
  let q4 = q[4];
  let q5 = q[5];
  let q6 = q[6];
  let q7 = q[7];
  let r0 = (q0 >> 16) | (q0 << 48);
  let r1 = (q1 >> 16) | (q1 << 48);
  let r2 = (q2 >> 16) | (q2 << 48);
  let r3 = (q3 >> 16) | (q3 << 48);
  let r4 = (q4 >> 16) | (q4 << 48);
  let r5 = (q5 >> 16) | (q5 << 48);
  let r6 = (q6 >> 16) | (q6 << 48);
  let r7 = (q7 >> 16) | (q7 << 48);

  q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
  q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
  q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
  q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
}

pub fn interleave_constant(out: &mut[u64], input: &[u8])
{
  let mut tmp_32_constant = [0u32; 16];

  br_range_dec32le(&mut tmp_32_constant, 16, input);
  for i in 0..4  {
    let mut q1_tmp =  out[i + 4];
      br_aes_ct64_interleave_in(&mut out[i], &mut q1_tmp, &mut tmp_32_constant[(i << 2)..]);
      out[i + 4] = q1_tmp;
    }
  br_aes_ct64_ortho(out);
}

pub fn interleave_constant32(out: &mut[u32], input: &[u8])
{
  for i in 0..4  {
    out[2*i] = br_dec32le(&input[4*i..]);
    out[2*i + 1] = br_dec32le(&input[4*i + 16..]);
  }
  br_aes_ct_ortho(out);
}

pub fn tweak_constants(ctx: &mut SpxCtx)
{
  let mut buf = [0u8; 40*16];

  // Use the standard constants to generate tweaked ones.
  ctx.tweaked512_rc64 = HARAKA512_RC64;

  // Constants for pk.seed
  haraka_s(&mut buf, 40*16, &ctx.pub_seed, SPX_N, &ctx);
  for i in 0..10  {
    interleave_constant32(&mut ctx.tweaked256_rc32[i], &buf[32*i..]);
    interleave_constant(&mut ctx.tweaked512_rc64[i], &buf[64*i..]);
  }
}

pub fn haraka_s_absorb(
  s: &mut[u8], m: &[u8], mut mlen: usize, p: u8, ctx: &SpxCtx
)
{
  let mut t = [0u8; HARAKAS_RATE];
  let mut idx = 0usize;
  while mlen >= HARAKAS_RATE {
    // XOR block to state
    for i in 0..HARAKAS_RATE  {
        s[i] ^= m[idx+i];
    }
    haraka512_perm(s, ctx);
    mlen -= HARAKAS_RATE;
    idx += HARAKAS_RATE;
  }
  
  for i in 0..mlen  {
    t[i] = m[idx + i];
  }

  t[mlen] = p;
  t[HARAKAS_RATE - 1] |= 128;
  for i in 0..HARAKAS_RATE  {
    s[i] ^= t[i];
  }
}

pub fn haraka_s_squeezeblocks(
  h: &mut[u8], mut nblocks: usize, s: &mut[u8], r: usize, ctx: &SpxCtx
)
{
  let mut idx = 0usize;
    while nblocks > 0 {
      haraka512_perm(s, ctx);
      h[idx..idx+HARAKAS_RATE].copy_from_slice(&s[..HARAKAS_RATE]);
      idx += r;
      nblocks -= 1;
    }
}

pub fn haraka_s_inc_absorb(s_inc: &mut[u8], m: &[u8], mut mlen: usize, ctx: &SpxCtx)
{
  let mut idx = 0usize;
  // Recall that s_inc[64] is the non-absorbed bytes xored into the state
  while mlen + s_inc[64] as usize >= HARAKAS_RATE {
    for i in 0..HARAKAS_RATE - s_inc[64] as usize {
      // Take the i'th byte from message xor with the s_inc[64] + i'th byte of the state
      s_inc[s_inc[64] as usize + i] ^= m[idx + i];
    }
    mlen -= HARAKAS_RATE - s_inc[64] as usize;
    idx += HARAKAS_RATE - s_inc[64] as usize;
    s_inc[64] = 0;

    haraka512_perm(s_inc, ctx);
  }

  for i in 0..mlen  {
    s_inc[s_inc[64] as usize + i] ^= m[idx + i];  
  }
  s_inc[64] += mlen as u8;
}

pub fn haraka_s_inc_finalize(s_inc: &mut[u8])
{
  // After haraka_S_inc_absorb, we are guaranteed that s_inc[64] < HARAKAS_RATE,
  // so we can always use one more byte for p in the current state.
  s_inc[s_inc[64] as usize] ^= 0x1F;
  s_inc[HARAKAS_RATE - 1] ^= 128;
  s_inc[64] = 0;
}

pub fn haraka_s_inc_squeeze(
  out: &mut[u8], mut outlen: usize, s_inc: &mut[u8], ctx: &SpxCtx
)
{

  // First consume any bytes we still have sitting around
  let mut i = 0usize;
  let mut idx = 0usize;
  while i < outlen && i < s_inc[64] as usize {
    // There are s_inc[64] bytes left, so r - s_inc[64] is the first
    // available byte. We consume from there, i.e., up to r.
    out[i] = s_inc[HARAKAS_RATE - s_inc[64] as usize + i];
    i += 1;
  }
  idx += i;
  outlen -= i;
  s_inc[64] -= i as u8;

  // Then squeeze the remaining necessary blocks
  while outlen > 0 {
    haraka512_perm(s_inc, ctx);
    i = 0usize;
    while i < outlen && i < HARAKAS_RATE {
      out[idx + i] = s_inc[i];
      i += 1;
    }
    idx += i;
    outlen -= i;
    s_inc[64] = (HARAKAS_RATE - i) as u8;
  }
}

pub fn haraka_s(
  out: &mut[u8], outlen: usize, input: &[u8], inlen: usize, ctx: &SpxCtx
)
{
  let mut s = [0u8; 64];
  let mut d = [0u8; 32];
  let mut idx = 0usize;
  haraka_s_absorb(&mut s, input, inlen, 0x1F, ctx);

  haraka_s_squeezeblocks(out, outlen / 32, &mut s, 32, ctx);
  idx += (outlen / 32) * 32;

  if outlen % 32 != 0 {
    haraka_s_squeezeblocks(&mut d, 1, &mut s, 32, ctx);
    for i in 0..outlen % 32 {
      out[idx + i] = d[i];
    }
  }
}

pub fn haraka512_perm(out: &mut[u8], ctx: &SpxCtx)
{
  let mut tmp_q;
  let mut w = [0u32; 16];
  let mut q = [0u64; 8];

  br_range_dec32le(&mut w, 16, &out);
  for i in 0..4  {
    tmp_q = q[i + 4];
    br_aes_ct64_interleave_in(&mut q[i], &mut tmp_q, &w[(i << 2)..]);
    q[i + 4] = tmp_q;
    }
  br_aes_ct64_ortho(&mut q);

  // AES rounds
  for i in 0..5  {
    for j in 0..2  {
      br_aes_ct_bitslice_sbox(&mut q);
      shift_rows(&mut q);
      mix_columns(&mut q);
      add_round_key(&mut q, &ctx.tweaked512_rc64[2*i + j]);
    }
    // Mix states
    for j in 0..8  {
      tmp_q = q[j];
      q[j] =  (tmp_q & 0x0001000100010001) << 5  |
              (tmp_q & 0x0002000200020002) << 12 | 
              (tmp_q & 0x0004000400040004) >> 1  | 
              (tmp_q & 0x0008000800080008) << 6  | 
              (tmp_q & 0x0020002000200020) << 9  | 
              (tmp_q & 0x0040004000400040) >> 4  | 
              (tmp_q & 0x0080008000800080) << 3  | 
              (tmp_q & 0x2100210021002100) >> 5  |
              (tmp_q & 0x0210021002100210) << 2  | 
              (tmp_q & 0x0800080008000800) << 4  | 
              (tmp_q & 0x1000100010001000) >> 12 | 
              (tmp_q & 0x4000400040004000) >> 10 | 
              (tmp_q & 0x8400840084008400) >> 3;
    }
  }

  br_aes_ct64_ortho(&mut q);
  for i in 0..4 {
    br_aes_ct64_interleave_out(&mut w[(i << 2)..], q[i], q[i + 4]);
  }
  br_range_enc32le(out, &w, 16);
}

pub fn haraka512(out: &mut[u8], input: &[u8], ctx: &SpxCtx)
{
  let mut buf = [0u8;64];
  buf.clone_from_slice(&input);

  haraka512_perm(&mut buf, ctx);
  // Feed-forward
  for i in 0..64  {
    buf[i] ^= input[i];
  }

  // Truncated
  out[..8].copy_from_slice(&buf[8..16]);
  out[8..16].copy_from_slice(&buf[24..32]);
  out[16..24].copy_from_slice(&buf[32..40]);
  out[24..32].copy_from_slice(&buf[48..56]);
}

#[cfg(feature = "robust")]
pub fn haraka256(out: &mut[u8], input: &[u8], ctx: &SpxCtx)
{
  let mut q = [0u32; 8];
  let mut tmp_q;
  for i in 0..4  {
    q[2*i] = br_dec32le(&input[4*i..]);
    q[2*i + 1] = br_dec32le(&input[4*i + 16..]);
  }
  br_aes_ct_ortho(&mut q);

  // AES rounds
  for i in 0..5  {
    for j in 0..2  {
      br_aes_ct_bitslice_sbox(&mut q);
      shift_rows32(&mut q);
      mix_columns32(&mut q);
      add_round_key32(&mut q, &ctx.tweaked256_rc32[2*i + j]);
    }

    // Mix states
    for j in 0..8  {
      tmp_q = q[j];
      q[j] =  (tmp_q & 0x81818181) |
              (tmp_q & 0x02020202) << 1 |
              (tmp_q & 0x04040404) << 2 |
              (tmp_q & 0x08080808) << 3 |
              (tmp_q & 0x10101010) >> 3 |
              (tmp_q & 0x20202020) >> 2 |
              (tmp_q & 0x40404040) >> 1;
    }
  }

  br_aes_ct_ortho(&mut q);
  for i in 0..4  {
    br_enc32le(&mut out[4*i..], q[2*i]);
    br_enc32le(&mut out[4*i + 16..], q[2*i + 1]);
  }

  for i in 0..32  {
    out[i] ^= input[i];
  }
}
