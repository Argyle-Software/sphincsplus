/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

use crate::params::*;
use crate::context::SpxCtx;
 
use crate::utils::*;
use std::ops::{Shr, Not, BitAnd, BitXor};

// TODO: use rust builtins
pub fn load_bigendian_32(x: &[u8]) -> u32 {
 (x[3] as u32) | 
 (((x[2] as u32)) << 8) | 
 (((x[1] as u32)) << 16) | 
 (((x[0] as u32)) << 24)
}

pub fn load_bigendian_64(x: &[u8]) -> u64 {
    (x[7] as u64) | (((x[6] as u64)) << 8) |
  (((x[5] as u64)) << 16) | (((x[4] as u64)) << 24) |
  (((x[3] as u64)) << 32) | (((x[2] as u64)) << 40) |
  (((x[1] as u64)) << 48) | (((x[0] as u64)) << 56)
}

pub fn store_bigendian_32(x: &mut[u8], mut u: u32) {
    x[3] = u as u8;
    u >>= 8;
    x[2] = u as u8;
    u >>= 8;
    x[1] = u as u8; 
    u >>= 8;
    x[0] = u as u8;
}

pub fn store_bigendian_64(x: &mut[u8], mut u: u64) {
  x[7] = u as u8;
  u >>= 8;
  x[6] = u as u8;
  u >>= 8;
  x[5] = u as u8;
  u >>= 8;
  x[4] = u as u8;
  u >>= 8;
  x[3] = u as u8;
  u >>= 8;
  x[2] = u as u8;
  u >>= 8;
  x[1] = u as u8;
  u >>= 8;
  x[0] = u as u8;
}

fn shr<T: Shr<Output=T>>(x: T, c: T) -> T {
  x >> c
}

fn  rotr_32(x: u32, c: u32) -> u32 { 
  ((x) >> (c)) | ((x) << (32 - (c))) 
}
fn  rotr_64(x: u64, c: u64) -> u64 {
  ((x) >> (c)) | ((x) << (64 - (c)))
}
fn  ch<T>(x: T, y: T, z: T) -> T
  where T: BitAnd<Output=T> + Not<Output=T> + BitXor<Output=T> + Copy
{
  ((x) & (y)) ^ (!(x) & (z))
}
fn  maj<T>(x: T, y: T, z: T) -> T 
  where T: BitAnd<Output=T> + BitXor<Output=T> + Copy
{
  ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))
} 

fn Sigma0_32(x: u32) -> u32 { rotr_32(x, 2) ^ rotr_32(x,13) ^ rotr_32(x,22) }
fn Sigma1_32(x: u32) -> u32 { rotr_32(x, 6) ^ rotr_32(x,11) ^ rotr_32(x,25) }
fn sigma0_32(x: u32) -> u32 { rotr_32(x, 7) ^ rotr_32(x,18) ^ shr(x, 3) }
fn sigma1_32(x: u32) -> u32 { rotr_32(x,17) ^ rotr_32(x,19) ^ shr(x,10) }

fn Sigma0_64(x: u64) -> u64 { rotr_64(x,28) ^ rotr_64(x,34) ^ rotr_64(x,39) }
fn Sigma1_64(x: u64) -> u64 { rotr_64(x,14) ^ rotr_64(x,18) ^ rotr_64(x,41) }
fn sigma0_64(x: u64) -> u64 { rotr_64(x, 1) ^ rotr_64(x, 8) ^ shr(x,7) }
fn sigma1_64(x: u64) -> u64 { rotr_64(x,19) ^ rotr_64(x,61) ^ shr(x,6) }

fn  m_32(w0: &mut u32, w14: u32, w9: u32, w1: u32) {
  *w0 += sigma1_32(w14) + (w9) + sigma0_32(w1);
}
fn  m_64(w0: &mut u64, w14: u64, w9: u64, w1: u64) {
  *w0 += sigma1_64(w14) + (w9) + sigma0_64(w1);
}

fn crypto_hashblocks_sha256(
  statebytes: &mut [u8], input: &[u8], mut inlen: usize
) -> usize  
{
  let mut state = [0u32; 8];
  let mut t1 =  0u32;
  let mut t2 =  0u32;
  let mut idx = 0;

  let mut a = load_bigendian_32(&statebytes[0..]);
  state[0] = a;
  let mut b = load_bigendian_32(&statebytes[4..]);
  state[1] = b;
  let mut c = load_bigendian_32(&statebytes[8..]);
  state[2] = c;
  let mut d = load_bigendian_32(&statebytes[12..]);
  state[3] = d;
  let mut e = load_bigendian_32(&statebytes[16..]);
  state[4] = e;
  let mut f = load_bigendian_32(&statebytes[20..]);
  state[5] = f;
  let mut g = load_bigendian_32(&statebytes[24..]);
  state[6] = g;
  let mut h = load_bigendian_32(&statebytes[28..]);
  state[7] = h;

  while inlen >= 64 {
    let mut w0 =load_bigendian_32(&input[idx+0..]);
    let mut w1 =load_bigendian_32(&input[idx+4..]);
    let mut w2 =load_bigendian_32(&input[idx+8..]);
    let mut w3 =load_bigendian_32(&input[idx+12..]);
    let mut w4 =load_bigendian_32(&input[idx+16..]);
    let mut w5 =load_bigendian_32(&input[idx+20..]);
    let mut w6 =load_bigendian_32(&input[idx+24..]);
    let mut w7 =load_bigendian_32(&input[idx+28..]);
    let mut w8 =load_bigendian_32(&input[idx+32..]);
    let mut w9 =load_bigendian_32(&input[idx+36..]);
    let mut w10 =load_bigendian_32(&input[idx+40..]);
    let mut w11 =load_bigendian_32(&input[idx+44..]);
    let mut w12 =load_bigendian_32(&input[idx+48..]);
    let mut w13 =load_bigendian_32(&input[idx+52..]);
    let mut w14 =load_bigendian_32(&input[idx+56..]);
    let mut w15 =load_bigendian_32(&input[idx+60..]);

    macro_rules! f_32 {
      ($w:ident, $k:literal) => {
        t1 = h + Sigma1_32(e) + ch(e,f,g) + $k + $w;
        t2 = Sigma0_32(a) + maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      };
    }

    f_32!(w0, 0x428a2f98);
    f_32!(w1, 0x71374491);
    f_32!(w2, 0xb5c0fbcf);
    f_32!(w3, 0xe9b5dba5);
    f_32!(w4, 0x3956c25b);
    f_32!(w5, 0x59f111f1);
    f_32!(w6, 0x923f82a4);
    f_32!(w7, 0xab1c5ed5);
    f_32!(w8, 0xd807aa98);
    f_32!(w9, 0x12835b01);
    f_32!(w10, 0x243185be);
    f_32!(w11, 0x550c7dc3);
    f_32!(w12, 0x72be5d74);
    f_32!(w13, 0x80deb1fe);
    f_32!(w14, 0x9bdc06a7);
    f_32!(w15, 0xc19bf174);

    macro_rules! expand_32 {
      () => {
        m_32(&mut w0 ,w14,w9 ,w1 );
        m_32(&mut w1 ,w15,w10,w2 );
        m_32(&mut w2 ,w0 ,w11,w3 );
        m_32(&mut w3 ,w1 ,w12,w4 );
        m_32(&mut w4 ,w2 ,w13,w5 );
        m_32(&mut w5 ,w3 ,w14,w6 );
        m_32(&mut w6 ,w4 ,w15,w7 );
        m_32(&mut w7 ,w5 ,w0 ,w8 );
        m_32(&mut w8 ,w6 ,w1 ,w9 );
        m_32(&mut w9 ,w7 ,w2 ,w10);
        m_32(&mut w10,w8 ,w3 ,w11);
        m_32(&mut w11,w9 ,w4 ,w12);
        m_32(&mut w12,w10,w5 ,w13);
        m_32(&mut w13,w11,w6 ,w14);
        m_32(&mut w14,w12,w7 ,w15);
        m_32(&mut w15,w13,w8 ,w0 );
      };
    }

    expand_32!();

    f_32!(w0, 0xe49b69c1u32);
    f_32!(w1, 0xefbe4786u32);
    f_32!(w2, 0x0fc19dc6u32);
    f_32!(w3, 0x240ca1ccu32);
    f_32!(w4, 0x2de92c6fu32);
    f_32!(w5, 0x4a7484aau32);
    f_32!(w6, 0x5cb0a9dcu32);
    f_32!(w7, 0x76f988dau32);
    f_32!(w8, 0x983e5152u32);
    f_32!(w9, 0xa831c66du32);
    f_32!(w10, 0xb00327c8u32);
    f_32!(w11, 0xbf597fc7u32);
    f_32!(w12, 0xc6e00bf3u32);
    f_32!(w13, 0xd5a79147u32);
    f_32!(w14, 0x06ca6351u32);
    f_32!(w15, 0x14292967u32);

    expand_32!();

    f_32!(w0, 0x27b70a85u32);
    f_32!(w1, 0x2e1b2138u32);
    f_32!(w2, 0x4d2c6dfcu32);
    f_32!(w3, 0x53380d13u32);
    f_32!(w4, 0x650a7354u32);
    f_32!(w5, 0x766a0abbu32);
    f_32!(w6, 0x81c2c92eu32);
    f_32!(w7, 0x92722c85u32);
    f_32!(w8, 0xa2bfe8a1u32);
    f_32!(w9, 0xa81a664bu32);
    f_32!(w10, 0xc24b8b70u32);
    f_32!(w11, 0xc76c51a3u32);
    f_32!(w12, 0xd192e819u32);
    f_32!(w13, 0xd6990624u32);
    f_32!(w14, 0xf40e3585u32);
    f_32!(w15, 0x106aa070u32);

    expand_32!();

    f_32!(w0, 0x19a4c116u32);
    f_32!(w1, 0x1e376c08u32);
    f_32!(w2, 0x2748774cu32);
    f_32!(w3, 0x34b0bcb5u32);
    f_32!(w4, 0x391c0cb3u32);
    f_32!(w5, 0x4ed8aa4au32);
    f_32!(w6, 0x5b9cca4fu32);
    f_32!(w7, 0x682e6ff3u32);
    f_32!(w8, 0x748f82eeu32);
    f_32!(w9, 0x78a5636fu32);
    f_32!(w10, 0x84c87814u32);
    f_32!(w11, 0x8cc70208u32);
    f_32!(w12, 0x90befffau32);
    f_32!(w13, 0xa4506cebu32);
    f_32!(w14, 0xbef9a3f7u32);
    f_32!(w15, 0xc67178f2u32);

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    idx += 64;
    inlen -= 64;
  }

  store_bigendian_32(&mut statebytes[0..], state[0]);
  store_bigendian_32(&mut statebytes[4..], state[1]);
  store_bigendian_32(&mut statebytes[8..], state[2]);
  store_bigendian_32(&mut statebytes[12..], state[3]);
  store_bigendian_32(&mut statebytes[16..], state[4]);
  store_bigendian_32(&mut statebytes[20..], state[5]);
  store_bigendian_32(&mut statebytes[24..], state[6]);
  store_bigendian_32(&mut statebytes[28..], state[7]);

  return inlen;
}

fn crypto_hashblocks_sha512(statebytes: &mut[u8],input: &[u8], mut inlen: usize) -> usize
{
  let mut state = [0u64; 8];
  let mut t1 =  0u64;
  let mut t2 =  0u64;
  let mut idx = 0;

  let mut a = load_bigendian_64(&statebytes[0..]); state[0] = a;
  let mut b = load_bigendian_64(&statebytes[8..]); state[1] = b;
  let mut c = load_bigendian_64(&statebytes[16..]); state[2] = c;
  let mut d = load_bigendian_64(&statebytes[24..]); state[3] = d;
  let mut e = load_bigendian_64(&statebytes[32..]); state[4] = e;
  let mut f = load_bigendian_64(&statebytes[40..]); state[5] = f;
  let mut g = load_bigendian_64(&statebytes[48..]); state[6] = g;
  let mut h = load_bigendian_64(&statebytes[56..]); state[7] = h;

  while inlen >= 128 {
    let mut w0  = load_bigendian_64(&input[idx+0..]);
    let mut w1  = load_bigendian_64(&input[idx+8..]);
    let mut w2  = load_bigendian_64(&input[idx+16..]);
    let mut w3  = load_bigendian_64(&input[idx+24..]);
    let mut w4  = load_bigendian_64(&input[idx+32..]);
    let mut w5  = load_bigendian_64(&input[idx+40..]);
    let mut w6  = load_bigendian_64(&input[idx+48..]);
    let mut w7  = load_bigendian_64(&input[idx+56..]);
    let mut w8  = load_bigendian_64(&input[idx+64..]);
    let mut w9  = load_bigendian_64(&input[idx+72..]);
    let mut w10 = load_bigendian_64(&input[idx+80..]);
    let mut w11 = load_bigendian_64(&input[idx+88..]);
    let mut w12 = load_bigendian_64(&input[idx+96..]);
    let mut w13 = load_bigendian_64(&input[idx+104..]);
    let mut w14 = load_bigendian_64(&input[idx+112..]);
    let mut w15 = load_bigendian_64(&input[idx+120..]);

    macro_rules! f_64 {
      ($w:ident, $k:literal) => {
        t1 = h + Sigma1_64(e) + ch(e,f,g) + $k + $w;
        t2 = Sigma0_64(a) + maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      };
    }

    f_64!(w0 ,0x428a2f98d728ae22u64);
    f_64!(w1 ,0x7137449123ef65cdu64);
    f_64!(w2 ,0xb5c0fbcfec4d3b2fu64);
    f_64!(w3 ,0xe9b5dba58189dbbcu64);
    f_64!(w4 ,0x3956c25bf348b538u64);
    f_64!(w5 ,0x59f111f1b605d019u64);
    f_64!(w6 ,0x923f82a4af194f9bu64);
    f_64!(w7 ,0xab1c5ed5da6d8118u64);
    f_64!(w8 ,0xd807aa98a3030242u64);
    f_64!(w9 ,0x12835b0145706fbeu64);
    f_64!(w10,0x243185be4ee4b28cu64);
    f_64!(w11,0x550c7dc3d5ffb4e2u64);
    f_64!(w12,0x72be5d74f27b896fu64);
    f_64!(w13,0x80deb1fe3b1696b1u64);
    f_64!(w14,0x9bdc06a725c71235u64);
    f_64!(w15,0xc19bf174cf692694u64);

    macro_rules! expand_64 {
      ( ) => {
        m_64(&mut w0 ,w14,w9 ,w1 );
        m_64(&mut w1 ,w15,w10,w2 );
        m_64(&mut w2 ,w0 ,w11,w3 );
        m_64(&mut w3 ,w1 ,w12,w4 );
        m_64(&mut w4 ,w2 ,w13,w5 );
        m_64(&mut w5 ,w3 ,w14,w6 );
        m_64(&mut w6 ,w4 ,w15,w7 );
        m_64(&mut w7 ,w5 ,w0 ,w8 );
        m_64(&mut w8 ,w6 ,w1 ,w9 );
        m_64(&mut w9 ,w7 ,w2 ,w10);
        m_64(&mut w10,w8 ,w3 ,w11);
        m_64(&mut w11,w9 ,w4 ,w12);
        m_64(&mut w12,w10,w5 ,w13);
        m_64(&mut w13,w11,w6 ,w14);
        m_64(&mut w14,w12,w7 ,w15);
        m_64(&mut w15,w13,w8 ,w0 );
      };
    }

    expand_64!();

    f_64!(w0 ,0xe49b69c19ef14ad2u64);
    f_64!(w1 ,0xefbe4786384f25e3u64);
    f_64!(w2 ,0x0fc19dc68b8cd5b5u64);
    f_64!(w3 ,0x240ca1cc77ac9c65u64);
    f_64!(w4 ,0x2de92c6f592b0275u64);
    f_64!(w5 ,0x4a7484aa6ea6e483u64);
    f_64!(w6 ,0x5cb0a9dcbd41fbd4u64);
    f_64!(w7 ,0x76f988da831153b5u64);
    f_64!(w8 ,0x983e5152ee66dfabu64);
    f_64!(w9 ,0xa831c66d2db43210u64);
    f_64!(w10,0xb00327c898fb213fu64);
    f_64!(w11,0xbf597fc7beef0ee4u64);
    f_64!(w12,0xc6e00bf33da88fc2u64);
    f_64!(w13,0xd5a79147930aa725u64);
    f_64!(w14,0x06ca6351e003826fu64);
    f_64!(w15,0x142929670a0e6e70u64);

    expand_64!();

    f_64!(w0 ,0x27b70a8546d22ffcu64);
    f_64!(w1 ,0x2e1b21385c26c926u64);
    f_64!(w2 ,0x4d2c6dfc5ac42aedu64);
    f_64!(w3 ,0x53380d139d95b3dfu64);
    f_64!(w4 ,0x650a73548baf63deu64);
    f_64!(w5 ,0x766a0abb3c77b2a8u64);
    f_64!(w6 ,0x81c2c92e47edaee6u64);
    f_64!(w7 ,0x92722c851482353bu64);
    f_64!(w8 ,0xa2bfe8a14cf10364u64);
    f_64!(w9 ,0xa81a664bbc423001u64);
    f_64!(w10,0xc24b8b70d0f89791u64);
    f_64!(w11,0xc76c51a30654be30u64);
    f_64!(w12,0xd192e819d6ef5218u64);
    f_64!(w13,0xd69906245565a910u64);
    f_64!(w14,0xf40e35855771202au64);
    f_64!(w15,0x106aa07032bbd1b8u64);

    expand_64!();

    f_64!(w0 ,0x19a4c116b8d2d0c8u64);
    f_64!(w1 ,0x1e376c085141ab53u64);
    f_64!(w2 ,0x2748774cdf8eeb99u64);
    f_64!(w3 ,0x34b0bcb5e19b48a8u64);
    f_64!(w4 ,0x391c0cb3c5c95a63u64);
    f_64!(w5 ,0x4ed8aa4ae3418acbu64);
    f_64!(w6 ,0x5b9cca4f7763e373u64);
    f_64!(w7 ,0x682e6ff3d6b2b8a3u64);
    f_64!(w8 ,0x748f82ee5defb2fcu64);
    f_64!(w9 ,0x78a5636f43172f60u64);
    f_64!(w10,0x84c87814a1f0ab72u64);
    f_64!(w11,0x8cc702081a6439ecu64);
    f_64!(w12,0x90befffa23631e28u64);
    f_64!(w13,0xa4506cebde82bde9u64);
    f_64!(w14,0xbef9a3f7b2c67915u64);
    f_64!(w15,0xc67178f2e372532bu64);

    expand_64!();

    f_64!(w0 ,0xca273eceea26619cu64);
    f_64!(w1 ,0xd186b8c721c0c207u64);
    f_64!(w2 ,0xeada7dd6cde0eb1eu64);
    f_64!(w3 ,0xf57d4f7fee6ed178u64);
    f_64!(w4 ,0x06f067aa72176fbau64);
    f_64!(w5 ,0x0a637dc5a2c898a6u64);
    f_64!(w6 ,0x113f9804bef90daeu64);
    f_64!(w7 ,0x1b710b35131c471bu64);
    f_64!(w8 ,0x28db77f523047d84u64);
    f_64!(w9 ,0x32caab7b40c72493u64);
    f_64!(w10,0x3c9ebe0a15c9bebcu64);
    f_64!(w11,0x431d67c49c100d4cu64);
    f_64!(w12,0x4cc5d4becb3e42b6u64);
    f_64!(w13,0x597f299cfc657e2au64);
    f_64!(w14,0x5fcb6fab3ad6faecu64);
    f_64!(w15,0x6c44198c4a475817u64);

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];
  
    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    idx += 128;
    inlen -= 128;
  }

  store_bigendian_64(&mut statebytes[0..],state[0]);
  store_bigendian_64(&mut statebytes[8..],state[1]);
  store_bigendian_64(&mut statebytes[16..],state[2]);
  store_bigendian_64(&mut statebytes[24..],state[3]);
  store_bigendian_64(&mut statebytes[32..],state[4]);
  store_bigendian_64(&mut statebytes[40..],state[5]);
  store_bigendian_64(&mut statebytes[48..],state[6]);
  store_bigendian_64(&mut statebytes[56..],state[7]);

  return inlen;
}

const IV_256: [u8; 32] = [
  0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
  0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
  0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
  0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
];

const IV_512: [u8; 64] = [
  0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
  0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
  0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
  0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
  0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
  0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
];

pub fn sha256_inc_init(state: &mut[u8]) {
  for i in 0..32 {
    state[i] = IV_256[i];
  }
  for i in 32..40 {
    state[i] = 0;
  }
}

pub fn sha512_inc_init(state: &mut[u8]) {
  for i in 0..64 {
    state[i] = IV_512[i];
  }
  for i in 64..72 {
    state[i] = 0;
  }
}

pub fn sha256_inc_blocks(state: &mut [u8], input: &[u8], inblocks: usize) {
  let mut bytes = load_bigendian_64(&state[32..]);
  crypto_hashblocks_sha256(state, input, 64 * inblocks);
  bytes += 64 * inblocks as u64;
  store_bigendian_64(&mut state[32..], bytes);
}

pub fn sha512_inc_blocks(state: &mut[u8], input: &[u8], inblocks: usize) {
  let mut bytes = load_bigendian_64(&state[64..]);
  crypto_hashblocks_sha512(state, input, 128 * inblocks);
  bytes += 128 * inblocks as u64;
  store_bigendian_64(&mut state[64..], bytes);
}

pub fn sha256_inc_finalize(out: &mut[u8], state: &mut[u8], input: &[u8], mut inlen: usize) {
  let mut padded = [0u8; 128];
  let bytes = load_bigendian_64(&state[32..]) + inlen as u64;

  crypto_hashblocks_sha256(state, input, inlen);
  let mut idx = 0;
  idx += inlen;
  inlen &= 63;
  idx -= inlen;

  for i in 0..inlen as usize {
    padded[i] = input[idx as usize + i];
  }
  padded[inlen as usize] = 0x80;

  if inlen < 56 {
    for i in (inlen + 1)..56 {
      padded[i as usize] = 0;
    }
    padded[56] = (bytes >> 53) as u8;
    padded[57] = (bytes >> 45) as u8;
    padded[58] = (bytes >> 37) as u8;
    padded[59] = (bytes >> 29) as u8;
    padded[60] = (bytes >> 21) as u8;
    padded[61] = (bytes >> 13) as u8;
    padded[62] = (bytes >> 5) as u8;
    padded[63] = (bytes << 3) as u8;
    crypto_hashblocks_sha256(state, &padded, 64);
  } else {
    for i in (inlen + 1)..120 {
      padded[i as usize] = 0;
    }
    padded[120] = (bytes >> 53) as u8;
    padded[121] = (bytes >> 45) as u8;
    padded[122] = (bytes >> 37) as u8;
    padded[123] = (bytes >> 29) as u8;
    padded[124] = (bytes >> 21) as u8;
    padded[125] = (bytes >> 13) as u8;
    padded[126] = (bytes >> 5) as u8;
    padded[127] = (bytes << 3) as u8;
    crypto_hashblocks_sha256(state, &padded, 128);
  }

  out[..32].copy_from_slice(&state[..]);
}

pub fn sha512_inc_finalize(out: &mut[u8], state: &mut[u8], input: &[u8], mut inlen: usize) 
{
  let mut padded = [0u8; 256];
  let mut bytes = load_bigendian_64(&state[64..]) + inlen as u64;

  crypto_hashblocks_sha512(state, input, inlen);
  let mut idx = 0;
  idx += inlen;
  inlen &= 127;
  idx -= inlen;

  for i in 0..inlen as usize {
    padded[i] = input[idx as usize + i];
  }
  padded[inlen as usize] = 0x80;

  if inlen < 112 {
    for i in (inlen + 1)..119 {
      padded[i as usize] = 0;
    }
    padded[119] = (bytes >> 61) as u8;
    padded[120] = (bytes >> 53) as u8;
    padded[121] = (bytes >> 45) as u8;
    padded[122] = (bytes >> 37) as u8;
    padded[123] = (bytes >> 29) as u8;
    padded[124] = (bytes >> 21) as u8;
    padded[125] = (bytes >> 13) as u8;
    padded[126] = (bytes >> 5) as u8;
    padded[127] = (bytes << 3) as u8;
    crypto_hashblocks_sha512(state, &padded, 128);
  } else {
    for i in (inlen + 1)..247 {
      padded[i as usize] = 0;
    }
    padded[247] = (bytes >> 61) as u8;
    padded[248] = (bytes >> 53) as u8;
    padded[249] = (bytes >> 45) as u8;
    padded[250] = (bytes >> 37) as u8;
    padded[251] = (bytes >> 29) as u8;
    padded[252] = (bytes >> 21) as u8;
    padded[253] = (bytes >> 13) as u8;
    padded[254] = (bytes >> 5) as u8;
    padded[255] = (bytes << 3) as u8;
    crypto_hashblocks_sha512(state, &padded, 256);
  }
  out[..64].copy_from_slice(&state[..64]);
}

pub fn sha256(out: &mut [u8], input: &[u8], inlen: usize) {
  let mut state = [0u8; 40];
  sha256_inc_init(&mut state);
  sha256_inc_finalize(out, &mut state, input, inlen);
}

pub fn sha512(out: &mut [u8], input: &[u8], inlen: usize) {
  let mut state = [0u8; 72];
  sha512_inc_init(&mut state);
  sha512_inc_finalize(out, &mut state, input, inlen);
}

/**
 * mgf1 function based on the SHA-256 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'input' is merely a seed.
 * Outputs outlen number of bytes
 */
pub fn mgf1_256(out: &mut[u8], outlen: usize, input: &[u8])
{
  const INLEN: usize = SPX_N + SPX_SHA256_ADDR_BYTES;
  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];

  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  /* While we can fit in at least another fu64 block of SHA256 output.. */
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha256(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SHA256_OUTPUT_BYTES;
    i += 1;
  }
  /* Until we cannot anymore, and we fill the remainder. */
  if outlen > i*SPX_SHA256_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha256(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SHA256_OUTPUT_BYTES;
    out[..end].copy_from_slice(&outbuf[..end]);
  }
}

/*
 * mgf1 function based on the SHA-512 hash function
 */
pub fn mgf1_512(out: &mut[u8], outlen: usize, input: &[u8])
{
  const INLEN: usize = SPX_N + SPX_SHA256_ADDR_BYTES;
  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  /* While we can fit in at least another fu64 block of SHA512 output.. */
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SHA512_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha512(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SHA512_OUTPUT_BYTES;
    i += 1;
  }
  /* Until we cannot anymore, and we fill the remainder. */
  if outlen > i*SPX_SHA512_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha512(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SHA512_OUTPUT_BYTES;
    out[..end].copy_from_slice(&outbuf[..end]);
  }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused input thash
 **/
pub fn seed_state(ctx: &mut SpxCtx) {
  let mut block = [0u8; SPX_SHA512_BLOCK_BYTES];

  for i in 0..SPX_N  {
    block[i] = ctx.pub_seed[i];
  }
  for i in SPX_N..SPX_SHA512_BLOCK_BYTES {
    block[i] = 0;
  }

  /* block has been properly initialized for both SHA-256 and SHA-512 */
  sha256_inc_init(&mut ctx.state_seeded);
  sha256_inc_blocks(&mut ctx.state_seeded, &block, 1);

  #[cfg(feature = "sha512")] 
  {
    sha512_inc_init(&mut ctx.state_seeded_512);
    sha512_inc_blocks(&mut ctx.state_seeded_512, &block, 1);
  }
}


// TODO: Refactor and get rid of code duplication
pub fn mgf1_256_2(out: &mut[u8], outlen: usize, input: &[u8])
{
  // inlen / buffer size is the only difference
  const INLEN: usize = 2 * SPX_N + SPX_SHAX_OUTPUT_BYTES;
  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];

  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  /* While we can fit in at least another fu64 block of SHA256 output.. */
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha256(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SHA256_OUTPUT_BYTES;
    i += 1;
  }
  /* Until we cannot anymore, and we fill the remainder. */
  if outlen > i*SPX_SHA256_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha256(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SHA256_OUTPUT_BYTES;
    out[..end].copy_from_slice(&outbuf[..end]);
  }
}

/*
 * mgf1 function based on the SHA-512 hash function
 */
pub fn mgf1_512_2(out: &mut[u8], outlen: usize, input: &[u8])
{
  // inlen / buffer size is the only difference
  const INLEN: usize = 2 * SPX_N + SPX_SHAX_OUTPUT_BYTES;

  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  /* While we can fit in at least another fu64 block of SHA512 output.. */
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SHA512_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha512(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SHA512_OUTPUT_BYTES;
    i += 1;
  }
  /* Until we cannot anymore, and we fill the remainder. */
  if outlen > i*SPX_SHA512_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sha512(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SHA512_OUTPUT_BYTES;
    out[..end].copy_from_slice(&outbuf[..end]);
  }
}
