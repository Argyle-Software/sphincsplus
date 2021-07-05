/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */
 
use crate::utils::*;
use crate::sha2::*;

uint32_t load_bigendian_32(const uint8_t *x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
           (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
           (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
           (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
           (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}

pub fn store_bigendian_32(uint8_t *x, uint64_t u) {
    x[3] = u; as u8
    u >>= 8;
    x[2] = u; as u8
    u >>= 8;
    x[1] = u; as u8
    u >>= 8;
    x[0] = u; as u8
}

pub fn store_bigendian_64(uint8_t *x, uint64_t u) {
    x[7] = u; as u8
    u >>= 8;
    x[6] = u; as u8
    u >>= 8;
    x[5] = u; as u8
    u >>= 8;
    x[4] = u; as u8
    u >>= 8;
    x[3] = u; as u8
    u >>= 8;
    x[2] = u; as u8
    u >>= 8;
    x[1] = u; as u8
    u >>= 8;
    x[0] = u; as u8
}

#define SHR(x, c) ((x) >> (c))
#define ROTR_32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define ROTR_64(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_32(x) (ROTR_32(x, 2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define Sigma1_32(x) (ROTR_32(x, 6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define sigma0_32(x) (ROTR_32(x, 7) ^ ROTR_32(x,18) ^ SHR(x, 3))
#define sigma1_32(x) (ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10))

#define Sigma0_64(x) (ROTR_64(x,28) ^ ROTR_64(x,34) ^ ROTR_64(x,39))
#define Sigma1_64(x) (ROTR_64(x,14) ^ ROTR_64(x,18) ^ ROTR_64(x,41))
#define sigma0_64(x) (ROTR_64(x, 1) ^ ROTR_64(x, 8) ^ SHR(x,7))
#define sigma1_64(x) (ROTR_64(x,19) ^ ROTR_64(x,61) ^ SHR(x,6))

#define M_32(w0, w14, w9, w1) w0 = sigma1_32(w14) + (w9) + sigma0_32(w1) + (w0);
#define M_64(w0, w14, w9, w1) w0 = sigma1_64(w14) + (w9) + sigma0_64(w1) + (w0);

#define EXPAND_32           \
    M_32(w0, w14, w9, w1)   \
    M_32(w1, w15, w10, w2)  \
    M_32(w2, w0, w11, w3)   \
    M_32(w3, w1, w12, w4)   \
    M_32(w4, w2, w13, w5)   \
    M_32(w5, w3, w14, w6)   \
    M_32(w6, w4, w15, w7)   \
    M_32(w7, w5, w0, w8)    \
    M_32(w8, w6, w1, w9)    \
    M_32(w9, w7, w2, w10)   \
    M_32(w10, w8, w3, w11)  \
    M_32(w11, w9, w4, w12)  \
    M_32(w12, w10, w5, w13) \
    M_32(w13, w11, w6, w14) \
    M_32(w14, w12, w7, w15) \
    M_32(w15, w13, w8, w0)

#define EXPAND_64 \
  M_64(w0 ,w14,w9 ,w1 ) \
  M_64(w1 ,w15,w10,w2 ) \
  M_64(w2 ,w0 ,w11,w3 ) \
  M_64(w3 ,w1 ,w12,w4 ) \
  M_64(w4 ,w2 ,w13,w5 ) \
  M_64(w5 ,w3 ,w14,w6 ) \
  M_64(w6 ,w4 ,w15,w7 ) \
  M_64(w7 ,w5 ,w0 ,w8 ) \
  M_64(w8 ,w6 ,w1 ,w9 ) \
  M_64(w9 ,w7 ,w2 ,w10) \
  M_64(w10,w8 ,w3 ,w11) \
  M_64(w11,w9 ,w4 ,w12) \
  M_64(w12,w10,w5 ,w13) \
  M_64(w13,w11,w6 ,w14) \
  M_64(w14,w12,w7 ,w15) \
  M_64(w15,w13,w8 ,w0 )

#define F_32(w, k)                                   \
    T1 = h + Sigma1_32(e) + Ch(e, f, g) + (k) + (w); \
    T2 = Sigma0_32(a) + Maj(a, b, c);                \
    h = g;                                           \
    g = f;                                           \
    f = e;                                           \
    e = d + T1;                                      \
    d = c;                                           \
    c = b;                                           \
    b = a;                                           \
    a = T1 + T2;

#define F_64(w,k) \
    T1 = h + Sigma1_64(e) + Ch(e,f,g) + k + w; \
    T2 = Sigma0_64(a) + Maj(a,b,c); \
    h = g; \
    g = f; \
    f = e; \
    e = d + T1; \
    d = c; \
    c = b; \
    b = a; \
    a = T1 + T2;

size_t crypto_hashblocks_sha256(uint8_t *statebytes,
                                       const uint8_t *input, size_t inlen) {
    let mut state = [0u32; 8];
    let mut a =  0u32;
    let mut b =  0u32;
    let mut c =  0u32;
    let mut d =  0u32;
    let mut e =  0u32;
    let mut f =  0u32;
    let mut g =  0u32;
    let mut h =  0u32;
    let mut T1 =  0u32;
    let mut T2 =  0u32;

    a = load_bigendian_32(statebytes + 0);
    state[0] = a;
    b = load_bigendian_32(statebytes + 4);
    state[1] = b;
    c = load_bigendian_32(statebytes + 8);
    state[2] = c;
    d = load_bigendian_32(statebytes + 12);
    state[3] = d;
    e = load_bigendian_32(statebytes + 16);
    state[4] = e;
    f = load_bigendian_32(statebytes + 20);
    state[5] = f;
    g = load_bigendian_32(statebytes + 24);
    state[6] = g;
    h = load_bigendian_32(statebytes + 28);
    state[7] = h;

    while (inlen >= 64) {
        let mut w0 =load_bigendian_32(input + 0);
        let mut w1 =load_bigendian_32(input + 4);
        let mut w2 =load_bigendian_32(input + 8);
        let mut w3 =load_bigendian_32(input + 12);
        let mut w4 =load_bigendian_32(input + 16);
        let mut w5 =load_bigendian_32(input + 20);
        let mut w6 =load_bigendian_32(input + 24);
        let mut w7 =load_bigendian_32(input + 28);
        let mut w8 =load_bigendian_32(input + 32);
        let mut w9 =load_bigendian_32(input + 36);
        let mut w10 =load_bigendian_32(input + 40);
        let mut w11 =load_bigendian_32(input + 44);
        let mut w12 =load_bigendian_32(input + 48);
        let mut w13 =load_bigendian_32(input + 52);
        let mut w14 =load_bigendian_32(input + 56);
        let mut w15 =load_bigendian_32(input + 60);

        F_32(w0, 0x428a2f98)
        F_32(w1, 0x71374491)
        F_32(w2, 0xb5c0fbcf)
        F_32(w3, 0xe9b5dba5)
        F_32(w4, 0x3956c25b)
        F_32(w5, 0x59f111f1)
        F_32(w6, 0x923f82a4)
        F_32(w7, 0xab1c5ed5)
        F_32(w8, 0xd807aa98)
        F_32(w9, 0x12835b01)
        F_32(w10, 0x243185be)
        F_32(w11, 0x550c7dc3)
        F_32(w12, 0x72be5d74)
        F_32(w13, 0x80deb1fe)
        F_32(w14, 0x9bdc06a7)
        F_32(w15, 0xc19bf174)

        EXPAND_32

        F_32(w0, 0xe49b69c1)
        F_32(w1, 0xefbe4786)
        F_32(w2, 0x0fc19dc6)
        F_32(w3, 0x240ca1cc)
        F_32(w4, 0x2de92c6f)
        F_32(w5, 0x4a7484aa)
        F_32(w6, 0x5cb0a9dc)
        F_32(w7, 0x76f988da)
        F_32(w8, 0x983e5152)
        F_32(w9, 0xa831c66d)
        F_32(w10, 0xb00327c8)
        F_32(w11, 0xbf597fc7)
        F_32(w12, 0xc6e00bf3)
        F_32(w13, 0xd5a79147)
        F_32(w14, 0x06ca6351)
        F_32(w15, 0x14292967)

        EXPAND_32

        F_32(w0, 0x27b70a85)
        F_32(w1, 0x2e1b2138)
        F_32(w2, 0x4d2c6dfc)
        F_32(w3, 0x53380d13)
        F_32(w4, 0x650a7354)
        F_32(w5, 0x766a0abb)
        F_32(w6, 0x81c2c92e)
        F_32(w7, 0x92722c85)
        F_32(w8, 0xa2bfe8a1)
        F_32(w9, 0xa81a664b)
        F_32(w10, 0xc24b8b70)
        F_32(w11, 0xc76c51a3)
        F_32(w12, 0xd192e819)
        F_32(w13, 0xd6990624)
        F_32(w14, 0xf40e3585)
        F_32(w15, 0x106aa070)

        EXPAND_32

        F_32(w0, 0x19a4c116)
        F_32(w1, 0x1e376c08)
        F_32(w2, 0x2748774c)
        F_32(w3, 0x34b0bcb5)
        F_32(w4, 0x391c0cb3)
        F_32(w5, 0x4ed8aa4a)
        F_32(w6, 0x5b9cca4f)
        F_32(w7, 0x682e6ff3)
        F_32(w8, 0x748f82ee)
        F_32(w9, 0x78a5636f)
        F_32(w10, 0x84c87814)
        F_32(w11, 0x8cc70208)
        F_32(w12, 0x90befffa)
        F_32(w13, 0xa4506ceb)
        F_32(w14, 0xbef9a3f7)
        F_32(w15, 0xc67178f2)

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

        input += 64;
        inlen -= 64;
    }

    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);

    return inlen;
}

let mut crypto_hashblocks_sha512(statebytes: &mut[u8],input: &[u8],inlen: u64)
{
  uint64_t state[8];
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
  uint64_t e;
  uint64_t f;
  uint64_t g;
  uint64_t h;
  uint64_t T1;
  uint64_t T2;

  a = load_bigendian_64(statebytes +  0); state[0] = a;
  b = load_bigendian_64(statebytes +  8); state[1] = b;
  c = load_bigendian_64(statebytes + 16); state[2] = c;
  d = load_bigendian_64(statebytes + 24); state[3] = d;
  e = load_bigendian_64(statebytes + 32); state[4] = e;
  f = load_bigendian_64(statebytes + 40); state[5] = f;
  g = load_bigendian_64(statebytes + 48); state[6] = g;
  h = load_bigendian_64(statebytes + 56); state[7] = h;

  while (inlen >= 128) {
    uint64_t w0  = load_bigendian_64(input +   0);
    uint64_t w1  = load_bigendian_64(input +   8);
    uint64_t w2  = load_bigendian_64(input +  16);
    uint64_t w3  = load_bigendian_64(input +  24);
    uint64_t w4  = load_bigendian_64(input +  32);
    uint64_t w5  = load_bigendian_64(input +  40);
    uint64_t w6  = load_bigendian_64(input +  48);
    uint64_t w7  = load_bigendian_64(input +  56);
    uint64_t w8  = load_bigendian_64(input +  64);
    uint64_t w9  = load_bigendian_64(input +  72);
    uint64_t w10 = load_bigendian_64(input +  80);
    uint64_t w11 = load_bigendian_64(input +  88);
    uint64_t w12 = load_bigendian_64(input +  96);
    uint64_t w13 = load_bigendian_64(input + 104);
    uint64_t w14 = load_bigendian_64(input + 112);
    uint64_t w15 = load_bigendian_64(input + 120);

    F_64(w0 ,0x428a2f98d728ae22ULL)
    F_64(w1 ,0x7137449123ef65cdULL)
    F_64(w2 ,0xb5c0fbcfec4d3b2fULL)
    F_64(w3 ,0xe9b5dba58189dbbcULL)
    F_64(w4 ,0x3956c25bf348b538ULL)
    F_64(w5 ,0x59f111f1b605d019ULL)
    F_64(w6 ,0x923f82a4af194f9bULL)
    F_64(w7 ,0xab1c5ed5da6d8118ULL)
    F_64(w8 ,0xd807aa98a3030242ULL)
    F_64(w9 ,0x12835b0145706fbeULL)
    F_64(w10,0x243185be4ee4b28cULL)
    F_64(w11,0x550c7dc3d5ffb4e2ULL)
    F_64(w12,0x72be5d74f27b896fULL)
    F_64(w13,0x80deb1fe3b1696b1ULL)
    F_64(w14,0x9bdc06a725c71235ULL)
    F_64(w15,0xc19bf174cf692694ULL)

    EXPAND_64

    F_64(w0 ,0xe49b69c19ef14ad2ULL)
    F_64(w1 ,0xefbe4786384f25e3ULL)
    F_64(w2 ,0x0fc19dc68b8cd5b5ULL)
    F_64(w3 ,0x240ca1cc77ac9c65ULL)
    F_64(w4 ,0x2de92c6f592b0275ULL)
    F_64(w5 ,0x4a7484aa6ea6e483ULL)
    F_64(w6 ,0x5cb0a9dcbd41fbd4ULL)
    F_64(w7 ,0x76f988da831153b5ULL)
    F_64(w8 ,0x983e5152ee66dfabULL)
    F_64(w9 ,0xa831c66d2db43210ULL)
    F_64(w10,0xb00327c898fb213fULL)
    F_64(w11,0xbf597fc7beef0ee4ULL)
    F_64(w12,0xc6e00bf33da88fc2ULL)
    F_64(w13,0xd5a79147930aa725ULL)
    F_64(w14,0x06ca6351e003826fULL)
    F_64(w15,0x142929670a0e6e70ULL)

    EXPAND_64

    F_64(w0 ,0x27b70a8546d22ffcULL)
    F_64(w1 ,0x2e1b21385c26c926ULL)
    F_64(w2 ,0x4d2c6dfc5ac42aedULL)
    F_64(w3 ,0x53380d139d95b3dfULL)
    F_64(w4 ,0x650a73548baf63deULL)
    F_64(w5 ,0x766a0abb3c77b2a8ULL)
    F_64(w6 ,0x81c2c92e47edaee6ULL)
    F_64(w7 ,0x92722c851482353bULL)
    F_64(w8 ,0xa2bfe8a14cf10364ULL)
    F_64(w9 ,0xa81a664bbc423001ULL)
    F_64(w10,0xc24b8b70d0f89791ULL)
    F_64(w11,0xc76c51a30654be30ULL)
    F_64(w12,0xd192e819d6ef5218ULL)
    F_64(w13,0xd69906245565a910ULL)
    F_64(w14,0xf40e35855771202aULL)
    F_64(w15,0x106aa07032bbd1b8ULL)

    EXPAND_64

    F_64(w0 ,0x19a4c116b8d2d0c8ULL)
    F_64(w1 ,0x1e376c085141ab53ULL)
    F_64(w2 ,0x2748774cdf8eeb99ULL)
    F_64(w3 ,0x34b0bcb5e19b48a8ULL)
    F_64(w4 ,0x391c0cb3c5c95a63ULL)
    F_64(w5 ,0x4ed8aa4ae3418acbULL)
    F_64(w6 ,0x5b9cca4f7763e373ULL)
    F_64(w7 ,0x682e6ff3d6b2b8a3ULL)
    F_64(w8 ,0x748f82ee5defb2fcULL)
    F_64(w9 ,0x78a5636f43172f60ULL)
    F_64(w10,0x84c87814a1f0ab72ULL)
    F_64(w11,0x8cc702081a6439ecULL)
    F_64(w12,0x90befffa23631e28ULL)
    F_64(w13,0xa4506cebde82bde9ULL)
    F_64(w14,0xbef9a3f7b2c67915ULL)
    F_64(w15,0xc67178f2e372532bULL)

    EXPAND_64

    F_64(w0 ,0xca273eceea26619cULL)
    F_64(w1 ,0xd186b8c721c0c207ULL)
    F_64(w2 ,0xeada7dd6cde0eb1eULL)
    F_64(w3 ,0xf57d4f7fee6ed178ULL)
    F_64(w4 ,0x06f067aa72176fbaULL)
    F_64(w5 ,0x0a637dc5a2c898a6ULL)
    F_64(w6 ,0x113f9804bef90daeULL)
    F_64(w7 ,0x1b710b35131c471bULL)
    F_64(w8 ,0x28db77f523047d84ULL)
    F_64(w9 ,0x32caab7b40c72493ULL)
    F_64(w10,0x3c9ebe0a15c9bebcULL)
    F_64(w11,0x431d67c49c100d4cULL)
    F_64(w12,0x4cc5d4becb3e42b6ULL)
    F_64(w13,0x597f299cfc657e2aULL)
    F_64(w14,0x5fcb6fab3ad6faecULL)
    F_64(w15,0x6c44198c4a475817ULL)

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

    input += 128;
    inlen -= 128;
  }

  store_bigendian_64(statebytes +  0,state[0]);
  store_bigendian_64(statebytes +  8,state[1]);
  store_bigendian_64(statebytes + 16,state[2]);
  store_bigendian_64(statebytes + 24,state[3]);
  store_bigendian_64(statebytes + 32,state[4]);
  store_bigendian_64(statebytes + 40,state[5]);
  store_bigendian_64(statebytes + 48,state[6]);
  store_bigendian_64(statebytes + 56,state[7]);

  return inlen;
}


let iv_256: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
];

let iv_512: [u8; 64] = [
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae,
    0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
    0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51,
    0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c,
    0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd,
    0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79
];

pub fn sha256_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}

pub fn sha512_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 64; ++i) {
        state[i] = iv_512[i];
    }
    for (size_t i = 64; i < 72; ++i) {
        state[i] = 0;
    }
}

pub fn sha256_inc_blocks(uint8_t *state, const uint8_t *input, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);

    crypto_hashblocks_sha256(state, input, 64 * inblocks);
    bytes += 64 * inblocks;

    store_bigendian_64(state + 32, bytes);
}

pub fn sha512_inc_blocks(uint8_t *state, const uint8_t *input, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 64);

    crypto_hashblocks_sha512(state, input, 128 * inblocks);
    bytes += 128 * inblocks;

    store_bigendian_64(state + 64, bytes);
}

pub fn sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *input, size_t inlen) {
    let mut padded = [0u8; 128]
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;

    crypto_hashblocks_sha256(state, input, inlen);
    input += inlen;
    inlen &= 63;
    input -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = input[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; ++i) {
            padded[i] = 0;
        }
        padded[56] = (bytes >> 53); as u8
        padded[57] = (bytes >> 45); as u8
        padded[58] = (bytes >> 37); as u8
        padded[59] = (bytes >> 29); as u8
        padded[60] = (bytes >> 21); as u8
        padded[61] = (bytes >> 13); as u8
        padded[62] = (bytes >> 5); as u8
        padded[63] = (bytes << 3); as u8
        crypto_hashblocks_sha256(state, padded, 64);
    } else {
        for (size_t i = inlen + 1; i < 120; ++i) {
            padded[i] = 0;
        }
        padded[120] = (bytes >> 53); as u8
        padded[121] = (bytes >> 45); as u8
        padded[122] = (bytes >> 37); as u8
        padded[123] = (bytes >> 29); as u8
        padded[124] = (bytes >> 21); as u8
        padded[125] = (bytes >> 13); as u8
        padded[126] = (bytes >> 5); as u8
        padded[127] = (bytes << 3); as u8
        crypto_hashblocks_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < 32; ++i) {
        out[i] = state[i];
    }

}

pub fn sha512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *input, size_t inlen) {
    let mut padded = [0u8; 256]
    uint64_t bytes = load_bigendian_64(state + 64) + inlen;

    crypto_hashblocks_sha512(state, input, inlen);
    input += inlen;
    inlen &= 127;
    input -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = input[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 112) {
        for (size_t i = inlen + 1; i < 119; ++i) {
            padded[i] = 0;
        }
        padded[119] = (bytes >> 61); as u8
        padded[120] = (bytes >> 53); as u8
        padded[121] = (bytes >> 45); as u8
        padded[122] = (bytes >> 37); as u8
        padded[123] = (bytes >> 29); as u8
        padded[124] = (bytes >> 21); as u8
        padded[125] = (bytes >> 13); as u8
        padded[126] = (bytes >> 5); as u8
        padded[127] = (bytes << 3); as u8
        crypto_hashblocks_sha512(state, padded, 128);
    } else {
        for (size_t i = inlen + 1; i < 247; ++i) {
            padded[i] = 0;
        }
        padded[247] = (bytes >> 61); as u8
        padded[248] = (bytes >> 53); as u8
        padded[249] = (bytes >> 45); as u8
        padded[250] = (bytes >> 37); as u8
        padded[251] = (bytes >> 29); as u8
        padded[252] = (bytes >> 21); as u8
        padded[253] = (bytes >> 13); as u8
        padded[254] = (bytes >> 5); as u8
        padded[255] = (bytes << 3); as u8
        crypto_hashblocks_sha512(state, padded, 256);
    }

    for (size_t i = 0; i < 64; ++i) {
        out[i] = state[i];
    }
}

pub fn sha256(uint8_t *out, const uint8_t *input, size_t inlen) {
    let mut state = [0u8; 40]

    sha256_inc_init(state);
    sha256_inc_finalize(out, state, input, inlen);
}

pub fn sha512(uint8_t *out, const uint8_t *input, size_t inlen) {
    let mut state = [0u8; 72]

    sha512_inc_init(state);
    sha512_inc_finalize(out, state, input, inlen);
}

/**
 * mgf1 function based on the SHA-256 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'input' is merely a seed.
 * Outputs outlen number of bytes
 */
pub fn mgf1_256(out: &mut[u8], unsigned long outlen,
          input: &[u8], unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    let mut outbuf = [0u8; SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    &inbuf[..inlen].copy_from_slice(&input[..inlen]);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}

/*
 * mgf1 function based on the SHA-512 hash function
 */
pub fn mgf1_512(out: &mut[u8], unsigned long outlen,
          input: &[u8], unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    let mut outbuf = [0u8; SPX_SHA512_OUTPUT_BYTES];
    unsigned long i;

    &inbuf[..inlen].copy_from_slice(&input[..inlen]);

    /* While we can fit in at least another full block of SHA512 output.. */
    for (i = 0; (i+1)*SPX_SHA512_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha512(out, inbuf, inlen + 4);
        out += SPX_SHA512_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA512_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha512(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA512_OUTPUT_BYTES);
    }
}


/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused input thash
 **/
pub fn seed_state(spx_ctx *ctx) {
    uint8_t block[SPX_SHA512_BLOCK_BYTES];
    size_t i;

    for i in 0..SPX_N  {
        block[i] = ctx.pub_seed[i];
    }
    for (i = SPX_N; i < SPX_SHA512_BLOCK_BYTES; ++i) {
        block[i] = 0;
    }
    /* block has been properly initialized for both SHA-256 and SHA-512 */

    sha256_inc_init(ctx.state_seeded);
    sha256_inc_blocks(ctx.state_seeded, block, 1);
#if SPX_SHA512
    sha512_inc_init(ctx.state_seeded_512);
    sha512_inc_blocks(ctx.state_seeded_512, block, 1);
#endif
}
