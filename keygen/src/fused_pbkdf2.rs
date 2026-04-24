// Fused PBKDF2-HMAC-SHA512 using ARM SHA-512 hardware instructions.
//
// Eliminates ring's overhead by:
// - Precomputing HMAC inner/outer hash states once
// - Keeping state in NEON registers across the PBKDF2 loop
// - Skipping byte-endian conversions in the inner loop
// - No Context objects, no heap allocation, no function call boundaries
//
// SHA-512 compression adapted from the sha2 crate (MIT/Apache-2.0).

#[cfg(target_arch = "aarch64")]
use core::arch::{aarch64::*, asm};

#[cfg(target_arch = "aarch64")]
static K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[cfg(target_arch = "aarch64")]
const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

// ── SHA-512 intrinsic polyfills (inline asm, from sha2 crate) ──

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vsha512hq_u64(
    mut hash_ed: uint64x2_t, hash_gf: uint64x2_t, kwh: uint64x2_t,
) -> uint64x2_t {
    asm!(
        "SHA512H {:q}, {:q}, {:v}.2D",
        inout(vreg) hash_ed, in(vreg) hash_gf, in(vreg) kwh,
        options(pure, nomem, nostack, preserves_flags)
    );
    hash_ed
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vsha512h2q_u64(
    mut sum_ab: uint64x2_t, hash_c_: uint64x2_t, hash_ab: uint64x2_t,
) -> uint64x2_t {
    asm!(
        "SHA512H2 {:q}, {:q}, {:v}.2D",
        inout(vreg) sum_ab, in(vreg) hash_c_, in(vreg) hash_ab,
        options(pure, nomem, nostack, preserves_flags)
    );
    sum_ab
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vsha512su0q_u64(mut w0_1: uint64x2_t, w2_: uint64x2_t) -> uint64x2_t {
    asm!(
        "SHA512SU0 {:v}.2D, {:v}.2D",
        inout(vreg) w0_1, in(vreg) w2_,
        options(pure, nomem, nostack, preserves_flags)
    );
    w0_1
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vsha512su1q_u64(
    mut s01: uint64x2_t, w14_15: uint64x2_t, w9_10: uint64x2_t,
) -> uint64x2_t {
    asm!(
        "SHA512SU1 {:v}.2D, {:v}.2D, {:v}.2D",
        inout(vreg) s01, in(vreg) w14_15, in(vreg) w9_10,
        options(pure, nomem, nostack, preserves_flags)
    );
    s01
}

// ── SHA-512 round macros (must precede compression functions) ──

#[cfg(target_arch = "aarch64")]
macro_rules! sha512_round2 {
    ($ab:ident, $cd:ident, $ef:ident, $gh:ident, $wi:expr, $ki:expr) => {
        let initial_sum = vaddq_u64($wi, vld1q_u64(K64.as_ptr().add($ki)));
        let sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), $gh);
        let intermed = vsha512hq_u64(sum, vextq_u64($ef, $gh, 1), vextq_u64($cd, $ef, 1));
        $gh = vsha512h2q_u64(intermed, $cd, $ab);
        $cd = vaddq_u64($cd, intermed);
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! sha512_schedule_round16 {
    ($ab:ident,$cd:ident,$ef:ident,$gh:ident,
     $s0:ident,$s1:ident,$s2:ident,$s3:ident,
     $s4:ident,$s5:ident,$s6:ident,$s7:ident, $t:expr) => {
        $s0 = vsha512su1q_u64(vsha512su0q_u64($s0, $s1), $s7, vextq_u64($s4, $s5, 1));
        sha512_round2!($ab, $cd, $ef, $gh, $s0, $t);
        $s1 = vsha512su1q_u64(vsha512su0q_u64($s1, $s2), $s0, vextq_u64($s5, $s6, 1));
        sha512_round2!($gh, $ab, $cd, $ef, $s1, $t + 2);
        $s2 = vsha512su1q_u64(vsha512su0q_u64($s2, $s3), $s1, vextq_u64($s6, $s7, 1));
        sha512_round2!($ef, $gh, $ab, $cd, $s2, $t + 4);
        $s3 = vsha512su1q_u64(vsha512su0q_u64($s3, $s4), $s2, vextq_u64($s7, $s0, 1));
        sha512_round2!($cd, $ef, $gh, $ab, $s3, $t + 6);
        $s4 = vsha512su1q_u64(vsha512su0q_u64($s4, $s5), $s3, vextq_u64($s0, $s1, 1));
        sha512_round2!($ab, $cd, $ef, $gh, $s4, $t + 8);
        $s5 = vsha512su1q_u64(vsha512su0q_u64($s5, $s6), $s4, vextq_u64($s1, $s2, 1));
        sha512_round2!($gh, $ab, $cd, $ef, $s5, $t + 10);
        $s6 = vsha512su1q_u64(vsha512su0q_u64($s6, $s7), $s5, vextq_u64($s2, $s3, 1));
        sha512_round2!($ef, $gh, $ab, $cd, $s6, $t + 12);
        $s7 = vsha512su1q_u64(vsha512su0q_u64($s7, $s0), $s6, vextq_u64($s3, $s4, 1));
        sha512_round2!($cd, $ef, $gh, $ab, $s7, $t + 14);
    };
}

#[cfg(target_arch = "aarch64")]
macro_rules! sha512_rounds {
    ($ab:ident, $cd:ident, $ef:ident, $gh:ident,
     $s0:ident, $s1:ident, $s2:ident, $s3:ident,
     $s4:ident, $s5:ident, $s6:ident, $s7:ident) => {
        sha512_round2!($ab, $cd, $ef, $gh, $s0, 0);
        sha512_round2!($gh, $ab, $cd, $ef, $s1, 2);
        sha512_round2!($ef, $gh, $ab, $cd, $s2, 4);
        sha512_round2!($cd, $ef, $gh, $ab, $s3, 6);
        sha512_round2!($ab, $cd, $ef, $gh, $s4, 8);
        sha512_round2!($gh, $ab, $cd, $ef, $s5, 10);
        sha512_round2!($ef, $gh, $ab, $cd, $s6, 12);
        sha512_round2!($cd, $ef, $gh, $ab, $s7, 14);

        // Rounds 16-79: loop (4 iterations × 16 rounds). Kept as loop to avoid
        // I-cache pressure from the fully inlined PBKDF2 function.
        let mut t = 16usize;
        while t < 80 {
            sha512_schedule_round16!($ab,$cd,$ef,$gh,$s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7, t);
            t += 16;
        }
    };
}

// ── SHA-512 compression (byte-array block, for initial blocks) ──

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut ab = vld1q_u64(state.as_ptr());
    let mut cd = vld1q_u64(state.as_ptr().add(2));
    let mut ef = vld1q_u64(state.as_ptr().add(4));
    let mut gh = vld1q_u64(state.as_ptr().add(6));
    let (ab_orig, cd_orig, ef_orig, gh_orig) = (ab, cd, ef, gh);

    // Load message words and byte-swap from big-endian
    let mut s0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr())));
    let mut s1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(16))));
    let mut s2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(32))));
    let mut s3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(48))));
    let mut s4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(64))));
    let mut s5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(80))));
    let mut s6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(96))));
    let mut s7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(112))));

    sha512_rounds!(ab, cd, ef, gh, s0, s1, s2, s3, s4, s5, s6, s7);

    ab = vaddq_u64(ab, ab_orig);
    cd = vaddq_u64(cd, cd_orig);
    ef = vaddq_u64(ef, ef_orig);
    gh = vaddq_u64(gh, gh_orig);

    vst1q_u64(state.as_mut_ptr(), ab);
    vst1q_u64(state.as_mut_ptr().add(2), cd);
    vst1q_u64(state.as_mut_ptr().add(4), ef);
    vst1q_u64(state.as_mut_ptr().add(6), gh);
}

// ── SHA-512 compression (u64 words, no byte-swap — for PBKDF2 inner loop) ──

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sha512_compress_u64(state: &mut [u64; 8], words: &[u64; 16]) {
    let mut ab = vld1q_u64(state.as_ptr());
    let mut cd = vld1q_u64(state.as_ptr().add(2));
    let mut ef = vld1q_u64(state.as_ptr().add(4));
    let mut gh = vld1q_u64(state.as_ptr().add(6));
    let (ab_orig, cd_orig, ef_orig, gh_orig) = (ab, cd, ef, gh);

    let mut s0 = vld1q_u64(words.as_ptr());
    let mut s1 = vld1q_u64(words.as_ptr().add(2));
    let mut s2 = vld1q_u64(words.as_ptr().add(4));
    let mut s3 = vld1q_u64(words.as_ptr().add(6));
    let mut s4 = vld1q_u64(words.as_ptr().add(8));
    let mut s5 = vld1q_u64(words.as_ptr().add(10));
    let mut s6 = vld1q_u64(words.as_ptr().add(12));
    let mut s7 = vld1q_u64(words.as_ptr().add(14));

    sha512_rounds!(ab, cd, ef, gh, s0, s1, s2, s3, s4, s5, s6, s7);

    ab = vaddq_u64(ab, ab_orig);
    cd = vaddq_u64(cd, cd_orig);
    ef = vaddq_u64(ef, ef_orig);
    gh = vaddq_u64(gh, gh_orig);

    vst1q_u64(state.as_mut_ptr(), ab);
    vst1q_u64(state.as_mut_ptr().add(2), cd);
    vst1q_u64(state.as_mut_ptr().add(4), ef);
    vst1q_u64(state.as_mut_ptr().add(6), gh);
}

// ── SHA-512 full hash (for hashing keys > 128 bytes) ──

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sha512_hash(data: &[u8]) -> [u64; 8] {
    let mut state = IV;
    let mut offset = 0;
    while offset + 128 <= data.len() {
        sha512_compress(&mut state, &*(data.as_ptr().add(offset) as *const [u8; 128]));
        offset += 128;
    }
    let remaining = data.len() - offset;
    let bit_len = (data.len() as u128) * 8;

    let mut block = [0u8; 128];
    block[..remaining].copy_from_slice(&data[offset..]);
    block[remaining] = 0x80;

    if remaining < 112 {
        block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_compress(&mut state, &block);
    } else {
        sha512_compress(&mut state, &block);
        block = [0u8; 128];
        block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        sha512_compress(&mut state, &block);
    }
    state
}

// ── Fused PBKDF2-HMAC-SHA512 ──

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
pub unsafe fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8; 64]) {
    // Step 1: Derive HMAC key (hash if > 128 bytes)
    let mut padded_key = [0u8; 128];
    if password.len() > 128 {
        let hashed = sha512_hash(password);
        for i in 0..8 {
            padded_key[i * 8..(i + 1) * 8].copy_from_slice(&hashed[i].to_be_bytes());
        }
    } else {
        padded_key[..password.len()].copy_from_slice(password);
    }

    // Step 2: Precompute HMAC inner/outer states
    let mut inner_pad = [0u8; 128];
    let mut outer_pad = [0u8; 128];
    for i in 0..128 {
        inner_pad[i] = padded_key[i] ^ 0x36;
        outer_pad[i] = padded_key[i] ^ 0x5c;
    }
    let mut inner_state = IV;
    sha512_compress(&mut inner_state, &inner_pad);
    let mut outer_state = IV;
    sha512_compress(&mut outer_state, &outer_pad);

    // Step 3: Compute U1 = HMAC(key, salt || BE32(1))
    // Inner hash: SHA-512(inner_pad || salt || INT(1))
    // Total length: 128 + salt.len() + 4
    let total_inner_len = (128 + salt.len() + 4) as u128 * 8;
    let data_len = salt.len() + 4;

    let mut state;
    if data_len <= 112 {
        // Fits in one block after inner_pad
        let mut block = [0u8; 128];
        block[..salt.len()].copy_from_slice(salt);
        block[salt.len()..salt.len() + 4].copy_from_slice(&1u32.to_be_bytes());
        block[data_len] = 0x80;
        block[112..128].copy_from_slice(&total_inner_len.to_be_bytes());
        state = inner_state;
        sha512_compress(&mut state, &block);
    } else {
        // Need more blocks (unlikely for "mnemonic" salt but handle correctly)
        let mut msg = Vec::new();
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&1u32.to_be_bytes());
        state = inner_state;
        let mut off = 0;
        while off + 128 <= msg.len() {
            sha512_compress(&mut state, &*(msg.as_ptr().add(off) as *const [u8; 128]));
            off += 128;
        }
        let rem = msg.len() - off;
        let mut block = [0u8; 128];
        block[..rem].copy_from_slice(&msg[off..]);
        block[rem] = 0x80;
        if rem < 112 {
            block[112..128].copy_from_slice(&total_inner_len.to_be_bytes());
            sha512_compress(&mut state, &block);
        } else {
            sha512_compress(&mut state, &block);
            block = [0u8; 128];
            block[112..128].copy_from_slice(&total_inner_len.to_be_bytes());
            sha512_compress(&mut state, &block);
        }
    }
    let inner_hash = state;

    // Outer hash: SHA-512(outer_pad || inner_hash)
    // Total length: 128 + 64 = 192 bytes = 1536 bits
    let outer_len: u128 = 192 * 8;
    let mut outer_block_template = [0u64; 16];
    outer_block_template[8] = 0x8000000000000000;
    outer_block_template[15] = outer_len as u64;

    let mut outer_words = outer_block_template;
    for i in 0..8 {
        outer_words[i] = inner_hash[i];
    }
    state = outer_state;
    sha512_compress_u64(&mut state, &outer_words);
    let mut u = state;
    let mut acc = u;

    // Step 4: PBKDF2 iterations 2..iterations
    // Persistent word arrays — only first 8 words change per iteration,
    // padding words 8-15 are constant.
    let mut inner_words = [0u64; 16];
    inner_words[8] = 0x8000000000000000;
    inner_words[15] = 192 * 8; // 1536 bits
    let mut outer_words = inner_words; // same padding structure

    for _ in 1..iterations {
        // Inner hash: compress(inner_state, U || padding)
        inner_words[0] = u[0]; inner_words[1] = u[1];
        inner_words[2] = u[2]; inner_words[3] = u[3];
        inner_words[4] = u[4]; inner_words[5] = u[5];
        inner_words[6] = u[6]; inner_words[7] = u[7];

        state = inner_state;
        sha512_compress_u64(&mut state, &inner_words);

        // Outer hash: compress(outer_state, inner_hash || padding)
        outer_words[0] = state[0]; outer_words[1] = state[1];
        outer_words[2] = state[2]; outer_words[3] = state[3];
        outer_words[4] = state[4]; outer_words[5] = state[5];
        outer_words[6] = state[6]; outer_words[7] = state[7];

        state = outer_state;
        sha512_compress_u64(&mut state, &outer_words);
        u = state;

        // XOR into accumulator
        acc[0] ^= u[0]; acc[1] ^= u[1]; acc[2] ^= u[2]; acc[3] ^= u[3];
        acc[4] ^= u[4]; acc[5] ^= u[5]; acc[6] ^= u[6]; acc[7] ^= u[7];
    }

    // Step 5: Write output as big-endian bytes
    for i in 0..8 {
        output[i * 8..(i + 1) * 8].copy_from_slice(&acc[i].to_be_bytes());
    }
}

// ── HMAC-SHA512 (for BIP32) ──

/// HMAC-SHA512 using hardware SHA-512. Returns 64-byte MAC as [u64; 8].
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // Derive HMAC key (hash if > 128 bytes)
    let mut padded_key = [0u8; 128];
    if key.len() > 128 {
        let hashed = sha512_hash(key);
        for i in 0..8 {
            padded_key[i * 8..(i + 1) * 8].copy_from_slice(&hashed[i].to_be_bytes());
        }
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    // Inner hash: SHA-512(inner_pad || data)
    let mut inner_pad = [0u8; 128];
    for i in 0..128 { inner_pad[i] = padded_key[i] ^ 0x36; }
    let mut state = IV;
    sha512_compress(&mut state, &inner_pad);

    // Process data blocks
    let mut offset = 0;
    while offset + 128 <= data.len() {
        sha512_compress(&mut state, &*(data.as_ptr().add(offset) as *const [u8; 128]));
        offset += 128;
    }
    let remaining = data.len() - offset;
    let total_len = (128 + data.len()) as u128 * 8;
    let mut block = [0u8; 128];
    block[..remaining].copy_from_slice(&data[offset..]);
    block[remaining] = 0x80;
    if remaining < 112 {
        block[112..128].copy_from_slice(&total_len.to_be_bytes());
        sha512_compress(&mut state, &block);
    } else {
        sha512_compress(&mut state, &block);
        block = [0u8; 128];
        block[112..128].copy_from_slice(&total_len.to_be_bytes());
        sha512_compress(&mut state, &block);
    }
    let inner_hash = state;

    // Outer hash: SHA-512(outer_pad || inner_hash)
    let mut outer_pad = [0u8; 128];
    for i in 0..128 { outer_pad[i] = padded_key[i] ^ 0x5c; }
    state = IV;
    sha512_compress(&mut state, &outer_pad);

    let mut outer_block = [0u8; 128];
    for i in 0..8 {
        outer_block[i * 8..(i + 1) * 8].copy_from_slice(&inner_hash[i].to_be_bytes());
    }
    outer_block[64] = 0x80;
    let outer_len: u128 = (128 + 64) * 8;
    outer_block[112..128].copy_from_slice(&outer_len.to_be_bytes());
    sha512_compress(&mut state, &outer_block);

    let mut output = [0u8; 64];
    for i in 0..8 {
        output[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_be_bytes());
    }
    output
}

/// Test-only wrapper for hmac_sha512
#[cfg(all(target_arch = "aarch64", test))]
pub unsafe fn hmac_sha512_for_test(key: &[u8], data: &[u8]) -> [u8; 64] {
    hmac_sha512(key, data)
}

/// Test-only: returns intermediate secret bytes at each BIP32 level
#[cfg(all(target_arch = "aarch64", test))]
pub unsafe fn bip32_debug(seed: &[u8; 64]) -> Vec<[u8; 32]> {
    let mut levels = Vec::new();
    let result = hmac_sha512(b"ed25519 seed", seed);
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    levels.push(secret);

    for &index in &[44u32, 501, 0, 0] {
        let index_bits = index | 0x80000000;
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&secret);
        data[33..37].copy_from_slice(&index_bits.to_be_bytes());
        let result = hmac_sha512(&chain_code, &data);
        secret.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
        levels.push(secret);
    }
    levels
}

// ── Lean BIP32 derivation (avoids 4 unnecessary scalar multiplies) ──

/// BIP32 ed25519 derivation using hardware SHA-512 HMAC.
/// Only computes the public key (scalar multiply) once at the end,
/// instead of at every intermediate derivation level.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn bip32_derive_raw(seed: &[u8; 64], path: &[(u32, bool)]) -> [u8; 32] {
    // from_seed: HMAC-SHA512("ed25519 seed", seed) → (secret, chain_code)
    let result = hmac_sha512(b"ed25519 seed", seed);
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // derive_child for each path component — raw bytes only, no scalar multiply
    for &(index, _hardened) in path {
        let index_bits = index | 0x80000000; // hardened
        let mut data = [0u8; 37]; // 1 + 32 + 4
        data[0] = 0x00;
        data[1..33].copy_from_slice(&secret);
        data[33..37].copy_from_slice(&index_bits.to_be_bytes());

        let result = hmac_sha512(&chain_code, &data);
        secret.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    secret
}

/// Full keypair derivation: fused PBKDF2 → lean BIP32 → Keypair.
/// Combines HW-accelerated PBKDF2 with overhead-free BIP32.
pub fn derive_keypair_fused(mnemonic_phrase: &[u8]) -> solana_keypair::Keypair {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha3") {
            unsafe {
                let mut seed = [0u8; 64];
                pbkdf2_sha512(mnemonic_phrase, b"mnemonic", 2048, &mut seed);
                let secret = bip32_derive_raw(&seed, &[
                    (44, true), (501, true), (0, true), (0, true),
                ]);
                return solana_keypair::Keypair::new_from_array(secret);
            }
        }
    }

    // Fallback
    let mut seed = [0u8; 64];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(2048).unwrap(),
        b"mnemonic",
        mnemonic_phrase,
        &mut seed,
    );
    solana_keypair::seed_derivable::keypair_from_seed_and_derivation_path(
        &seed,
        Some(solana_derivation_path::DerivationPath::from_absolute_path_str("m/44'/501'/0'/0'").unwrap()),
    )
    .unwrap()
}

/// Public entry point with runtime SHA-512 hardware detection.
pub fn derive_seed_fused(password: &[u8], output: &mut [u8; 64]) {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha3") {
            unsafe {
                pbkdf2_sha512(password, b"mnemonic", 2048, output);
            }
            return;
        }
    }
    // Fallback to ring if no SHA-512 hardware
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(2048).unwrap(),
        b"mnemonic",
        password,
        output,
    );
}
