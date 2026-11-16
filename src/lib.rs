//! Simple, dependency-free SHA-2 (512bit) implementation.
//!
//! ```
//! assert_eq!(simple_rs_sha2_512::sha2_512("hello").len(), 128);
//! ```

const BLOCK: usize = 128;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Compresses `blocks` into `h`, using the SHA512 instructions when the CPU has them.
#[inline(always)]
fn compress_blocks(h: &mut [u64; 8], blocks: &[[u8; BLOCK]], accel: bool) {
    #[cfg(target_arch = "x86_64")]
    if accel {
        // SAFETY: `accel` is only true when `has_sha512_ni()` confirmed the CPU features.
        unsafe { sha512ni::compress_blocks(h, blocks) };
        return;
    }
    let _ = accel;
    for block in blocks {
        compress(h, block);
    }
}

#[inline(always)]
fn has_sha512_ni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("sha512") && std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Body of the SHA512-instruction path. It is a macro so the tests can also build it against
/// software models of the three SHA512 instructions (see `tests::sha512ni_emulated`) and check
/// the state layout / message schedule on CPUs that don't have the instructions.
#[cfg(target_arch = "x86_64")]
macro_rules! sha512ni_impl {
    ($features:literal) => {
        /// Next 4 message-schedule words from the previous 16 (w0 oldest).
        #[inline]
        #[target_feature(enable = $features)]
        unsafe fn schedule(w0: __m256i, w1: __m256i, w2: __m256i, w3: __m256i) -> __m256i {
            // W[t-7..t-4] = w2[1], w2[2], w2[3], w3[0]
            let w9 = _mm256_permute4x64_epi64(_mm256_blend_epi32(w2, w3, 0x03), 0x39);
            let t = _mm256_add_epi64(_mm256_sha512msg1_epi64(w0, _mm256_castsi256_si128(w1)), w9);
            _mm256_sha512msg2_epi64(t, w3)
        }

        #[target_feature(enable = $features)]
        pub(super) unsafe fn compress_blocks(h: &mut [u64; 8], blocks: &[[u8; BLOCK]]) {
            let bswap = _mm256_set_epi64x(
                0x0809_0a0b_0c0d_0e0f,
                0x0001_0203_0405_0607,
                0x0809_0a0b_0c0d_0e0f,
                0x0001_0203_0405_0607,
            );

            // The instructions want the state as ABEF / CDGH (A in the highest qword).
            let mut abef = _mm256_set_epi64x(h[0] as i64, h[1] as i64, h[4] as i64, h[5] as i64);
            let mut cdgh = _mm256_set_epi64x(h[2] as i64, h[3] as i64, h[6] as i64, h[7] as i64);

            for block in blocks {
                let (abef_save, cdgh_save) = (abef, cdgh);
                let d = block.as_ptr() as *const __m256i;
                let mut w = [
                    _mm256_shuffle_epi8(_mm256_loadu_si256(d), bswap),
                    _mm256_shuffle_epi8(_mm256_loadu_si256(d.add(1)), bswap),
                    _mm256_shuffle_epi8(_mm256_loadu_si256(d.add(2)), bswap),
                    _mm256_shuffle_epi8(_mm256_loadu_si256(d.add(3)), bswap),
                ];
                for i in 0..20 {
                    if i >= 4 {
                        w[i % 4] =
                            schedule(w[i % 4], w[(i + 1) % 4], w[(i + 2) % 4], w[(i + 3) % 4]);
                    }
                    let k = _mm256_loadu_si256(K.as_ptr().add(i * 4) as *const __m256i);
                    let wk = _mm256_add_epi64(w[i % 4], k);
                    cdgh = _mm256_sha512rnds2_epi64(cdgh, abef, _mm256_castsi256_si128(wk));
                    abef = _mm256_sha512rnds2_epi64(abef, cdgh, _mm256_extracti128_si256(wk, 1));
                }
                abef = _mm256_add_epi64(abef, abef_save);
                cdgh = _mm256_add_epi64(cdgh, cdgh_save);
            }

            let (mut o1, mut o2) = ([0u64; 4], [0u64; 4]);
            _mm256_storeu_si256(o1.as_mut_ptr() as *mut __m256i, abef); // F E B A
            _mm256_storeu_si256(o2.as_mut_ptr() as *mut __m256i, cdgh); // H G D C
            *h = [o1[3], o1[2], o2[3], o2[2], o1[1], o1[0], o2[1], o2[0]];
        }
    };
}

#[cfg(target_arch = "x86_64")]
mod sha512ni {
    use std::arch::x86_64::*;

    use super::{BLOCK, K};

    sha512ni_impl!("sha512,avx,avx2");
}

#[inline(always)]
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK]) {
    let mut w = [0u64; 16];
    for (i, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
        w[i] = u64::from_be_bytes(*chunk);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $i:expr, $j:expr) => {
            if $i > 0 {
                let w15 = w[($j + 1) & 15];
                let w2 = w[($j + 14) & 15];
                let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
                let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
                w[$j] = w[$j]
                    .wrapping_add(s0)
                    .wrapping_add(w[($j + 9) & 15])
                    .wrapping_add(s1);
            }
            let t1 = $h
                .wrapping_add($e.rotate_right(14) ^ $e.rotate_right(18) ^ $e.rotate_right(41))
                .wrapping_add(($e & $f) ^ (!$e & $g))
                .wrapping_add(K[$i + $j])
                .wrapping_add(w[$j]);
            $d = $d.wrapping_add(t1);
            $h = t1
                .wrapping_add($a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39))
                .wrapping_add(($a & $b) ^ ($a & $c) ^ ($b & $c));
        };
    }

    for i in (0..80).step_by(16) {
        round!(a, b, c, d, e, f, g, hh, i, 0);
        round!(hh, a, b, c, d, e, f, g, i, 1);
        round!(g, hh, a, b, c, d, e, f, i, 2);
        round!(f, g, hh, a, b, c, d, e, i, 3);
        round!(e, f, g, hh, a, b, c, d, i, 4);
        round!(d, e, f, g, hh, a, b, c, i, 5);
        round!(c, d, e, f, g, hh, a, b, i, 6);
        round!(b, c, d, e, f, g, hh, a, i, 7);
        round!(a, b, c, d, e, f, g, hh, i, 8);
        round!(hh, a, b, c, d, e, f, g, i, 9);
        round!(g, hh, a, b, c, d, e, f, i, 10);
        round!(f, g, hh, a, b, c, d, e, i, 11);
        round!(e, f, g, hh, a, b, c, d, i, 12);
        round!(d, e, f, g, hh, a, b, c, i, 13);
        round!(c, d, e, f, g, hh, a, b, i, 14);
        round!(b, c, d, e, f, g, hh, a, i, 15);
    }

    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

/// Hashes `input` and returns the raw 64-byte digest.
pub fn digest(input: impl AsRef<[u8]>) -> [u8; 64] {
    let m = input.as_ref();
    let mut h = H0;
    let accel = has_sha512_ni();

    let (blocks, rem) = m.as_chunks::<BLOCK>();
    compress_blocks(&mut h, blocks, accel);

    // Padding: 0x80, zeros, then the message length in bits (big endian).
    let mut tail = [0u8; BLOCK * 2];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() + 1 + 16 > BLOCK {
        BLOCK * 2
    } else {
        BLOCK
    };
    let bit_len = (m.len() as u128).wrapping_mul(8);
    tail[tail_len - 16..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    compress_blocks(&mut h, tail[..tail_len].as_chunks::<BLOCK>().0, accel);

    let mut out = [0u8; 64];
    for (chunk, word) in out.chunks_mut(8).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
    }
    out
}

/// Hashes `input` and returns the digest as a lowercase hex string.
///
/// Accepts `&str`, `String`, `&[u8]`, `Vec<u8>`, etc.
pub fn sha2_512(input: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(128);
    for byte in digest(input) {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    /// `compress_blocks` built against software models of the SHA512 instructions, so the
    /// SIMD wiring is tested even on CPUs without them. The models are taken from the
    /// reference tests in Rust's `core::arch` (stdarch `x86/sha.rs`).
    #[cfg(target_arch = "x86_64")]
    mod sha512ni_emulated {
        use std::arch::x86_64::*;
        use std::mem::transmute;

        use crate::{BLOCK, K};

        fn s0(w: u64) -> u64 {
            w.rotate_right(1) ^ w.rotate_right(8) ^ (w >> 7)
        }
        fn s1(w: u64) -> u64 {
            w.rotate_right(19) ^ w.rotate_right(61) ^ (w >> 6)
        }

        fn q4(x: __m256i) -> [u64; 4] {
            unsafe { transmute::<__m256i, [u64; 4]>(x) }
        }
        fn q2(x: __m128i) -> [u64; 2] {
            unsafe { transmute::<__m128i, [u64; 2]>(x) }
        }
        fn m256(x: [u64; 4]) -> __m256i {
            unsafe { transmute::<[u64; 4], __m256i>(x) }
        }

        // These shadow the real intrinsics pulled in by the glob import above.
        fn _mm256_sha512msg1_epi64(a: __m256i, b: __m128i) -> __m256i {
            let (a, b) = (q4(a), q2(b));
            let r = [
                a[0].wrapping_add(s0(a[1])),
                a[1].wrapping_add(s0(a[2])),
                a[2].wrapping_add(s0(a[3])),
                a[3].wrapping_add(s0(b[0])),
            ];
            m256(r)
        }

        fn _mm256_sha512msg2_epi64(a: __m256i, b: __m256i) -> __m256i {
            let (a, b) = (q4(a), q4(b));
            let e0 = a[0].wrapping_add(s1(b[2]));
            let e1 = a[1].wrapping_add(s1(b[3]));
            let r = [e0, e1, a[2].wrapping_add(s1(e0)), a[3].wrapping_add(s1(e1))];
            m256(r)
        }

        fn _mm256_sha512rnds2_epi64(a: __m256i, b: __m256i, k: __m128i) -> __m256i {
            let (a, b, k) = (q4(a), q4(b), q2(k));
            let mut s = [b[3], b[2], a[3], a[2], b[1], b[0], a[1], a[0]];
            for ki in k {
                let e = s[4];
                let t = ((e & s[5]) ^ (s[6] & !e))
                    .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
                    .wrapping_add(ki)
                    .wrapping_add(s[7]);
                let a = s[0];
                s[7] = t
                    .wrapping_add((a & s[1]) ^ (a & s[2]) ^ (s[1] & s[2]))
                    .wrapping_add(a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39));
                s[3] = t.wrapping_add(s[3]);
                s.rotate_right(1);
            }
            m256([s[5], s[4], s[1], s[0]])
        }

        sha512ni_impl!("avx,avx2");
    }

    fn check(accelerated: impl Fn(&mut [u64; 8], &[[u8; super::BLOCK]])) {
        let data: Vec<u8> = (0..128 * 20u32).map(|i| (i * 131 + 17) as u8).collect();
        for n in 0..=20 {
            let blocks = data[..n * 128].as_chunks::<128>().0;
            let (mut a, mut b) = (super::H0, super::H0);
            accelerated(&mut a, blocks);
            super::compress_blocks(&mut b, blocks, false);
            assert_eq!(a, b, "{n} blocks");
        }
    }

    /// The SHA512-instruction path and the portable path must agree on every block.
    #[test]
    fn accelerated_matches_portable() {
        if !super::has_sha512_ni() {
            return;
        }
        check(|h, blocks| super::compress_blocks(h, blocks, true));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn emulated_accelerated_matches_portable() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        // SAFETY: AVX2 checked above; the SHA512 instructions are software models here.
        check(|h, blocks| unsafe { sha512ni_emulated::compress_blocks(h, blocks) });
    }
}
