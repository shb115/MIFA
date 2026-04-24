/* rotating_common.c
 *
 * Shared primitives and attack stages for the rotating-key-schedule
 * key-recovery attack on DEFAULT.  Cipher-level primitives are the same
 * as in ../simple_key_schedule/default_common.c; the rest is specific to
 * the rotating attack (normalize_key_schedule, make_k3, make_k0, and the
 * four attack stages).
 */

#include "rotating_common.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#  include <omp.h>
#endif

/* ================================================================
 * Constants (same values as simple_key_schedule/default_common.c)
 * ================================================================ */

const uint8_t sbox[16] = {
    0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9,
    0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5
};

uint8_t inv_sbox_tbl[16];

const uint8_t default_bit_perm[128] = {
     0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
     4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
     8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
    12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
    16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
    20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
    24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
    28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
};

uint8_t inv_perm_tbl[128];

const uint8_t default_rc[28] = {
    1, 3, 7, 15, 31, 62, 61, 59, 55, 47, 30, 60, 57, 51,
    39, 14, 29, 58, 53, 43, 22, 44, 24, 48, 33, 2, 5, 11
};

/* --- precomputed LUTs for fast state_inv_perm / state_perm -------- */
static uint64_t perm_lut_inv_lo[32][16];
static uint64_t perm_lut_inv_hi[32][16];
static uint64_t perm_lut_fwd_lo[32][16];
static uint64_t perm_lut_fwd_hi[32][16];

static int g_initialised = 0;

void rotating_common_init(void)
{
    if (g_initialised) return;

    for (int i = 0; i < 16; i++) inv_sbox_tbl[sbox[i]] = (uint8_t)i;

    for (int i = 0; i < 128; i++) inv_perm_tbl[default_bit_perm[i]] = (uint8_t)i;

    /* Inverse-permutation LUT: out[j] = in[default_bit_perm[j]]; i.e. an
     *   input bit at position b  maps to output bit inv_perm_tbl[b]. */
    for (int n = 0; n < 32; n++) {
        for (int v = 0; v < 16; v++) {
            uint64_t lo = 0, hi = 0;
            for (int b = 0; b < 4; b++) {
                if ((v >> b) & 1) {
                    int src_bit = 4 * n + b;
                    int dst_bit = inv_perm_tbl[src_bit];
                    if (dst_bit < 64) lo |= (uint64_t)1 << dst_bit;
                    else              hi |= (uint64_t)1 << (dst_bit - 64);
                }
            }
            perm_lut_inv_lo[n][v] = lo;
            perm_lut_inv_hi[n][v] = hi;
        }
    }
    /* Forward-permutation LUT: out[default_bit_perm[i]] = in[i]; i.e. an
     *   input bit at position b  maps to output bit default_bit_perm[b]. */
    for (int n = 0; n < 32; n++) {
        for (int v = 0; v < 16; v++) {
            uint64_t lo = 0, hi = 0;
            for (int b = 0; b < 4; b++) {
                if ((v >> b) & 1) {
                    int src_bit = 4 * n + b;
                    int dst_bit = default_bit_perm[src_bit];
                    if (dst_bit < 64) lo |= (uint64_t)1 << dst_bit;
                    else              hi |= (uint64_t)1 << (dst_bit - 64);
                }
            }
            perm_lut_fwd_lo[n][v] = lo;
            perm_lut_fwd_hi[n][v] = hi;
        }
    }

    g_initialised = 1;
}

/* ================================================================
 * State primitives
 * ================================================================ */

void state_copy(state_t dst, const state_t src) { memcpy(dst, src, 32); }
void state_zero(state_t s)                       { memset(s,  0,  32); }

void state_xor(state_t s, const state_t other)
{
    for (int i = 0; i < 32; i++) s[i] ^= other[i];
}

void state_inv_sbox(state_t s)
{
    for (int i = 0; i < 32; i++) s[i] = inv_sbox_tbl[s[i] & 0xF];
}

static inline void state_perm_generic(state_t s,
                                      const uint64_t (*lut_lo)[16],
                                      const uint64_t (*lut_hi)[16])
{
    uint64_t lo = 0, hi = 0;
    for (int n = 0; n < 32; n++) {
        uint8_t v = s[n] & 0xF;
        lo ^= lut_lo[n][v];
        hi ^= lut_hi[n][v];
    }
    for (int n = 0; n < 16; n++) s[n]      = (uint8_t)((lo >> (4 * n)) & 0xF);
    for (int n = 0; n < 16; n++) s[n + 16] = (uint8_t)((hi >> (4 * n)) & 0xF);
}

void state_inv_perm(state_t s) { state_perm_generic(s, perm_lut_inv_lo, perm_lut_inv_hi); }
void state_perm    (state_t s) { state_perm_generic(s, perm_lut_fwd_lo, perm_lut_fwd_hi); }

void state_rc_add(state_t s, int r)
{
    assert(r >= 0 && r < (int)(sizeof default_rc / sizeof default_rc[0]));
    uint8_t rc = default_rc[r];
    s[31] ^= (uint8_t)(1u      << 3);
    s[5]  ^= (uint8_t)(((rc >> 5) & 1u) << 3);
    s[4]  ^= (uint8_t)(((rc >> 4) & 1u) << 3);
    s[3]  ^= (uint8_t)(((rc >> 3) & 1u) << 3);
    s[2]  ^= (uint8_t)(((rc >> 2) & 1u) << 3);
    s[1]  ^= (uint8_t)(((rc >> 1) & 1u) << 3);
    s[0]  ^= (uint8_t)((rc       & 1u) << 3);
}

void state_from_u128(state_t out, uint64_t lo, uint64_t hi)
{
    for (int i = 0; i < 16; i++) out[i]      = (uint8_t)((lo >> (4 * i)) & 0xF);
    for (int i = 0; i < 16; i++) out[i + 16] = (uint8_t)((hi >> (4 * i)) & 0xF);
}

int state_eq(const state_t a, const state_t b) { return memcmp(a, b, 32) == 0; }

/* ================================================================
 * Keyspace bookkeeping
 * ================================================================ */

void rk_keyspace_init_full(rk_keyspace_t *ks)
{
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 16; j++) ks->cand[i][j] = (uint8_t)j;
        ks->count[i] = 16;
    }
}

/* ================================================================
 * make_k0 / make_k3 — collapse a recovered per-nibble keyspace into
 * the normalised class index.
 *
 * Linear-structure equivalence classes:
 *      {0, 5, 10, 15}   -> class 0
 *      {1, 4, 11, 14}   -> class 1
 *      {2, 7, 8, 13}    -> class 2
 *      {3, 6, 9, 12}    -> class 3   (default when no other match)
 * ================================================================ */

static inline int class_of_nibble(uint8_t v)
{
    /* Defensive: every caller should have masked with & 0xF already.
     * If they haven't, falling through to "class 3" for v > 15 would
     * silently return wrong classes — abort() (not assert) so the
     * check survives `-DNDEBUG` release builds used by some distro
     * packagers. */
    if (v >= 16) {
        fprintf(stderr, "class_of_nibble: invalid input v=0x%x (caller should mask with &0xF)\n", v);
        abort();
    }
    switch (v) {
        case 0: case 5: case 10: case 15: return 0;
        case 1: case 4: case 11: case 14: return 1;
        case 2: case 7:  case 8: case 13: return 2;
        case 3: case 6:  case 9: case 12: return 3;
        default:                          /* unreachable */
            return 3;
    }
}

void make_k0(state_t nk_inout)
{
    for (int i = 0; i < 32; i++) nk_inout[i] = (uint8_t)class_of_nibble(nk_inout[i]);
}

/* make_k3 classifies each nibble's 4-candidate keyspace into one of
 * the four linear-structure classes by building an order-independent
 * bit-set of the candidates and matching against the four class masks:
 *   - {0, 5, 10, 15} -> mask 0x8421 -> class 0
 *   - {1, 4, 11, 14} -> mask 0x4812 -> class 1
 *   - {2, 7,  8, 13} -> mask 0x2184 -> class 2
 *   - {3, 6,  9, 12} -> mask 0x1248 -> class 3
 * Anything else (count != 4, zero-length, union of classes, …) emits
 * a stderr warning and falls back to class 3, so a future bug that
 * breaks the upstream invariant is loud, not silent.
 *
 * Using a bit-set rather than a literal list-equality check makes the
 * classification robust against any future upstream filter that
 * returns the same four candidates in a different order. */
void make_k3(state_t nk_out, const rk_keyspace_t *ks)
{
    /* Bit-set encoding: bit k is set iff k is in the candidate set.
     * Each mask has exactly 4 bits set — one per class member. */
    static const uint16_t class_mask[4] = {
        (uint16_t)((1u <<  0) | (1u <<  5) | (1u << 10) | (1u << 15)),  /* class 0: 0x8421 */
        (uint16_t)((1u <<  1) | (1u <<  4) | (1u << 11) | (1u << 14)),  /* class 1: 0x4812 */
        (uint16_t)((1u <<  2) | (1u <<  7) | (1u <<  8) | (1u << 13)),  /* class 2: 0x2184 */
        (uint16_t)((1u <<  3) | (1u <<  6) | (1u <<  9) | (1u << 12)),  /* class 3: 0x1248 */
    };
    for (int i = 0; i < 32; i++) {
        if (ks->count[i] == 4) {
            const uint8_t *c = ks->cand[i];
            uint16_t m = (uint16_t)((1u << (c[0] & 0xF))
                                  | (1u << (c[1] & 0xF))
                                  | (1u << (c[2] & 0xF))
                                  | (1u << (c[3] & 0xF)));
            int matched = 0;
            for (int cls = 0; cls < 4; cls++) {
                if (m == class_mask[cls]) {
                    nk_out[i] = (uint8_t)cls;
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                fprintf(stderr,
                    "make_k3: nibble %d has count 4 but cand=[%u,%u,%u,%u] "
                    "(bit-set 0x%04x) matches none of the four linear-"
                    "structure classes — defaulting to class 3, but "
                    "upstream filter invariant may be broken\n",
                    i, c[0], c[1], c[2], c[3], (unsigned)m);
                nk_out[i] = 3;
            }
        } else {
            fprintf(stderr,
                "make_k3: nibble %d has count=%u (expected 4) — "
                "defaulting to class 3; the rotating attack's "
                "invariant that every nibble's keyspace is exactly "
                "one linear-structure class is broken for this input\n",
                i, (unsigned)ks->count[i]);
            nk_out[i] = 3;
        }
    }
}

/* ================================================================
 * normalize_key_schedule — produce the normalised round-key table
 * `nk[4]` from the raw round keys `rk[4]`.
 *
 * For each round key from rk[3] down to rk[1]:
 *   - apply inv_perm to the round key;
 *   - for each nibble, find the (delta_in, delta_out) pair from
 *       linear_structures1 = [(0,0), (0xa,6), (0xf,9), (5,0xf)]
 *     such that (nibble ^ delta_in) & 0xc == 0; XOR delta_in into the
 *     nibble, record delta_out into next_key_delta[nibble_idx];
 *   - apply perm (forward) to the normalised round key;
 *   - XOR next_key_delta into the NEXT-lower round key (in-place).
 *
 * Notes:
 *   - nk[0] is never in-place normalised; it remains `rk[0]` XORed
 *     with all deltas propagated downward from round 1.
 *   - The input `rk[]` is not mutated: we deep-copy into nk[] on entry
 *     and operate on nk[] thereafter.
 * ================================================================ */
void normalize_key_schedule(state_t nk[4], const state_t rk[4])
{
    static const uint8_t li_in [4] = {0x0, 0xa, 0xf, 0x5};
    static const uint8_t li_out[4] = {0x0, 0x6, 0x9, 0xf};
    const uint8_t in_mask  = 0xc;
    const uint8_t in_value = 0x0;

    for (int i = 0; i < 4; i++) state_copy(nk[i], rk[i]);

    for (int round_idx = 3; round_idx >= 1; round_idx--) {
        state_t rk_t;
        state_copy(rk_t, nk[round_idx]);
        state_inv_perm(rk_t);

        state_t delta;
        state_zero(delta);

        for (int nibble_idx = 0; nibble_idx < 32; nibble_idx++) {
            uint8_t nib = rk_t[nibble_idx] & 0xF;
            int matched = 0;
            for (int k = 0; k < 4; k++) {
                if (((nib ^ li_in[k]) & in_mask) == in_value) {
                    rk_t[nibble_idx] = (uint8_t)(nib ^ li_in[k]);
                    delta[nibble_idx] = li_out[k];
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                fprintf(stderr, "normalize_key_schedule: no linear "
                                "structure matches nibble 0x%X at pos %d "
                                "of round %d\n", nib, nibble_idx, round_idx);
                exit(1);
            }
        }

        state_perm(rk_t);
        state_copy(nk[round_idx], rk_t);

        /* XOR delta into the next lower round key. */
        state_xor(nk[round_idx - 1], delta);
    }
}

/* ================================================================
 * Attack stages — attack_r{1..4}.
 *
 * Each stage iterates over all pairs, maintains a per-nibble keyspace
 * (intersect-as-you-go), and parallelises over pairs only at the
 * outermost level.  Parallelising the *per-pair filtering* across
 * nibbles inside OpenMP was considered but skipped: the work per pair
 * is small (32 nibbles × few candidates) and the dominant cost is the
 * global intersection, which has to be done sequentially per pair to
 * keep the output a deterministic function of the input pairs.
 * ================================================================ */

/* Compute an intersected-per-nibble-filter for one pair.  `keep[i][k]`
 * is 1 iff candidate k at nibble i satisfies this pair's S-box
 * differential.  Caller intersects this against the running keyspace. */
static inline void build_pair_filter(uint8_t keep[32][16],
                                     const state_t dec_cip,
                                     const state_t dec_fcip,
                                     const state_t target_diff)
{
    for (int i = 0; i < 32; i++) {
        uint8_t dc = dec_cip [i];
        uint8_t df = dec_fcip[i];
        for (int k = 0; k < 16; k++) {
            uint8_t in_diff =
                (uint8_t)(inv_sbox_tbl[dc ^ k] ^ inv_sbox_tbl[df ^ k]);
            keep[i][k] = (in_diff == target_diff[i]);
        }
    }
}

/* Intersect `keep` into `ks`. */
static inline void intersect_keyspace(rk_keyspace_t *ks,
                                      const uint8_t keep[32][16])
{
    for (int i = 0; i < 32; i++) {
        uint8_t w = 0;
        for (uint8_t j = 0; j < ks->count[i]; j++) {
            uint8_t k = ks->cand[i][j];
            if (keep[i][k]) ks->cand[i][w++] = k;
        }
        ks->count[i] = w;
    }
}

/* ================================================================
 * attack_r1..r4 — CONVENTIONS
 *
 *   1. "key" = inv_perm(rk).  The peel order is  rc_add → inv_perm →
 *      XOR(key) → inv_sbox ; because the bit-perm is linear this is
 *      algebraically  rc_add → XOR(rk) → inv_perm → inv_sbox , but
 *      written this way each per-nibble filter runs on the post-
 *      inv_perm state.  The recovered variables therefore hold
 *      inv_perm(rk), so drivers compare against state_inv_perm(rk).
 *
 *   2. RC index convention for the ROTATING schedule:
 *      reduced_encrypt uses rc[28-R .. 27], so the LAST round always
 *      uses rc[27].  Hard-coded below as 27, 26, ... NOT the simple
 *      schedule's `last_round = R-1` convention (see
 *      simple_key_schedule/default_common.c::attack_r1).  Do not
 *      feed a simple-schedule ciphertext to this rotating attack.
 * ================================================================ */

void attack_r1(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               rk_keyspace_t *rk3_ks)
{
    rk_keyspace_init_full(rk3_ks);

    /* Per-pair filters are independent and parallelisable. */
    typedef uint8_t filter_t[32][16];
    filter_t *filters = (filter_t *)calloc(n_pairs, sizeof(filter_t));
    if (!filters) { fprintf(stderr, "attack_r1: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n_pairs; i++) {
        state_t dc, df;
        state_copy(dc, c1_list[i]); state_copy(df, c2_list[i]);
        state_rc_add (dc, 27);       state_rc_add (df, 27);
        state_inv_perm(dc);          state_inv_perm(df);
        build_pair_filter(filters[i], dc, df, trail_target[i]);
    }
    for (size_t i = 0; i < n_pairs; i++) intersect_keyspace(rk3_ks, filters[i]);
    free(filters);
}

void attack_r2(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               const state_t  nk3,
               rk_keyspace_t *rk2_ks)
{
    rk_keyspace_init_full(rk2_ks);

    typedef uint8_t filter_t[32][16];
    filter_t *filters = (filter_t *)calloc(n_pairs, sizeof(filter_t));
    if (!filters) { fprintf(stderr, "attack_r2: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n_pairs; i++) {
        state_t dc, df;
        state_copy(dc, c1_list[i]); state_copy(df, c2_list[i]);
        state_rc_add (dc, 27); state_rc_add (df, 27);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk3);    state_xor(df, nk3);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 26); state_rc_add (df, 26);
        state_inv_perm(dc);    state_inv_perm(df);
        build_pair_filter(filters[i], dc, df, trail_target[i]);
    }
    for (size_t i = 0; i < n_pairs; i++) intersect_keyspace(rk2_ks, filters[i]);
    free(filters);
}

void attack_r3(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               const state_t  nk3,
               const state_t  nk2,
               rk_keyspace_t *rk1_ks)
{
    rk_keyspace_init_full(rk1_ks);

    typedef uint8_t filter_t[32][16];
    filter_t *filters = (filter_t *)calloc(n_pairs, sizeof(filter_t));
    if (!filters) { fprintf(stderr, "attack_r3: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n_pairs; i++) {
        state_t dc, df;
        state_copy(dc, c1_list[i]); state_copy(df, c2_list[i]);
        state_rc_add (dc, 27); state_rc_add (df, 27);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk3);    state_xor(df, nk3);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 26); state_rc_add (df, 26);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk2);    state_xor(df, nk2);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 25); state_rc_add (df, 25);
        state_inv_perm(dc);    state_inv_perm(df);
        build_pair_filter(filters[i], dc, df, trail_target[i]);
    }
    for (size_t i = 0; i < n_pairs; i++) intersect_keyspace(rk1_ks, filters[i]);
    free(filters);
}

void attack_r4(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               const state_t  nk3,
               const state_t  nk2,
               const state_t  nk1,
               rk_keyspace_t *rk0_ks)
{
    rk_keyspace_init_full(rk0_ks);

    typedef uint8_t filter_t[32][16];
    filter_t *filters = (filter_t *)calloc(n_pairs, sizeof(filter_t));
    if (!filters) { fprintf(stderr, "attack_r4: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n_pairs; i++) {
        state_t dc, df;
        state_copy(dc, c1_list[i]); state_copy(df, c2_list[i]);
        state_rc_add (dc, 27); state_rc_add (df, 27);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk3);    state_xor(df, nk3);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 26); state_rc_add (df, 26);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk2);    state_xor(df, nk2);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 25); state_rc_add (df, 25);
        state_inv_perm(dc);    state_inv_perm(df);
        state_xor(dc, nk1);    state_xor(df, nk1);
        state_inv_sbox(dc);    state_inv_sbox(df);
        state_rc_add (dc, 24); state_rc_add (df, 24);
        state_inv_perm(dc);    state_inv_perm(df);
        build_pair_filter(filters[i], dc, df, trail_target[i]);
    }
    for (size_t i = 0; i < n_pairs; i++) intersect_keyspace(rk0_ks, filters[i]);
    free(filters);
}
