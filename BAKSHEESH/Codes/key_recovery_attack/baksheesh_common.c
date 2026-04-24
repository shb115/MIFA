/* baksheesh_common.c
 *
 * Shared primitives + all attack stages for the BAKSHEESH key-recovery
 * attack (C + OpenMP).
 *
 * attack_r2 runs in three phases (even positions -> odd positions ->
 * combined); attack_r{3,4,5} are straight per-nibble filters over the
 * full 32-nibble survivors produced by attack_r2.
 */

#include "baksheesh_common.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#  include <omp.h>
#endif

/* ================================================================
 * Constants
 * ================================================================ */

const uint8_t sbox[16] = {
    0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe,
    0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1
};
uint8_t inv_sbox_tbl[16];

/* 128-bit permutation.  BAKSHEESH intentionally reuses the exact
 * table that the DEFAULT / GIFT-family cipher uses — this is not a
 * mistake.  See BAKSHEESH spec (IACR ePrint 2023/750, Alg. 1 /
 * Table 2) which cites "same bit-permutation as GIFT" directly. */
const uint8_t baksheesh_bit_perm[128] = {
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

const uint8_t baksheesh_rc[35] = {
     2, 33, 16,  9, 36, 19, 40, 53, 26, 13,
    38, 51, 56, 61, 62, 31, 14,  7, 34, 49,
    24, 45, 54, 59, 28, 47, 22, 43, 20, 11,
     4,  3, 32, 17,  8
};

/* Permutation LUTs (both directions) — one XOR-accumulation per nibble. */
static uint64_t perm_lut_inv_lo[32][16];
static uint64_t perm_lut_inv_hi[32][16];
static uint64_t perm_lut_fwd_lo[32][16];
static uint64_t perm_lut_fwd_hi[32][16];

static int g_init = 0;
void baksheesh_common_init(void)
{
    if (g_init) return;
    for (int i = 0; i < 16; i++) inv_sbox_tbl[sbox[i]] = (uint8_t)i;
    for (int i = 0; i < 128; i++)
        inv_perm_tbl[baksheesh_bit_perm[i]] = (uint8_t)i;

    for (int n = 0; n < 32; n++) {
        for (int v = 0; v < 16; v++) {
            uint64_t i_lo = 0, i_hi = 0, f_lo = 0, f_hi = 0;
            for (int b = 0; b < 4; b++) {
                if ((v >> b) & 1) {
                    int src = 4 * n + b;
                    int di  = inv_perm_tbl[src];
                    int df  = baksheesh_bit_perm[src];
                    if (di < 64) i_lo |= (uint64_t)1 << di;
                    else          i_hi |= (uint64_t)1 << (di - 64);
                    if (df < 64) f_lo |= (uint64_t)1 << df;
                    else          f_hi |= (uint64_t)1 << (df - 64);
                }
            }
            perm_lut_inv_lo[n][v] = i_lo;
            perm_lut_inv_hi[n][v] = i_hi;
            perm_lut_fwd_lo[n][v] = f_lo;
            perm_lut_fwd_hi[n][v] = f_hi;
        }
    }
    g_init = 1;
}

/* ================================================================
 * State primitives
 * ================================================================ */

void state_copy(state_t dst, const state_t src) { memcpy(dst, src, 32); }
void state_zero(state_t s) { memset(s, 0, 32); }

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

/* baksheesh_rc_add: XOR bits  c0..c5  of  rc[r]  into bit positions
 *   {8, 13, 19, 35, 67, 106}  of the 128-bit state. */
void state_rc_add(state_t s, int r)
{
    assert(r >= 0 && r < BAKSHEESH_ROUND_COUNT);
    uint8_t rc = baksheesh_rc[r];
    uint8_t c0 =  rc        & 1;
    uint8_t c1 = (rc >> 1)  & 1;
    uint8_t c2 = (rc >> 2)  & 1;
    uint8_t c3 = (rc >> 3)  & 1;
    uint8_t c4 = (rc >> 4)  & 1;
    uint8_t c5 = (rc >> 5)  & 1;
    s[8  / 4] ^= (uint8_t)(c0 << (8  % 4));
    s[13 / 4] ^= (uint8_t)(c1 << (13 % 4));
    s[19 / 4] ^= (uint8_t)(c2 << (19 % 4));
    s[35 / 4] ^= (uint8_t)(c3 << (35 % 4));
    s[67 / 4] ^= (uint8_t)(c4 << (67 % 4));
    s[106/ 4] ^= (uint8_t)(c5 << (106% 4));
}

void state_from_u128(state_t out, uint64_t lo, uint64_t hi)
{
    for (int i = 0; i < 16; i++) out[i]      = (uint8_t)((lo >> (4 * i)) & 0xF);
    for (int i = 0; i < 16; i++) out[i + 16] = (uint8_t)((hi >> (4 * i)) & 0xF);
}

int state_eq(const state_t a, const state_t b) { return memcmp(a, b, 32) == 0; }

/* Whole-state circular LEFT shift by 1 bit.  Nibble 0 holds the 4
 * LSBs and nibble 31 the 4 MSBs; the MSB of nibble 31 wraps into
 * the LSB of nibble 0. */
void state_circ_left_shift(state_t s)
{
    uint8_t carry_prev = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t carry = (uint8_t)((s[i] >> 3) & 1);
        s[i] = (uint8_t)(((s[i] << 1) | carry_prev) & 0xF);
        carry_prev = carry;
    }
    s[0] |= (uint8_t)(carry_prev & 0xF);
}

/* ================================================================
 * rk_keyspace_t, halfkey_vec_t, keyvec_t
 * ================================================================ */

void rk_keyspace_init_full(rk_keyspace_t *ks)
{
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 16; j++) ks->cand[i][j] = (uint8_t)j;
        ks->count[i] = 16;
    }
}

void halfkey_vec_init(halfkey_vec_t *v)
{
    v->keys = NULL;  v->count = v->capacity = 0;
}
void halfkey_vec_free(halfkey_vec_t *v)
{
    free(v->keys); v->keys = NULL; v->count = v->capacity = 0;
}
void halfkey_vec_reserve(halfkey_vec_t *v, size_t cap)
{
    if (cap <= v->capacity) return;
    uint64_t *p = (uint64_t *)realloc(v->keys, cap * sizeof(uint64_t));
    if (!p) { fprintf(stderr, "halfkey_vec_reserve: OOM (%zu)\n", cap);
              /* _Exit — may be reached from an OpenMP parallel region. */
              _Exit(1); }
    v->keys = p; v->capacity = cap;
}
void halfkey_vec_push(halfkey_vec_t *v, uint64_t packed)
{
    if (v->count >= v->capacity)
        halfkey_vec_reserve(v, v->capacity ? v->capacity * 2 : 1024);
    v->keys[v->count++] = packed;
}

void keyvec_init(keyvec_t *v)
{
    v->keys = NULL; v->count = v->capacity = 0;
}
void keyvec_free(keyvec_t *v)
{
    free(v->keys); v->keys = NULL; v->count = v->capacity = 0;
}
void keyvec_reserve(keyvec_t *v, size_t cap)
{
    if (cap <= v->capacity) return;
    state_t *p = (state_t *)realloc(v->keys, cap * sizeof(state_t));
    if (!p) { fprintf(stderr, "keyvec_reserve: OOM (%zu)\n", cap);
              /* _Exit — may be reached from an OpenMP parallel region. */
              _Exit(1); }
    v->keys = p; v->capacity = cap;
}
void keyvec_push(keyvec_t *v, const state_t key)
{
    if (v->count >= v->capacity)
        keyvec_reserve(v, v->capacity ? v->capacity * 2 : 256);
    memcpy(v->keys[v->count++], key, 32);
}

/* ================================================================
 * attack_r1..r5 — CONVENTIONS
 *
 *   1. "key" = inv_perm(rk).  The peel order is  rc_add → inv_perm →
 *      XOR(key) → inv_sbox ; per-nibble filters run on the post-
 *      inv_perm state.  Recovered vars therefore hold inv_perm(rk);
 *      compute_mk_nibbles() in key_recovery_Nr.c applies inv_perm
 *      to the rotation of the master key for the final comparison.
 *
 *   2. RC index convention: reduced_encrypt uses rc[35-R .. 34], so
 *      the LAST round always uses rc[34] (= BAKSHEESH_LAST_RC).
 *      This matches the DEFAULT rotating-schedule pattern of
 *      "LAST round's RC is hard-coded, not parameterised by R".
 *
 * attack_r1 — per-nibble filter (same shape as the rotating-DEFAULT
 * version, just with BAKSHEESH rc[34]).
 * ================================================================ */

void attack_r1(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               rk_keyspace_t *rk_ks)
{
    rk_keyspace_init_full(rk_ks);

    typedef uint8_t filter_t[32][16];
    filter_t *F = (filter_t *)calloc(n_pairs, sizeof(filter_t));
    if (!F) { fprintf(stderr, "attack_r1: OOM\n"); exit(1); }

#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n_pairs; i++) {
        state_t d1, d2;
        state_copy(d1, c1_list[i]);
        state_copy(d2, c2_list[i]);
        state_rc_add(d1, BAKSHEESH_LAST_RC);
        state_rc_add(d2, BAKSHEESH_LAST_RC);
        state_inv_perm(d1);
        state_inv_perm(d2);
        for (int p = 0; p < 32; p++) {
            uint8_t dc = d1[p];
            uint8_t df = d2[p];
            for (int k = 0; k < 16; k++) {
                uint8_t sbd = (uint8_t)(inv_sbox_tbl[dc ^ k] ^ inv_sbox_tbl[df ^ k]);
                F[i][p][k] = (sbd == trail_target[i][p]);
            }
        }
    }

    for (size_t i = 0; i < n_pairs; i++) {
        for (int p = 0; p < 32; p++) {
            uint8_t w = 0;
            for (uint8_t j = 0; j < rk_ks->count[p]; j++) {
                uint8_t k = rk_ks->cand[p][j];
                if (F[i][p][k]) rk_ks->cand[p][w++] = k;
            }
            rk_ks->count[p] = w;
        }
    }
    free(F);
}

/* ================================================================
 * attack_r2 — three-phase filter.
 *
 * Phase 1 targets even positions {0,1,2,3,8,9,10,11,16,17,18,19,
 *                                 24,25,26,27}  and uses the trail
 *   entries at nibble_idx ∈ {0,1,2,3,8,9,10,11}.
 *
 * Phase 2 targets odd positions  {4,5,6,7,12,13,14,15,20,21,22,23,
 *                                 28,29,30,31}  and uses nibble_idx ∈
 *   {20,21,22,23,28,29,30,31}.
 *
 * Phase 3 combines phase 1 × phase 2 survivors and applies a plain
 *   per-nibble filter across all 32 positions (no 0/1 bit-0 splitting).
 * ================================================================ */

static const int EVEN16_POS[16] = {
     0,  1,  2,  3,   8,  9, 10, 11,
    16, 17, 18, 19,  24, 25, 26, 27
};
static const int  ODD16_POS[16] = {
     4,  5,  6,  7,  12, 13, 14, 15,
    20, 21, 22, 23,  28, 29, 30, 31
};

static const int EVEN_NIB_IDX[8] = {0, 1, 2, 3,  8,  9, 10, 11};
static const int  ODD_NIB_IDX[8] = {20, 21, 22, 23, 28, 29, 30, 31};

/* Pack / unpack 16 nibbles (held at specific positions of a state_t)
 * to/from a uint64_t.  Packing order matches the position array. */
static inline uint64_t pack_16(const uint8_t nibs[16])
{
    uint64_t v = 0;
    for (int i = 0; i < 16; i++) v |= (uint64_t)(nibs[i] & 0xF) << (4 * i);
    return v;
}
static inline void unpack_16(uint64_t v, uint8_t nibs[16])
{
    for (int i = 0; i < 16; i++) nibs[i] = (uint8_t)((v >> (4 * i)) & 0xF);
}

/* Place 16 nibbles at given positions in a 32-nibble state_t,
 * zeroing all other positions. */
static inline void scatter_16(state_t dst, const uint8_t nibs[16],
                              const int positions[16])
{
    state_zero(dst);
    for (int i = 0; i < 16; i++) dst[positions[i]] = nibs[i];
}

/* Filter one (nibble_idx, pair, packed-halfkey) combination.  Returns
 * 1 if the key passes the 0/1-split second-to-last filter, 0 otherwise.
 * Used by both the streaming and materialised half-phase paths.         */
static inline int r2_halfphase_key_passes(uint64_t        packed,
                                          const int       positions[16],
                                          int             nibble_idx,
                                          const state_t   c1,
                                          const state_t   c2,
                                          uint8_t         tgt)
{
    uint8_t nibs[16];
    unpack_16(packed, nibs);

    state_t last_key, scnd, scnd_ip;
    scatter_16(last_key, nibs, positions);
    state_perm(last_key);
    state_copy(scnd, last_key);
    state_circ_left_shift(scnd);

    state_copy(scnd_ip, scnd);
    state_inv_perm(scnd_ip);

    state_t scnd_0, scnd_1;
    state_copy(scnd_0, scnd_ip);
    state_copy(scnd_1, scnd_ip);
    scnd_0[nibble_idx] = (uint8_t)((scnd_0[nibble_idx] & 0xE) | 0);
    scnd_1[nibble_idx] = (uint8_t)((scnd_1[nibble_idx] & 0xE) | 1);
    state_perm(scnd_0);
    state_perm(scnd_1);

    /* last round peel */
    state_t dc, df;
    state_copy(dc, c1);  state_copy(df, c2);
    state_rc_add(dc, BAKSHEESH_LAST_RC); state_rc_add(df, BAKSHEESH_LAST_RC);
    state_xor(dc, last_key); state_xor(df, last_key);
    state_inv_perm(dc);  state_inv_perm(df);
    state_inv_sbox(dc);  state_inv_sbox(df);

    /* variant 0 */
    state_t d0c, d0f;
    state_copy(d0c, dc); state_copy(d0f, df);
    state_xor(d0c, scnd_0); state_xor(d0f, scnd_0);
    state_rc_add(d0c, BAKSHEESH_PENULT_RC); state_rc_add(d0f, BAKSHEESH_PENULT_RC);
    state_inv_perm(d0c); state_inv_perm(d0f);
    state_inv_sbox(d0c); state_inv_sbox(d0f);

    /* variant 1 */
    state_t d1c, d1f;
    state_copy(d1c, dc); state_copy(d1f, df);
    state_xor(d1c, scnd_1); state_xor(d1f, scnd_1);
    state_rc_add(d1c, BAKSHEESH_PENULT_RC); state_rc_add(d1f, BAKSHEESH_PENULT_RC);
    state_inv_perm(d1c); state_inv_perm(d1f);
    state_inv_sbox(d1c); state_inv_sbox(d1f);

    uint8_t in_diff_0 = (uint8_t)(d0c[nibble_idx] ^ d0f[nibble_idx]);
    uint8_t in_diff_1 = (uint8_t)(d1c[nibble_idx] ^ d1f[nibble_idx]);
    return (in_diff_0 == tgt) || (in_diff_1 == tgt);
}

/* Build an "active filters" list: pairs of (nibble_idx, pair) where
 * trail_target[pair][nibble_idx] != 0.  Used both by streaming and
 * materialised paths.                                                   */
typedef struct { int nibble_idx; int pair_idx; uint8_t tgt; } active_filter_t;

static size_t collect_active_filters(const state_t *trail_target,
                                     size_t         n_pairs,
                                     const int      nibble_idx_list[8],
                                     active_filter_t *out)
{
    size_t k = 0;
    for (int ni = 0; ni < 8; ni++) {
        int nibble_idx = nibble_idx_list[ni];
        for (size_t p = 0; p < n_pairs; p++) {
            uint8_t tgt = trail_target[p][nibble_idx];
            if (tgt == 0) continue;
            out[k].nibble_idx = nibble_idx;
            out[k].pair_idx   = (int)p;
            out[k].tgt        = tgt;
            k++;
        }
    }
    return k;
}

/* Streaming half-phase: iterates the Cartesian product of the given
 * 16 r1 keyspaces implicitly (ripple-carry counter), runs every active
 * filter on each candidate, and keeps only those that pass them all.
 *
 * This avoids the 2^28-ish peak memory footprint of materialising the
 * full product (which was what killed the 5-round BAKSHEESH attack on
 * one bad-luck r1 distribution).
 *
 * The outer loop splits the product across OpenMP threads by
 * partitioning the top index; each thread walks its slice sequentially.
 * ================================================================== */
static void attack_r2_halfphase_streaming(const state_t        *c1_list,
                                          const state_t        *c2_list,
                                          const state_t        *trail_target,
                                          size_t                n_pairs,
                                          const rk_keyspace_t  *r1,
                                          const int             positions[16],
                                          const int             nibble_idx_list[8],
                                          halfkey_vec_t        *out)
{
    /* Pre-compute the active filter list once.  The 2048-slot buffer
     * is an explicit upper bound; assert so over-large trail sets
     * fail loudly instead of silently corrupting memory. */
    active_filter_t filters[8 * 256];
    if (n_pairs > 256) {
        fprintf(stderr, "attack_r2_core: n_pairs=%zu exceeds hard-coded 256 filter cap\n", n_pairs);
        exit(1);
    }
    size_t n_filters = collect_active_filters(trail_target, n_pairs,
                                              nibble_idx_list, filters);

    /* Product sizes per slot. */
    uint8_t sz[16];
    for (int i = 0; i < 16; i++) sz[i] = r1->count[positions[i]];

    /* Short-circuit the empty-slot case explicitly so it cannot be
     * confused with a product-overflow later. */
    for (int i = 0; i < 16; i++) {
        if (sz[i] == 0) { halfkey_vec_free(out); halfkey_vec_init(out); return; }
    }

    /* (An earlier revision of this function computed a product
     * `n0 * n1 * ... * n15` here with an overflow guard, ostensibly
     * to size per-thread chunks.  That value was never actually
     * consumed — work is partitioned on `sz[15]` directly at line
     * ~515 — so the whole block was dead code.  Removed; the real
     * thread-split logic remains below.) */

    /* Thread-local survivor vectors, merged at the end.
     *
     * KNOWN LIMITATION (false sharing).  Successive `halfkey_vec_t`
     * slots in the array below land on the same cacheline (the
     * struct is 24 B on 64-bit, 64 B cachelines hold ~2.6 slots).
     * In the hot loop each thread writes to `local[tid].count` and
     * `local[tid].keys` on every push; neighbouring threads' writes
     * invalidate each other's cachelines, which costs measurable
     * throughput on high-core boxes.  Correctness is unaffected.
     * We accept this today for code simplicity — a follow-up could
     * replace the `calloc(nthr, ...)` with an array of
     * `halfkey_vec_t *` pointing at separately-malloc'd structs
     * (each on its own cacheline thanks to the allocator's minimum
     * alignment), at the cost of an indirection on every push.
     * See review "m6" in the TCHES 2026 artifact thread. */
    int nthr = 1;
#ifdef _OPENMP
    nthr = omp_get_max_threads();
#endif
    halfkey_vec_t *local = (halfkey_vec_t *)calloc(nthr, sizeof(halfkey_vec_t));
    for (int t = 0; t < nthr; t++) halfkey_vec_init(&local[t]);

#pragma omp parallel
    {
        int tid = 0;
#ifdef _OPENMP
        tid = omp_get_thread_num();
        int nt = omp_get_num_threads();
#else
        int nt = 1;
#endif
        /* Partition the top-most index (position 15 in our array)
         * across threads to split work.  Top slot has sz[15] values;
         * we assign  [tid*sz15/nt .. (tid+1)*sz15/nt)  to this thread. */
        size_t top_sz = sz[15];
        size_t top_from = (top_sz * (size_t)tid) / (size_t)nt;
        size_t top_to   = (top_sz * (size_t)(tid + 1)) / (size_t)nt;

        uint8_t idx[16] = {0};
        uint8_t nibs[16];

        for (size_t top = top_from; top < top_to; top++) {
            idx[15] = (uint8_t)top;
            /* iterate sub-product for indices 0..14 */
            for (int i = 0; i < 15; i++) idx[i] = 0;
            while (1) {
                for (int i = 0; i < 16; i++)
                    nibs[i] = r1->cand[positions[i]][idx[i]];
                uint64_t packed = pack_16(nibs);

                int pass = 1;
                for (size_t fi = 0; fi < n_filters; fi++) {
                    int p = filters[fi].pair_idx;
                    int ni = filters[fi].nibble_idx;
                    uint8_t tg = filters[fi].tgt;
                    if (!r2_halfphase_key_passes(packed, positions, ni,
                                                 c1_list[p], c2_list[p], tg)) {
                        pass = 0;
                        break;
                    }
                }
                if (pass) halfkey_vec_push(&local[tid], packed);

                /* ripple-carry increment over idx[0..14] */
                int i = 0;
                while (i < 15) {
                    if (++idx[i] < sz[i]) break;
                    idx[i] = 0;
                    i++;
                }
                if (i == 15) break;   /* exhausted this  top  slice */
            }
        }
    }

    /* Merge thread-local vectors into  out. */
    size_t total_survivors = 0;
    for (int t = 0; t < nthr; t++) total_survivors += local[t].count;
    halfkey_vec_free(out);
    halfkey_vec_init(out);
    halfkey_vec_reserve(out, total_survivors);
    for (int t = 0; t < nthr; t++) {
        for (size_t i = 0; i < local[t].count; i++)
            halfkey_vec_push(out, local[t].keys[i]);
        halfkey_vec_free(&local[t]);
    }
    free(local);
}

/* Phase 3 — combines phase-1 and phase-2 survivors, filters per-nibble
 * across all 32 positions.  Input keys are stored as (even, odd) pairs
 * in a keyvec_t built on the fly; output is a keyvec_t of 32-nibble
 * last_keys *before* the permutation used by attack_r3/r4/r5.        */
static void attack_r2_phase3(const state_t      *c1_list,
                             const state_t      *c2_list,
                             const state_t      *trail_target,
                             size_t              n_pairs,
                             const halfkey_vec_t *phase1,
                             const halfkey_vec_t *phase2,
                             keyvec_t           *out)
{
    /* Materialise the Cartesian product in place as 32-nibble keys. */
    keyvec_t cur, nxt;
    keyvec_init(&cur);  keyvec_init(&nxt);
    keyvec_reserve(&cur, phase1->count * phase2->count);

    for (size_t a = 0; a < phase1->count; a++) {
        uint8_t even_nibs[16];
        unpack_16(phase1->keys[a], even_nibs);
        for (size_t b = 0; b < phase2->count; b++) {
            uint8_t odd_nibs[16];
            unpack_16(phase2->keys[b], odd_nibs);
            state_t k;
            state_zero(k);
            for (int i = 0; i < 16; i++) k[EVEN16_POS[i]] = even_nibs[i];
            for (int i = 0; i < 16; i++) k[ ODD16_POS[i]] = odd_nibs[i];
            keyvec_push(&cur, k);
        }
    }

    for (int nibble_idx = 0; nibble_idx < 32; nibble_idx++) {
        for (size_t p = 0; p < n_pairs; p++) {
            uint8_t tgt = trail_target[p][nibble_idx];
            if (tgt == 0) continue;

            uint8_t *mark = (uint8_t *)calloc(cur.count, 1);
            if (!mark) { fprintf(stderr, "attack_r2_phase3: OOM\n"); exit(1); }

#pragma omp parallel for schedule(static)
            for (size_t kidx = 0; kidx < cur.count; kidx++) {
                state_t last_key, scnd;
                state_copy(last_key, cur.keys[kidx]);
                state_perm(last_key);             /* forward perm */
                state_copy(scnd, last_key);
                state_circ_left_shift(scnd);

                /* last round peel */
                state_t dc, df;
                state_copy(dc, c1_list[p]);
                state_copy(df, c2_list[p]);
                state_xor(dc, last_key);
                state_xor(df, last_key);
                state_rc_add(dc, BAKSHEESH_LAST_RC);
                state_rc_add(df, BAKSHEESH_LAST_RC);
                state_inv_perm(dc);
                state_inv_perm(df);
                state_inv_sbox(dc);
                state_inv_sbox(df);

                /* second-to-last round peel with the straight scnd key */
                state_xor(dc, scnd);
                state_xor(df, scnd);
                state_rc_add(dc, BAKSHEESH_PENULT_RC);
                state_rc_add(df, BAKSHEESH_PENULT_RC);
                state_inv_perm(dc);
                state_inv_perm(df);
                state_inv_sbox(dc);
                state_inv_sbox(df);

                uint8_t in_diff = (uint8_t)(dc[nibble_idx] ^ df[nibble_idx]);
                mark[kidx] = (in_diff == tgt);
            }

            nxt.count = 0;
            keyvec_reserve(&nxt, cur.count);
            for (size_t kidx = 0; kidx < cur.count; kidx++)
                if (mark[kidx]) keyvec_push(&nxt, cur.keys[kidx]);
            free(mark);
            keyvec_t tmp = cur; cur = nxt; nxt = tmp;
        }
    }

    keyvec_free(out);
    *out = cur;
    keyvec_free(&nxt);
}

void attack_r2(const state_t        *c1_list,
               const state_t        *c2_list,
               const state_t        *trail_target,
               size_t                n_pairs,
               const rk_keyspace_t  *r1_ks,
               keyvec_t             *out)
{
    /* Streaming half-phases — never materialise the 2^28-ish full
     * product; only the survivors are kept.                          */
    halfkey_vec_t phase1, phase2;
    halfkey_vec_init(&phase1);
    halfkey_vec_init(&phase2);

    attack_r2_halfphase_streaming(c1_list, c2_list, trail_target, n_pairs,
                                  r1_ks, EVEN16_POS, EVEN_NIB_IDX, &phase1);

    attack_r2_halfphase_streaming(c1_list, c2_list, trail_target, n_pairs,
                                  r1_ks, ODD16_POS, ODD_NIB_IDX, &phase2);

    attack_r2_phase3(c1_list, c2_list, trail_target, n_pairs,
                     &phase1, &phase2, out);

    halfkey_vec_free(&phase1);
    halfkey_vec_free(&phase2);
}

/* ================================================================
 * attack_r3 / r4 / r5 — per-nibble filter with  R-2 / R-3 / R-4
 * additional rounds of peel.  Each extra round uses the next
 * circ_left_shift of the previous round key.
 * ================================================================ */

/* Generic implementation: given the number of "extra rounds beyond the
 * last and second-to-last" to peel, filter  r_ks  in place. */
static void attack_rN(const state_t *c1_list,
                      const state_t *c2_list,
                      const state_t *trail_target,
                      size_t         n_pairs,
                      int            extra_rounds,   /* 1 for r3, 2 for r4, 3 for r5 */
                      keyvec_t      *r_ks)
{
    keyvec_t cur = *r_ks;
    keyvec_t nxt;
    keyvec_init(&nxt);

    for (int nibble_idx = 0; nibble_idx < 32; nibble_idx++) {
        for (size_t p = 0; p < n_pairs; p++) {
            uint8_t tgt = trail_target[p][nibble_idx];
            if (tgt == 0) continue;

            uint8_t *mark = (uint8_t *)calloc(cur.count, 1);
            if (!mark) { fprintf(stderr, "attack_rN: OOM\n"); exit(1); }

#pragma omp parallel for schedule(static)
            for (size_t kidx = 0; kidx < cur.count; kidx++) {
                state_t last_key;
                state_copy(last_key, cur.keys[kidx]);
                state_perm(last_key);    /* forward perm */

                /* Build the per-round key chain (last, scnd, third, …).
                 * Sized dynamically from extra_rounds so future round
                 * counts (r6+) don't OOB-write; for the shipped r3/r4/r5
                 * drivers extra_rounds ≤ 3, giving a 160 B VLA per
                 * iteration — negligible vs. the surrounding work. */
                state_t kchain[2 + extra_rounds];
                state_copy(kchain[0], last_key);
                for (int r = 1; r <= 1 + extra_rounds; r++) {
                    state_copy(kchain[r], kchain[r - 1]);
                    state_circ_left_shift(kchain[r]);
                }

                /* Last round peel */
                state_t dc, df;
                state_copy(dc, c1_list[p]);
                state_copy(df, c2_list[p]);
                state_xor(dc, kchain[0]);
                state_xor(df, kchain[0]);
                state_rc_add(dc, BAKSHEESH_LAST_RC);
                state_rc_add(df, BAKSHEESH_LAST_RC);
                state_inv_perm(dc);
                state_inv_perm(df);
                state_inv_sbox(dc);
                state_inv_sbox(df);

                /* Second-to-last round peel */
                state_xor(dc, kchain[1]);
                state_xor(df, kchain[1]);
                state_rc_add(dc, BAKSHEESH_PENULT_RC);
                state_rc_add(df, BAKSHEESH_PENULT_RC);
                state_inv_perm(dc);
                state_inv_perm(df);
                state_inv_sbox(dc);
                state_inv_sbox(df);

                /* Extra rounds (third-to-last, fourth-to-last, fifth-to-last).
                 * rc index for the k-th stripped-off round (k >= 3, 1-based
                 * from the last round) is BAKSHEESH_ROUND_COUNT - k; the
                 * first two rounds used BAKSHEESH_LAST_RC and
                 * BAKSHEESH_PENULT_RC above, and here we strip off
                 * rounds 3 .. 3+extra_rounds-1 so the rc index is
                 * (BAKSHEESH_ROUND_COUNT - 3 - r). */
                for (int r = 0; r < extra_rounds; r++) {
                    state_xor(dc, kchain[2 + r]);
                    state_xor(df, kchain[2 + r]);
                    state_rc_add (dc, BAKSHEESH_ROUND_COUNT - 3 - r);
                    state_rc_add (df, BAKSHEESH_ROUND_COUNT - 3 - r);
                    state_inv_perm(dc);
                    state_inv_perm(df);
                    state_inv_sbox(dc);
                    state_inv_sbox(df);
                }

                uint8_t in_diff = (uint8_t)(dc[nibble_idx] ^ df[nibble_idx]);
                mark[kidx] = (in_diff == tgt);
            }

            nxt.count = 0;
            keyvec_reserve(&nxt, cur.count);
            for (size_t kidx = 0; kidx < cur.count; kidx++)
                if (mark[kidx]) keyvec_push(&nxt, cur.keys[kidx]);
            free(mark);
            keyvec_t tmp = cur; cur = nxt; nxt = tmp;
        }
    }

    *r_ks = cur;
    keyvec_free(&nxt);
}

void attack_r3(const state_t *c1_list, const state_t *c2_list,
               const state_t *trail_target, size_t n_pairs, keyvec_t *r_ks)
{ attack_rN(c1_list, c2_list, trail_target, n_pairs, 1, r_ks); }

void attack_r4(const state_t *c1_list, const state_t *c2_list,
               const state_t *trail_target, size_t n_pairs, keyvec_t *r_ks)
{ attack_rN(c1_list, c2_list, trail_target, n_pairs, 2, r_ks); }

void attack_r5(const state_t *c1_list, const state_t *c2_list,
               const state_t *trail_target, size_t n_pairs, keyvec_t *r_ks)
{ attack_rN(c1_list, c2_list, trail_target, n_pairs, 3, r_ks); }
