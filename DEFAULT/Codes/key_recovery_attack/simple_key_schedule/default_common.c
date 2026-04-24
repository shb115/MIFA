/* default_common.c
 *
 * Shared primitives for the DEFAULT key-recovery attack drivers
 * `key_recovery_attack_{6,7,8}r.c` (simple_key_schedule variant).
 *
 * The committed outputs under
 *     github/DEFAULT/Results/key_recovery_attack/simple_key_schedule/
 * are the canonical reference; OpenMP parallelises the large key-
 * filtering loops.
 *
 * ---------------------------------------------------------------------
 * Function naming convention (matches the README's stage table):
 *
 *   attack_r1, attack_r2, attack_r3
 *       Stages 1..3 of the attack — peel one round off the ciphertext
 *       end per stage.
 *
 *   attack_r456_from_r3_product
 *       Stage 4 — legacy name from the initial 6-round driver, where
 *       this function handled "round 4/5/6" collapsed into a single
 *       streaming pass over r3's Cartesian product.  It now represents
 *       the first stage past r3 for any round count.
 *
 *   attack_r456
 *       Stages 5..R — called R - 4 times by the R-round driver, once
 *       per remaining round.  The extra_rounds argument selects which
 *       round is being peeled off.
 *
 * So an R-round driver makes R stage calls, using exactly five distinct
 * functions regardless of R.
 * ---------------------------------------------------------------------
 */

#include "default_common.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#  include <omp.h>
#else
static inline int omp_get_max_threads(void) { return 1; }
static inline int omp_get_thread_num (void) { return 0; }
#endif

/* ================================================================
 * Constants
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

/* ================================================================
 * Pre-computed tables for fast inv_perm
 *
 *  inv_perm is a fixed 128-bit permutation defined as
 *      out[j] = in[default_bit_perm[j]]   for j in 0..127,
 *  equivalently,
 *      bit b of the input lands at bit inv_perm_tbl[b] of the output.
 *
 *  We tabulate, for each input nibble position n (0..31) and each
 *  nibble value v (0..15), the 128-bit pattern of output bits that
 *  this nibble alone contributes.  inv_perm is then 32 XOR-ed
 *  accumulations of two uint64_t words.                              */
static uint64_t perm_lut_lo[32][16];
static uint64_t perm_lut_hi[32][16];

static int g_initialised = 0;

void default_common_init(void)
{
    if (g_initialised) return;

    for (int i = 0; i < 16; i++) inv_sbox_tbl[sbox[i]] = (uint8_t)i;

    for (int i = 0; i < 128; i++) inv_perm_tbl[default_bit_perm[i]] = (uint8_t)i;

    /* Build perm_lut.  For each (n, v) enumerate the 4 bits of v,
     * locate where they land in the output (128-bit packed), and
     * OR them into the (lo, hi) word pair.                         */
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
            perm_lut_lo[n][v] = lo;
            perm_lut_hi[n][v] = hi;
        }
    }

    g_initialised = 1;
}

/* ================================================================
 * State primitives
 * ================================================================ */

void state_copy(state_t dst, const state_t src)
{
    memcpy(dst, src, 32);
}

void state_zero(state_t s)
{
    memset(s, 0, 32);
}

void state_xor(state_t s, const state_t other)
{
    /* The compiler vectorises this trivially under -O3. */
    for (int i = 0; i < 32; i++) s[i] ^= other[i];
}

void state_inv_sbox(state_t s)
{
    for (int i = 0; i < 32; i++) s[i] = inv_sbox_tbl[s[i] & 0xF];
}

void state_inv_perm(state_t s)
{
    uint64_t lo = 0, hi = 0;
    for (int n = 0; n < 32; n++) {
        uint8_t v = s[n] & 0xF;
        lo ^= perm_lut_lo[n][v];
        hi ^= perm_lut_hi[n][v];
    }
    for (int n = 0; n < 16; n++) s[n]      = (uint8_t)((lo >> (4 * n)) & 0xF);
    for (int n = 0; n < 16; n++) s[n + 16] = (uint8_t)((hi >> (4 * n)) & 0xF);
}

void state_rc_add(state_t s, int r)
{
    assert(r >= 0 && r < (int)(sizeof default_rc / sizeof default_rc[0]));
    uint8_t rc = default_rc[r];
    /* rc bits land at bit positions {127, 23, 19, 15, 11, 7, 3} of the
     * 128-bit state: values = [1, c5, c4, c3, c2, c1, c0]; every index
     * is of the form  nibble*4 + 3  (the high bit). */
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

/* ================================================================
 * Packing helpers
 * ================================================================ */

uint16_t pack_r2_entry(const uint8_t nibs[4])
{
    return (uint16_t)( (nibs[0] & 0xF)
                     | ((nibs[1] & 0xF) << 4)
                     | ((nibs[2] & 0xF) << 8)
                     | ((nibs[3] & 0xF) << 12));
}

/* r2_vals[m] is the uint16_t-packed 4-nibble key for r2 group
 * (group_idx_last + 2*m).  The r3 entry packs these 16 nibbles so
 * that retrieval by (m, k0) is
 *     nib = (v >> (4*(4*k0 + m))) & 0xF                              */
uint64_t pack_r3_entry(const uint16_t r2_vals[4])
{
    uint64_t v = 0;
    for (int m = 0; m < 4; m++) {
        for (int k0 = 0; k0 < 4; k0++) {
            uint64_t nib = (r2_vals[m] >> (4 * k0)) & 0xF;
            v |= nib << (4 * (4 * k0 + m));
        }
    }
    return v;
}

void build_last_key_from_r2_entry(state_t last_key, uint16_t r2_entry, int group_idx)
{
    /* Scatter the 4 nibbles at positions  group_idx + 8*j  for
     * j = 0..3.  Only those 4 positions are touched; the caller is
     * responsible for zeroing the rest.                             */
    for (int j = 0; j < 4; j++) {
        last_key[group_idx + 8 * j] = (uint8_t)((r2_entry >> (4 * j)) & 0xF);
    }
}

void build_last_key_from_r3_entry(state_t last_key, uint64_t r3_entry, int group_idx_last)
{
    /* Scatter across the 16 positions  gl + 2*m + 8*k0  for
     *   m  (group_idx_mid) in 0..3
     *   k0 (key_0)         in 0..3
     * The caller zeroes the full state before calling; only 16 of
     * the 32 nibbles are touched here.                              */
    for (int m = 0; m < 4; m++) {
        for (int k0 = 0; k0 < 4; k0++) {
            uint8_t nib = (uint8_t)((r3_entry >> (4 * (4 * k0 + m))) & 0xF);
            last_key[group_idx_last + 2 * m + 8 * k0] = nib;
        }
    }
}

void build_last_key_from_r4_pair(state_t last_key,
                                 uint64_t r3_0_entry,
                                 uint64_t r3_1_entry)
{
    for (int m = 0; m < 4; m++) {
        for (int k0 = 0; k0 < 4; k0++) {
            uint8_t nib0 = (uint8_t)((r3_0_entry >> (4 * (4 * k0 + m))) & 0xF);
            uint8_t nib1 = (uint8_t)((r3_1_entry >> (4 * (4 * k0 + m))) & 0xF);
            last_key[0 + 2 * m + 8 * k0] = nib0;
            last_key[1 + 2 * m + 8 * k0] = nib1;
        }
    }
}

/* ================================================================
 * Keyspace lifecycle
 * ================================================================ */

void r1_keyspace_init_full(r1_keyspace_t *ks)
{
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 16; j++) ks->cand[i][j] = (uint8_t)j;
        ks->count[i] = 16;
    }
}

/* Helper: compute n0*n1*n2*n3 with overflow detection.  Returns 0 on
 * any intermediate overflow and sets *ok to 0; otherwise returns the
 * product and leaves *ok alone. */
static size_t checked_product4(size_t n0, size_t n1, size_t n2, size_t n3, int *ok)
{
    size_t acc = n0;
    size_t factors[3] = { n1, n2, n3 };
    for (int i = 0; i < 3; i++) {
        size_t f = factors[i];
        if (f != 0 && acc > SIZE_MAX / f) { *ok = 0; return 0; }
        acc *= f;
    }
    return acc;
}

void r2_keyspace_init_product(r2_keyspace_t *ks, const r1_keyspace_t *r1)
{
    for (int g = 0; g < 8; g++) {
        size_t n0 = r1->count[g +  0];
        size_t n1 = r1->count[g +  8];
        size_t n2 = r1->count[g + 16];
        size_t n3 = r1->count[g + 24];
        int ok = 1;
        size_t total = checked_product4(n0, n1, n2, n3, &ok);
        if (!ok) {
            fprintf(stderr, "r2_keyspace_init_product: overflow in n0*n1*n2*n3 "
                            "(g=%d, sizes=%zu,%zu,%zu,%zu)\n", g, n0, n1, n2, n3);
            exit(1);
        }

        ks->cand[g]     = (uint16_t *)malloc(total * sizeof(uint16_t));
        ks->capacity[g] = total;
        ks->count[g]    = 0;
        if (total == 0) continue;
        if (!ks->cand[g]) {
            fprintf(stderr, "r2_keyspace_init_product: malloc failed (%zu)\n", total);
            exit(1);
        }

        size_t w = 0;
        for (size_t a = 0; a < n0; a++)
        for (size_t b = 0; b < n1; b++)
        for (size_t c = 0; c < n2; c++)
        for (size_t d = 0; d < n3; d++) {
            uint16_t v = (uint16_t)( r1->cand[g +  0][a]
                                   | (r1->cand[g +  8][b] << 4)
                                   | (r1->cand[g + 16][c] << 8)
                                   | (r1->cand[g + 24][d] << 12));
            ks->cand[g][w++] = v;
        }
        ks->count[g] = w;
    }
}

void r2_keyspace_free(r2_keyspace_t *ks)
{
    for (int g = 0; g < 8; g++) {
        free(ks->cand[g]);
        ks->cand[g] = NULL;
        ks->count[g] = ks->capacity[g] = 0;
    }
}

void r3_keyspace_init_product(r3_keyspace_t *ks, const r2_keyspace_t *r2)
{
    for (int gl = 0; gl < 2; gl++) {
        size_t n0 = r2->count[gl + 0];
        size_t n1 = r2->count[gl + 2];
        size_t n2 = r2->count[gl + 4];
        size_t n3 = r2->count[gl + 6];
        int ok = 1;
        size_t total = checked_product4(n0, n1, n2, n3, &ok);
        if (!ok) {
            fprintf(stderr, "r3_keyspace_init_product: overflow in n0*n1*n2*n3 "
                            "(gl=%d, sizes=%zu,%zu,%zu,%zu)\n", gl, n0, n1, n2, n3);
            exit(1);
        }

        ks->cand[gl]     = (uint64_t *)malloc(total * sizeof(uint64_t));
        ks->capacity[gl] = total;
        ks->count[gl]    = 0;
        if (total == 0) continue;
        if (!ks->cand[gl]) {
            fprintf(stderr, "r3_keyspace_init_product: malloc failed (%zu)\n", total);
            exit(1);
        }

        size_t w = 0;
        for (size_t a = 0; a < n0; a++)
        for (size_t b = 0; b < n1; b++)
        for (size_t c = 0; c < n2; c++)
        for (size_t d = 0; d < n3; d++) {
            uint16_t vals[4] = {
                r2->cand[gl + 0][a],
                r2->cand[gl + 2][b],
                r2->cand[gl + 4][c],
                r2->cand[gl + 6][d]
            };
            ks->cand[gl][w++] = pack_r3_entry(vals);
        }
        ks->count[gl] = w;
    }
}

void r3_keyspace_free(r3_keyspace_t *ks)
{
    for (int gl = 0; gl < 2; gl++) {
        free(ks->cand[gl]);
        ks->cand[gl] = NULL;
        ks->count[gl] = ks->capacity[gl] = 0;
    }
}

void r4_keyspace_init(r4_keyspace_t *ks)
{
    ks->keys = NULL;
    ks->count = 0;
    ks->capacity = 0;
}

void r4_keyspace_reserve(r4_keyspace_t *ks, size_t new_cap)
{
    if (new_cap <= ks->capacity) return;
    state_t *p = (state_t *)realloc(ks->keys, new_cap * sizeof(state_t));
    if (!p) {
        fprintf(stderr, "r4_keyspace_reserve: realloc failed (%zu)\n", new_cap);
        /* _Exit — this function may be called from inside an OpenMP
         * parallel region via r4_keyspace_push; plain exit() inside
         * a parallel region is undefined behaviour in the OpenMP
         * spec (atexit handlers + libgomp cleanup can deadlock). */
        _Exit(1);
    }
    ks->keys = p;
    ks->capacity = new_cap;
}

void r4_keyspace_push(r4_keyspace_t *ks, const state_t key)
{
    if (ks->count >= ks->capacity) {
        size_t nc = ks->capacity ? ks->capacity * 2 : 256;
        r4_keyspace_reserve(ks, nc);
    }
    memcpy(ks->keys[ks->count], key, 32);
    ks->count++;
}

void r4_keyspace_free(r4_keyspace_t *ks)
{
    free(ks->keys);
    ks->keys = NULL;
    ks->count = ks->capacity = 0;
}

/* ================================================================
 * attack_r1
 *
 * CONVENTIONS — common to attack_r1..r{N} in this file and shared
 * with rotating_common.c and baksheesh_common.c:
 *
 *   1. "key" = inv_perm(rk).  The attacks peel one round at a time
 *      as  rc_add → inv_perm → XOR(key) → inv_sbox , which is
 *      mathematically the same as  rc_add → XOR(rk) → inv_perm →
 *      inv_sbox  because the bit-perm is linear and commutes with
 *      XOR.  Factoring it this way lets us filter per nibble after
 *      inv_perm; a side-effect is that the "recovered key" variables
 *      hold inv_perm(rk), NOT rk itself — drivers compare against
 *      state_inv_perm(mk_or_rk) accordingly.
 *
 *   2. last_round (RC index) convention for the REDUCED cipher:
 *         simple schedule:   reduced_encrypt uses rc[0 .. R-1], so
 *                            last_round = R - 1  and the per-round
 *                            state_rc_add calls take  last_round,
 *                            last_round - 1, ...  via a parameter.
 *         rotating schedule: reduced_encrypt uses rc[28-R .. 27], so
 *                            the LAST round always uses rc[27] and
 *                            the per-round rc_add calls are
 *                            hard-coded to 27, 26, ... inside
 *                            rotating_common.c.  The two conventions
 *                            look the same at the "last round uses
 *                            the highest index" level but are NOT
 *                            interchangeable across ciphertexts — do
 *                            not feed a rotating-schedule ciphertext
 *                            to this simple-schedule attack.
 * ================================================================ */

void attack_r1(const uint8_t  target_diff[32],
               const state_t  c1,
               const state_t  c2,
               int            last_round,
               r1_keyspace_t *r1)
{
    state_t dec_c1, dec_c2;
    state_copy(dec_c1, c1);
    state_copy(dec_c2, c2);
    state_rc_add (dec_c1, last_round);
    state_rc_add (dec_c2, last_round);
    state_inv_perm(dec_c1);
    state_inv_perm(dec_c2);

    for (int i = 0; i < 32; i++) {
        uint8_t tmp[16];
        uint8_t w = 0;
        for (uint8_t j = 0; j < r1->count[i]; j++) {
            uint8_t k = r1->cand[i][j];
            uint8_t u1 = dec_c1[i] ^ k;
            uint8_t u2 = dec_c2[i] ^ k;
            uint8_t sbd = (uint8_t)(inv_sbox_tbl[u1] ^ inv_sbox_tbl[u2]);
            if (sbd == target_diff[i]) tmp[w++] = k;
        }
        memcpy(r1->cand[i], tmp, w);
        /* Zero the tail so debug dumps / future scans that ignore
         * count[i] don't see pre-filter leftovers from the previous
         * iteration.  Safe because cand[i] is sized 16 (nibble domain). */
        if (w < 16) memset(r1->cand[i] + w, 0, (size_t)(16 - w));
        r1->count[i] = w;
    }
}

/* ================================================================
 * attack_r2
 *
 * For each of the 8 groups, decrypt 2 rounds with the last_key built
 * from the 4-nibble group key, then filter by checking all 4 nibble
 * positions (4*g .. 4*g+3) in a single decryption pass.
 * ================================================================ */

/* Helper: check one nibble_idx against (dec_cip, dec_fcip, target) */
static inline int r2_nibble_check(const state_t         dec_cip,
                                  const state_t         dec_fcip,
                                  const state_t         last_key,
                                  const r1_keyspace_t  *r1,
                                  int                   nibble_idx,
                                  uint8_t               td)
{
    /* "Known" positions where last_key carries the actual key nibble
     * at this position (the hard-coded set {0, 10, 21, 31}). */
    int use_lk = (nibble_idx == 0 || nibble_idx == 10 ||
                  nibble_idx == 21 || nibble_idx == 31);
    uint8_t dc = dec_cip [nibble_idx];
    uint8_t df = dec_fcip[nibble_idx];

    if (use_lk) {
        uint8_t k = last_key[nibble_idx];
        uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k] ^ inv_sbox_tbl[df ^ k]);
        return (in_diff == td);
    } else {
        for (uint8_t ii = 0; ii < r1->count[nibble_idx]; ii++) {
            uint8_t k = r1->cand[nibble_idx][ii];
            uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k] ^ inv_sbox_tbl[df ^ k]);
            if (in_diff == td) return 1;
        }
        return 0;
    }
}

void attack_r2(const uint8_t        target_diff[32],
               const state_t        cip,
               const state_t        fcip,
               int                  last_round,
               const r1_keyspace_t *r1,
               r2_keyspace_t       *r2)
{
    for (int g = 0; g < 8; g++) {
        size_t n = r2->count[g];
        if (n == 0) continue;

        uint8_t *keep = (uint8_t *)calloc(n, 1);
        if (!keep) { fprintf(stderr, "attack_r2: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(static)
        for (size_t idx = 0; idx < n; idx++) {
            uint16_t key4 = r2->cand[g][idx];
            state_t last_key;
            state_zero(last_key);
            build_last_key_from_r2_entry(last_key, key4, g);

            state_t dec_cip, dec_fcip;
            state_copy(dec_cip,  cip);
            state_copy(dec_fcip, fcip);

            state_rc_add (dec_cip,  last_round);
            state_rc_add (dec_fcip, last_round);
            state_inv_perm(dec_cip);
            state_inv_perm(dec_fcip);
            state_xor(dec_cip,  last_key);
            state_xor(dec_fcip, last_key);

            state_inv_sbox(dec_cip);
            state_inv_sbox(dec_fcip);
            state_rc_add (dec_cip,  last_round - 1);
            state_rc_add (dec_fcip, last_round - 1);
            state_inv_perm(dec_cip);
            state_inv_perm(dec_fcip);

            int all_pass = 1;
            for (int bit = 0; bit < 4; bit++) {
                int nibble_idx = 4 * g + bit;
                if (!r2_nibble_check(dec_cip, dec_fcip, last_key, r1,
                                     nibble_idx, target_diff[nibble_idx])) {
                    all_pass = 0;
                    break;
                }
            }
            keep[idx] = (uint8_t)all_pass;
        }

        /* Serial compress */
        size_t w = 0;
        for (size_t idx = 0; idx < n; idx++) {
            if (keep[idx]) r2->cand[g][w++] = r2->cand[g][idx];
        }
        r2->count[g] = w;
        free(keep);
    }
}

/* ================================================================
 * attack_r3
 *
 * For each group_idx_last in {0,1}, filter r3 keys by 16 nibble
 * positions.  For direct-branch nibbles (at r2 groups {0,2,5,7}) we
 * do a straightforward 3-round peel.  For mid-branch nibbles (at r2
 * groups {1,3,4,6}) we iterate candidate mid-round keys coming from
 * r2_keyspace[nibble_idx/4] when that group has > 16 entries, else
 * we just use its first entry.
 *
 * We collapse the 16 inner (nibble_idx) iterations so that the shared
 * 2-round prefix (peel of the last round + linear part of round-2) is
 * computed only once per r3 key.
 * ================================================================ */

static int is_direct_branch(int nibble_idx)
{
    /* {0..3, 8..11, 20..23, 28..31}  -- matches r2 group in {0,2,5,7} */
    int g = nibble_idx / 4;
    return (g == 0 || g == 2 || g == 5 || g == 7);
}

void attack_r3(const uint8_t        target_diff[32],
               const state_t        cip,
               const state_t        fcip,
               int                  last_round,
               const r1_keyspace_t *r1,
               const r2_keyspace_t *r2,
               r3_keyspace_t       *r3)
{
    static const int nibble_idx_list[2][16] = {
        { 0,  1,  2,  3,  8,  9, 10, 11,  4,  5,  6,  7, 12, 13, 14, 15},
        {20, 21, 22, 23, 28, 29, 30, 31, 16, 17, 18, 19, 24, 25, 26, 27}
    };

    /* Default mid-round key: use the first entry of each r2 group. */
    state_t default_mid_key;
    state_zero(default_mid_key);
    for (int qr = 0; qr < 8; qr++) {
        if (r2->count[qr] == 0) continue;
        uint16_t v = r2->cand[qr][0];
        for (int i = 0; i < 4; i++) {
            default_mid_key[qr + 8 * i] = (uint8_t)((v >> (4 * i)) & 0xF);
        }
    }

    for (int gl = 0; gl < 2; gl++) {
        size_t n = r3->count[gl];
        if (n == 0) continue;

        uint8_t *keep = (uint8_t *)calloc(n, 1);
        if (!keep) { fprintf(stderr, "attack_r3: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(dynamic, 64)
        for (size_t kidx = 0; kidx < n; kidx++) {
            uint64_t r3e = r3->cand[gl][kidx];
            state_t last_key;
            state_zero(last_key);
            build_last_key_from_r3_entry(last_key, r3e, gl);

            /* ----- 2-round shared prefix -----
             * After:
             *   s1 = inv_sbox( inv_perm( rc_add(c, R) ) XOR last_key )
             *   s2 = inv_perm( rc_add(s1, R-1) )
             * which is the common state before either XOR last_key
             * (direct branch) or XOR mid_key (mid branch).          */
            state_t s2_cip, s2_fcip;
            state_copy(s2_cip,  cip);
            state_copy(s2_fcip, fcip);

            state_rc_add (s2_cip,  last_round);
            state_rc_add (s2_fcip, last_round);
            state_inv_perm(s2_cip);
            state_inv_perm(s2_fcip);
            state_xor(s2_cip,  last_key);
            state_xor(s2_fcip, last_key);
            state_inv_sbox(s2_cip);
            state_inv_sbox(s2_fcip);
            state_rc_add (s2_cip,  last_round - 1);
            state_rc_add (s2_fcip, last_round - 1);
            state_inv_perm(s2_cip);
            state_inv_perm(s2_fcip);

            /* Direct-branch tail: XOR last_key, inv_sbox, rc_add(R-2), inv_perm */
            state_t d_cip, d_fcip;
            state_copy(d_cip,  s2_cip);
            state_copy(d_fcip, s2_fcip);
            state_xor(d_cip,  last_key);
            state_xor(d_fcip, last_key);
            state_inv_sbox(d_cip);
            state_inv_sbox(d_fcip);
            state_rc_add (d_cip,  last_round - 2);
            state_rc_add (d_fcip, last_round - 2);
            state_inv_perm(d_cip);
            state_inv_perm(d_fcip);

            int all_pass = 1;

            for (int ni = 0; ni < 16; ni++) {
                int nibble_idx = nibble_idx_list[gl][ni];
                uint8_t td = target_diff[nibble_idx];

                int pass = 0;

                if (is_direct_branch(nibble_idx)) {
                    /* Check position `nibble_idx` in d_cip/d_fcip. */
                    int use_lk =
                        (gl == 0 ? ((nibble_idx & 1) == 0)
                                 : ((nibble_idx & 1) == 1));
                    uint8_t dc = d_cip [nibble_idx];
                    uint8_t df = d_fcip[nibble_idx];

                    if (use_lk) {
                        uint8_t k = last_key[nibble_idx];
                        uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k]
                                                 ^ inv_sbox_tbl[df ^ k]);
                        pass = (in_diff == td);
                    } else {
                        for (uint8_t ii = 0; ii < r1->count[nibble_idx]; ii++) {
                            uint8_t k = r1->cand[nibble_idx][ii];
                            uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k]
                                                     ^ inv_sbox_tbl[df ^ k]);
                            if (in_diff == td) { pass = 1; break; }
                        }
                    }
                } else {
                    /* Mid branch: iterate eq_key candidates. */
                    int qr = nibble_idx / 4;
                    int use_all = (r2->count[qr] > 16);
                    size_t nek = use_all ? r2->count[qr] : (r2->count[qr] ? 1 : 0);

                    int use_lk =
                        (gl == 0 ? ((nibble_idx & 1) == 0)
                                 : ((nibble_idx & 1) == 1));

                    for (size_t eki = 0; eki < nek && !pass; eki++) {
                        uint16_t eq_key = r2->cand[qr][use_all ? eki : 0];

                        /* mid_key = default_mid_key with substitution
                         * at positions (qr + 8*i) for i=0..3.         */
                        state_t mid_key;
                        state_copy(mid_key, default_mid_key);
                        for (int i = 0; i < 4; i++) {
                            mid_key[qr + 8 * i] =
                                (uint8_t)((eq_key >> (4 * i)) & 0xF);
                        }

                        state_t m_cip, m_fcip;
                        state_copy(m_cip,  s2_cip);
                        state_copy(m_fcip, s2_fcip);
                        state_xor(m_cip,  mid_key);
                        state_xor(m_fcip, mid_key);
                        state_inv_sbox(m_cip);
                        state_inv_sbox(m_fcip);
                        state_rc_add (m_cip,  last_round - 2);
                        state_rc_add (m_fcip, last_round - 2);
                        state_inv_perm(m_cip);
                        state_inv_perm(m_fcip);

                        uint8_t dc = m_cip [nibble_idx];
                        uint8_t df = m_fcip[nibble_idx];

                        if (use_lk) {
                            uint8_t k = last_key[nibble_idx];
                            uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k]
                                                     ^ inv_sbox_tbl[df ^ k]);
                            if (in_diff == td) pass = 1;
                        } else {
                            for (uint8_t ii = 0; ii < r1->count[nibble_idx]; ii++) {
                                uint8_t k = r1->cand[nibble_idx][ii];
                                uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dc ^ k]
                                                         ^ inv_sbox_tbl[df ^ k]);
                                if (in_diff == td) { pass = 1; break; }
                            }
                        }
                    }
                }

                if (!pass) { all_pass = 0; break; }
            }

            keep[kidx] = (uint8_t)all_pass;
        }

        size_t w = 0;
        for (size_t kidx = 0; kidx < n; kidx++) {
            if (keep[kidx]) r3->cand[gl][w++] = r3->cand[gl][kidx];
        }
        r3->count[gl] = w;
        free(keep);
    }
}

/* ================================================================
 * r4 filter (shared)
 * ================================================================ */

static inline int r456_filter_pass(const uint8_t  target_diff[32],
                                   const state_t  cip,
                                   const state_t  fcip,
                                   int            last_round,
                                   int            round_depth,
                                   const state_t  key)
{
    state_t dec_cip, dec_fcip;
    state_copy(dec_cip,  cip);
    state_copy(dec_fcip, fcip);

    state_rc_add (dec_cip,  last_round);
    state_rc_add (dec_fcip, last_round);
    state_inv_perm(dec_cip);
    state_inv_perm(dec_fcip);
    state_xor(dec_cip,  key);
    state_xor(dec_fcip, key);

    for (int r = 0; r < round_depth - 2; r++) {
        state_inv_sbox(dec_cip);
        state_inv_sbox(dec_fcip);
        state_rc_add (dec_cip,  last_round - 1 - r);
        state_rc_add (dec_fcip, last_round - 1 - r);
        state_inv_perm(dec_cip);
        state_inv_perm(dec_fcip);
        state_xor(dec_cip,  key);
        state_xor(dec_fcip, key);
    }

    /* Final (round_depth-th from end) layer, no trailing XOR key. */
    state_inv_sbox(dec_cip);
    state_inv_sbox(dec_fcip);
    state_rc_add (dec_cip,  last_round + 1 - round_depth);
    state_rc_add (dec_fcip, last_round + 1 - round_depth);
    state_inv_perm(dec_cip);
    state_inv_perm(dec_fcip);

    /* A key is kept iff every nonzero target_diff nibble matches the
     * observed inv-sbox input-difference at that nibble position.
     * Decrypt the ciphertext pair once and check every nibble in one
     * pass (avoids the redundant per-nibble re-decrypt). */
    for (int n = 0; n < 32; n++) {
        if (target_diff[n] != 0) {
            uint8_t k = key[n];
            uint8_t in_diff = (uint8_t)(inv_sbox_tbl[dec_cip [n] ^ k]
                                     ^ inv_sbox_tbl[dec_fcip[n] ^ k]);
            if (in_diff != target_diff[n]) return 0;
        }
    }
    return 1;
}

void attack_r456_from_r3_product(const uint8_t        target_diff[32],
                                 const state_t        cip,
                                 const state_t        fcip,
                                 int                  last_round,
                                 const r3_keyspace_t *r3,
                                 r4_keyspace_t       *out)
{
    const int    round_depth = 4;
    const size_t n0 = r3->count[0];
    const size_t n1 = r3->count[1];
    if (n0 == 0 || n1 == 0) return;

    int nthreads = omp_get_max_threads();
    r4_keyspace_t *local =
        (r4_keyspace_t *)calloc((size_t)nthreads, sizeof(r4_keyspace_t));
    if (!local) { fprintf(stderr, "r456 initial: calloc failed\n"); exit(1); }
    for (int t = 0; t < nthreads; t++) r4_keyspace_init(&local[t]);

#pragma omp parallel for schedule(dynamic, 8)
    for (size_t i = 0; i < n0; i++) {
        int tid = omp_get_thread_num();
        uint64_t a = r3->cand[0][i];
        for (size_t j = 0; j < n1; j++) {
            uint64_t b = r3->cand[1][j];
            state_t key;
            build_last_key_from_r4_pair(key, a, b);
            if (r456_filter_pass(target_diff, cip, fcip,
                                 last_round, round_depth, key)) {
                r4_keyspace_push(&local[tid], key);
            }
        }
    }

    /* Merge thread-local survivors into `out`. */
    size_t total = out->count;
    for (int t = 0; t < nthreads; t++) total += local[t].count;
    r4_keyspace_reserve(out, total);
    for (int t = 0; t < nthreads; t++) {
        for (size_t k = 0; k < local[t].count; k++) {
            r4_keyspace_push(out, local[t].keys[k]);
        }
        r4_keyspace_free(&local[t]);
    }
    free(local);
}

void attack_r456(const uint8_t  target_diff[32],
                 const state_t  cip,
                 const state_t  fcip,
                 int            last_round,
                 int            round_depth,
                 r4_keyspace_t *r4)
{
    size_t n = r4->count;
    if (n == 0) return;

    uint8_t *keep = (uint8_t *)calloc(n, 1);
    if (!keep) { fprintf(stderr, "attack_r456: calloc failed\n"); exit(1); }

#pragma omp parallel for schedule(dynamic, 1024)
    for (size_t i = 0; i < n; i++) {
        keep[i] = (uint8_t)r456_filter_pass(target_diff, cip, fcip,
                                            last_round, round_depth,
                                            r4->keys[i]);
    }

    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (keep[i]) {
            if (w != i) memcpy(r4->keys[w], r4->keys[i], 32);
            w++;
        }
    }
    r4->count = w;
    free(keep);
}

/* ================================================================
 * mk-in-keyspace checks
 * ================================================================ */

int mk_in_r1(const state_t mk_permed, const r1_keyspace_t *r1)
{
    for (int i = 0; i < 32; i++) {
        int found = 0;
        for (uint8_t j = 0; j < r1->count[i]; j++) {
            if (r1->cand[i][j] == mk_permed[i]) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

int mk_in_r2(const state_t mk_permed, const r2_keyspace_t *r2)
{
    for (int g = 0; g < 8; g++) {
        uint16_t target = (uint16_t)( mk_permed[g + 0]
                                    | (mk_permed[g +  8] << 4)
                                    | (mk_permed[g + 16] << 8)
                                    | (mk_permed[g + 24] << 12));
        int found = 0;
        for (size_t j = 0; j < r2->count[g]; j++) {
            if (r2->cand[g][j] == target) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

int mk_in_r3(const state_t mk_permed, const r3_keyspace_t *r3)
{
    for (int gl = 0; gl < 2; gl++) {
        /* Build the packed r3 entry for the master key. */
        uint16_t r2_vals[4];
        for (int m = 0; m < 4; m++) {
            int g = gl + 2 * m;
            r2_vals[m] = (uint16_t)( mk_permed[g +  0]
                                   | (mk_permed[g +  8] << 4)
                                   | (mk_permed[g + 16] << 8)
                                   | (mk_permed[g + 24] << 12));
        }
        uint64_t target = pack_r3_entry(r2_vals);

        int found = 0;
        for (size_t j = 0; j < r3->count[gl]; j++) {
            if (r3->cand[gl][j] == target) { found = 1; break; }
        }
        if (!found) return 0;
    }
    return 1;
}

int mk_in_r4(const state_t mk_permed, const r4_keyspace_t *r4)
{
    for (size_t i = 0; i < r4->count; i++) {
        if (memcmp(r4->keys[i], mk_permed, 32) == 0) return 1;
    }
    return 0;
}
