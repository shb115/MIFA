#ifndef BAKSHEESH_COMMON_H
#define BAKSHEESH_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * BAKSHEESH primitives — C + OpenMP key-recovery attack.
 *   sbox        : 4-bit BAKSHEESH S-box
 *   bit_perm    : same 128-bit permutation as DEFAULT / GIFT
 *                 (see baksheesh_common.c for citation)
 *   rc_add      : XORs six bits of rc[r] into six specific state bits
 *   circ_left_shift : 1-bit whole-state left rotation (key-schedule step)
 * ================================================================ */

#define BAKSHEESH_ROUND_COUNT    35   /* full BAKSHEESH round count */
#define BAKSHEESH_LAST_RC        (BAKSHEESH_ROUND_COUNT - 1)   /* = 34 */
#define BAKSHEESH_PENULT_RC      (BAKSHEESH_ROUND_COUNT - 2)   /* = 33 */

extern const uint8_t sbox[16];
extern       uint8_t inv_sbox_tbl[16];
extern const uint8_t baksheesh_bit_perm[128];
extern       uint8_t inv_perm_tbl[128];
extern const uint8_t baksheesh_rc[BAKSHEESH_ROUND_COUNT];

void baksheesh_common_init(void);

/* 128-bit state as 32 nibbles (low 4 bits of each byte). */
typedef uint8_t state_t[32];

void state_copy     (state_t dst, const state_t src);
void state_zero     (state_t s);
void state_xor      (state_t s, const state_t other);
void state_inv_sbox (state_t s);
void state_inv_perm (state_t s);
void state_perm     (state_t s);       /* forward permutation */
void state_rc_add   (state_t s, int r);
void state_from_u128(state_t out, uint64_t lo, uint64_t hi);
int  state_eq       (const state_t a, const state_t b);

/* Whole-state circular LEFT shift by 1 bit.  Inverse of the reference
 * cipher's key-schedule right-shift, so `circ_left_shift(rk[r])` gives
 * `rk[r-1]`.                                                          */
void state_circ_left_shift(state_t s);

/* ================================================================
 * Per-nibble candidate lists (output of attack_r1).
 * ================================================================ */
typedef struct {
    uint8_t cand [32][16];
    uint8_t count[32];
} rk_keyspace_t;

void rk_keyspace_init_full(rk_keyspace_t *ks);

/* ================================================================
 * Dynamic vectors of partial / full keys used by attack_r{2..5}.
 *   halfkey_vec_t  — 16-nibble partial keys (even or odd halves of
 *                    attack_r2 phases 1 and 2).  Nibbles packed into
 *                    a uint64_t for memory efficiency.
 *   keyvec_t       — full 32-nibble keys (attack_r2 phase 3 output
 *                    onwards — attack_r3/r4/r5 consume these).
 * ================================================================ */
typedef struct {
    uint64_t *keys;         /* packed 16 nibbles × 4 bits = 64 bits */
    size_t    count;
    size_t    capacity;
} halfkey_vec_t;

typedef struct {
    state_t *keys;
    size_t   count;
    size_t   capacity;
} keyvec_t;

void halfkey_vec_init  (halfkey_vec_t *v);
void halfkey_vec_free  (halfkey_vec_t *v);
void halfkey_vec_push  (halfkey_vec_t *v, uint64_t packed);
void halfkey_vec_reserve(halfkey_vec_t *v, size_t cap);

void keyvec_init  (keyvec_t *v);
void keyvec_free  (keyvec_t *v);
void keyvec_push  (keyvec_t *v, const state_t key);
void keyvec_reserve(keyvec_t *v, size_t cap);

/* ================================================================
 * Attack stages.
 *
 * Trail indexing convention: for an R-round attack, trail_list has
 * R+1 entries, indexed 0..R, and stage  attack_r{k}  uses  trail[R-k].
 * ================================================================ */

/* Stage 1 — per-nibble filter at the first-peel layer.  Produces
 * rk_ks->cand[i][*] of size rk_ks->count[i] for each nibble i. */
void attack_r1(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,   /* trail[R-1] per pair */
               size_t         n_pairs,
               rk_keyspace_t *rk_ks);

/* Stage 2 — three-phase product-space filter producing a set of 32-
 * nibble keys (before permutation).  Each survivor `key` in `out`
 * corresponds to one full last_key candidate (before the forward
 * permutation that attack_r{3..5} apply internally).                  */
void attack_r2(const state_t        *c1_list,
               const state_t        *c2_list,
               const state_t        *trail_target,   /* trail[R-2] per pair */
               size_t                n_pairs,
               const rk_keyspace_t  *r1_ks,
               keyvec_t             *out);

/* Stage 3 — peel 3 rounds using circ_left_shift key chain; filter the
 * survivors of stage 2 per nibble, with  trail[R-3]  as the target. */
void attack_r3(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               keyvec_t      *r_ks);

/* Stage 4 — peel 4 rounds, filter with  trail[R-4]. */
void attack_r4(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               keyvec_t      *r_ks);

/* Stage 5 — peel 5 rounds, filter with  trail[R-5]  (5r-attack only). */
void attack_r5(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,
               size_t         n_pairs,
               keyvec_t      *r_ks);

#endif /* BAKSHEESH_COMMON_H */
