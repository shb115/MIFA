#ifndef ROTATING_COMMON_H
#define ROTATING_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* ----------------------------------------------------------------
 * Shared cipher primitives (same sbox / perm / rc as the simple-
 * key-schedule port in ../simple_key_schedule/default_common.h).
 * ---------------------------------------------------------------- */
extern const uint8_t sbox[16];
extern uint8_t       inv_sbox_tbl[16];

extern const uint8_t default_bit_perm[128];
extern uint8_t       inv_perm_tbl[128];

extern const uint8_t default_rc[28];

/* Call once before anything else. */
void rotating_common_init(void);

/* 128-bit state as 32 nibbles (low-4-bits-per-byte). */
typedef uint8_t state_t[32];

void state_copy     (state_t dst, const state_t src);
void state_zero     (state_t s);
void state_xor      (state_t s, const state_t other);
void state_inv_sbox (state_t s);
void state_inv_perm (state_t s);
void state_perm     (state_t s);               /* forward permutation */
void state_rc_add   (state_t s, int r);
void state_from_u128(state_t out, uint64_t lo, uint64_t hi);

/* ----------------------------------------------------------------
 * Per-nibble key-space (each position has up to 16 candidates).
 * Used for rk3, rk2, rk1, rk0 in the rotating attack.
 * ---------------------------------------------------------------- */
typedef struct {
    uint8_t cand [32][16];
    uint8_t count[32];
} rk_keyspace_t;

void rk_keyspace_init_full(rk_keyspace_t *ks);

/* ----------------------------------------------------------------
 * Key-schedule helpers (rotating-specific)
 *
 *   normalize_key_schedule: given the four raw round keys rk0..rk3
 *     (as state_t's), produces their normalised forms nk0..nk3.
 *
 *   make_k3: collapses a per-nibble keyspace into a normalised nk[]
 *     by matching each nibble position's candidate list against the
 *     four linear-structure equivalence classes
 *        class 0 = {0, 5, 10, 15}
 *        class 1 = {1, 4, 11, 14}
 *        class 2 = {2, 7, 8, 13}
 *        class 3 = {3, 6, 9, 12}   (default if no exact match)
 *
 *   make_k0: collapses a 32-nibble state into class ids nibble-wise
 *     (used only on nk0).
 * ---------------------------------------------------------------- */
void normalize_key_schedule(state_t nk[4], const state_t rk[4]);
void make_k3(state_t nk_out, const rk_keyspace_t *ks);
void make_k0(state_t nk_inout);

/* ----------------------------------------------------------------
 * Input arrays for the attack.
 *
 *   pairs[i]:  (c1, c2)         — ciphertext pair
 *   trails[i]: state_t[R+1]     — full differential trail for that pair
 *                                   trail[0] = plaintext diff (0x01)
 *                                   trail[R] = c1 ^ c2
 * ---------------------------------------------------------------- */

/* Stage 1: recover rk3 per-nibble using trail[R-1].
 * On entry `ks` must be freshly initialised with all 16 candidates. */
void attack_r1(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,   /* trail[R-1] of each pair */
               size_t         n_pairs,
               rk_keyspace_t *rk3_ks);

/* Stage 2: uses nk3 to peel one more round, filters rk2 with trail[R-2]. */
void attack_r2(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,   /* trail[R-2] */
               size_t         n_pairs,
               const state_t  nk3,
               rk_keyspace_t *rk2_ks);

/* Stage 3: uses (nk3, nk2), filters rk1 with trail[R-3]. */
void attack_r3(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,   /* trail[R-3] */
               size_t         n_pairs,
               const state_t  nk3,
               const state_t  nk2,
               rk_keyspace_t *rk1_ks);

/* Stage 4: uses (nk3, nk2, nk1), filters rk0 with trail[R-4]. */
void attack_r4(const state_t *c1_list,
               const state_t *c2_list,
               const state_t *trail_target,   /* trail[R-4] */
               size_t         n_pairs,
               const state_t  nk3,
               const state_t  nk2,
               const state_t  nk1,
               rk_keyspace_t *rk0_ks);

/* Equality of two 32-nibble states. */
int  state_eq(const state_t a, const state_t b);

#endif /* ROTATING_COMMON_H */
