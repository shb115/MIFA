#ifndef DEFAULT_COMMON_H
#define DEFAULT_COMMON_H

#include <stdint.h>
#include <stddef.h>

/* ----------------------------------------------------------------
 * Constants (defined in default_common.c)
 * ---------------------------------------------------------------- */
extern const uint8_t sbox[16];
extern uint8_t inv_sbox_tbl[16];

extern const uint8_t default_bit_perm[128];
extern uint8_t inv_perm_tbl[128];

extern const uint8_t default_rc[28];

/* Call exactly once before using any primitive. */
void default_common_init(void);

/* ----------------------------------------------------------------
 * State: 128-bit block as 32 nibbles, each held in the low 4 bits
 *        of a uint8_t (a "list of 32 ints" model).
 * ---------------------------------------------------------------- */
typedef uint8_t state_t[32];

void state_copy(state_t dst, const state_t src);
void state_xor(state_t s, const state_t other);
void state_zero(state_t s);

void state_inv_sbox(state_t s);
void state_inv_perm(state_t s);
void state_rc_add(state_t s, int r);

/* Build a 32-nibble state from two 64-bit halves of a 128-bit
 * integer value (nibble 0 = low 4 bits of `lo`). */
void state_from_u128(state_t out, uint64_t lo, uint64_t hi);

/* ----------------------------------------------------------------
 * Key spaces
 * ---------------------------------------------------------------- */

/* r1: 32 nibble positions, each with up to 16 candidates. */
typedef struct {
    uint8_t cand[32][16];
    uint8_t count[32];
} r1_keyspace_t;

/* r2: 8 groups, each holds a list of 4-nibble tuples packed into a
 *     uint16_t.  Nibble key4[j] is stored at bit offset 4*j so that
 *     key4[j] = (v >> (4*j)) & 0xF, and the scatter
 *         last_key[group + 8*j] = key4[j]
 *     then reconstructs a 32-nibble last-round-key partial. */
typedef struct {
    uint16_t *cand[8];
    size_t    count[8];
    size_t    capacity[8];
} r2_keyspace_t;

/* r3: 2 groups (group_idx_last = 0 / 1), each holds a list of
 *     16-nibble (half-key) tuples packed into a uint64_t.          */
typedef struct {
    uint64_t *cand[2];
    size_t    count[2];
    size_t    capacity[2];
} r3_keyspace_t;

/* r4: list of 32-nibble full last-round keys. */
typedef struct {
    state_t *keys;
    size_t   count;
    size_t   capacity;
} r4_keyspace_t;

/* ----------------------------------------------------------------
 * Keyspace lifecycle
 * ---------------------------------------------------------------- */
void r1_keyspace_init_full (r1_keyspace_t *ks);

void r2_keyspace_init_product(r2_keyspace_t *ks, const r1_keyspace_t *r1);
void r2_keyspace_free       (r2_keyspace_t *ks);

void r3_keyspace_init_product(r3_keyspace_t *ks, const r2_keyspace_t *r2);
void r3_keyspace_free       (r3_keyspace_t *ks);

void r4_keyspace_init  (r4_keyspace_t *ks);
void r4_keyspace_reserve(r4_keyspace_t *ks, size_t new_cap);
void r4_keyspace_push  (r4_keyspace_t *ks, const state_t key);
void r4_keyspace_free  (r4_keyspace_t *ks);

/* ----------------------------------------------------------------
 * Helpers to expand packed keys into a full 32-nibble last_key
 * ---------------------------------------------------------------- */
/* r2 element at group g goes to positions (g + 8*j) for j = 0..3. */
void build_last_key_from_r2_entry(state_t last_key, uint16_t r2_entry, int group_idx);

/* r3 element at group gl goes to positions (gl + 2*m + 8*k0)
 * for m,k0 = 0..3.                                              */
void build_last_key_from_r3_entry(state_t last_key, uint64_t r3_entry, int group_idx_last);

/* Combine one r3[0] element and one r3[1] element into a full key. */
void build_last_key_from_r4_pair(state_t last_key,
                                 uint64_t r3_0_entry,
                                 uint64_t r3_1_entry);

/* Pack/unpack helpers used by tests and by mk_in_* checks. */
uint16_t pack_r2_entry(const uint8_t nibs[4]);
uint64_t pack_r3_entry(const uint16_t r2_vals[4]);

/* ----------------------------------------------------------------
 * Attack steps (parameterized by `last_round`, the 0-indexed
 * round whose output is the ciphertext we observe).
 * ---------------------------------------------------------------- */
void attack_r1(const uint8_t  target_diff[32],
               const state_t  c1,
               const state_t  c2,
               int            last_round,
               r1_keyspace_t *r1);

void attack_r2(const uint8_t        target_diff[32],
               const state_t        cip,
               const state_t        fcip,
               int                  last_round,
               const r1_keyspace_t *r1,
               r2_keyspace_t       *r2);

void attack_r3(const uint8_t        target_diff[32],
               const state_t        cip,
               const state_t        fcip,
               int                  last_round,
               const r1_keyspace_t *r1,
               const r2_keyspace_t *r2,
               r3_keyspace_t       *r3);

/* First R4 filter: streams through the Cartesian product r3[0] x r3[1]
 * (so we never materialise the ~|r3[0]|*|r3[1]| list) and keeps only
 * survivors.  `out` must be initialised; survivors are appended.     */
void attack_r456_from_r3_product(const uint8_t        target_diff[32],
                                 const state_t        cip,
                                 const state_t        fcip,
                                 int                  last_round,
                                 const r3_keyspace_t *r3,
                                 r4_keyspace_t       *out);

/* Generic R4/R5/R6/R7/R8 filter acting on an existing r4 keyspace. */
void attack_r456(const uint8_t  target_diff[32],
                 const state_t  cip,
                 const state_t  fcip,
                 int            last_round,
                 int            round_depth,
                 r4_keyspace_t *r4);

/* ----------------------------------------------------------------
 * "mk in keyspace?" helpers (mk is expected to be already inv_perm'd
 * — see the per-attack-stage header in default_common.c for the
 * "key = inv_perm(rk)" convention).
 * ---------------------------------------------------------------- */
int mk_in_r1(const state_t mk_permed, const r1_keyspace_t *r1);
int mk_in_r2(const state_t mk_permed, const r2_keyspace_t *r2);
int mk_in_r3(const state_t mk_permed, const r3_keyspace_t *r3);
int mk_in_r4(const state_t mk_permed, const r4_keyspace_t *r4);

#endif /* DEFAULT_COMMON_H */
