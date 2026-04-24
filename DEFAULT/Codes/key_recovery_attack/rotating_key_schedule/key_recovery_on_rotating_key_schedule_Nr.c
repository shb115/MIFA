/* key_recovery_on_rotating_key_schedule_Nr.c
 *
 * Unified C+OpenMP driver for the rotating-key-schedule key-recovery
 * attack on DEFAULT at round counts N ∈ {6, 7, 8}.
 *
 * Usage:  ./key_recovery_on_rotating_key_schedule <6|7|8>
 *
 * The round-count argument selects which trails/pairs file to load
 * (trails_6r.txt / trails_7r.txt / trails_8r.txt next to this binary)
 * and which trail index to feed into each of the four attack stages
 * (stage k uses trail[N-k] for k = 1..4).
 *
 * The same master key (rk0..rk3 below) is reused across all three
 * round counts; the `gen_trails.py` tool that produces the committed
 * `trails_Nr.txt` files reads the same constants from its own copy
 * of the table.
 */

#include "rotating_common.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * Hard-coded master-key materialisation.
 *
 * CROSS-CIPHER MK-PLACEMENT CONVENTIONS IN THIS REPO:
 *   - DEFAULT rotating (this file): rk0..rk3 hard-coded in C below.
 *   - DEFAULT simple              : mk + all trails inline in each
 *                                   per-round driver
 *                                   (key_recovery_attack_{6,7,8}r.c).
 *   - BAKSHEESH                   : mk = 0x... recorded in each
 *                                   trails_{4,5}r.txt file; driver
 *                                   reads it via parse_hex128().
 * The three conventions are intentionally different — each driver
 * uses the simplest form for its shipped data — and a unified
 * "trails_file-carries-mk" refactor is out of scope for this release.
 * ================================================================ */
/* rk0 = 0x829B94B6F9B89B943986B2CB7DD8315F
 * rk1 = 0xD3D64E9A76439AC72349CC01CB887E05
 * rk2 = 0x0E8E1C09CB3B5798152F60FA09D9F45C
 * rk3 = 0x296FB8A0645D19574FFC52C937BA5EB9                        */
static void load_master_key(state_t rk[4])
{
    state_from_u128(rk[0], 0x3986B2CB7DD8315FULL, 0x829B94B6F9B89B94ULL);
    state_from_u128(rk[1], 0x2349CC01CB887E05ULL, 0xD3D64E9A76439AC7ULL);
    state_from_u128(rk[2], 0x152F60FA09D9F45CULL, 0x0E8E1C09CB3B5798ULL);
    state_from_u128(rk[3], 0x4FFC52C937BA5EB9ULL, 0x296FB8A0645D1957ULL);
}

/* ================================================================
 * Minimal parser for the trails_<N>r.txt file format:
 *
 *     # optional comment lines
 *     c1_list = [
 *         0x<32 hex>,
 *         ...
 *     ]
 *
 *     c2_list = [
 *         0x<32 hex>,
 *         ...
 *     ]
 *
 *     trail_list = [
 *         [
 *             0x<32 hex>,                   # R+1 entries per inner list
 *             ...
 *         ],
 *         ...
 *     ]
 *
 * Whitespace and blank lines are ignored.  No validation of inner-list
 * length is done here; the caller is expected to pass R and the parser
 * verifies each trail has R+1 entries.
 * ================================================================ */

static int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int parse_hex128(const char *s, uint64_t *lo, uint64_t *hi)
{
    /* expects s = "0x" + exactly 32 hex digits, followed by a
     * separator (',', ']', whitespace, '\0', or '#').  Reject a
     * 33rd hex digit so a typo'd literal doesn't silently merge
     * with the next one. */
    if (!(s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) return 0;
    s += 2;
    uint64_t h = 0, l = 0;
    int i;
    for (i = 0; i < 16; i++) {
        char c = s[i]; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return 0;
        h = (h << 4) | d;
    }
    for (i = 0; i < 16; i++) {
        char c = s[16 + i]; int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return 0;
        l = (l << 4) | d;
    }
    /* Reject over-long literals. */
    if (is_hex_digit(s[32])) return 0;
    *lo = l; *hi = h;
    return 1;
}

typedef struct {
    size_t    n_pairs;
    int       R;            /* trail length = R + 1 */
    state_t  *c1;
    state_t  *c2;
    state_t  *trail;        /* flat array, n_pairs * (R+1) */
} trails_file_t;

static void trails_free(trails_file_t *tf)
{
    free(tf->c1); free(tf->c2); free(tf->trail);
    tf->c1 = tf->c2 = NULL; tf->trail = NULL;
}

static int load_trails_file(const char *path, int expect_R, trails_file_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    /* read whole file */
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { perror("fseek"); fclose(f); return 0; }
    /* Cap at 16 MB — legitimate trails_Nr.txt files are well under
     * 1 MB; anything larger is almost certainly a corrupt / swapped
     * file, and we should not let the parser allocate gigabytes. */
    const size_t MAX_TRAILS_FILE_SZ = 16 * 1024 * 1024;
    if ((size_t)sz > MAX_TRAILS_FILE_SZ) {
        fprintf(stderr, "%s: unreasonable file size %ld bytes (cap %zu)\n",
                path, sz, MAX_TRAILS_FILE_SZ);
        fclose(f);
        return 0;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        fprintf(stderr, "trails_parse: short read on %s (expected %ld, got %zu)\n", path, sz, got);
        free(buf); return 0;
    }
    buf[got] = '\0';

    /* Three sections: c1_list, c2_list, trail_list.
     * Scan linearly, collecting 0x... tokens within the current list.
     * A '[' inside trail_list starts a new inner list; ']' ends it. */
    enum { SEC_NONE, SEC_C1, SEC_C2, SEC_TRAIL } sec = SEC_NONE;

    size_t cap_c1 = 128, n_c1 = 0;
    size_t cap_c2 = 128, n_c2 = 0;
    out->c1 = (state_t *)malloc(cap_c1 * sizeof(state_t));
    out->c2 = (state_t *)malloc(cap_c2 * sizeof(state_t));

    size_t cap_tr = 128 * (expect_R + 1), n_tr = 0;
    out->trail = (state_t *)malloc(cap_tr * sizeof(state_t));
    if (!out->c1 || !out->c2 || !out->trail) {
        fprintf(stderr, "trails_parse: OOM allocating c1/c2/trail buffers\n");
        free(buf); free(out->c1); free(out->c2); free(out->trail); return 0;
    }

    int trail_depth = 0;            /* [[ ... ]] nesting for trail_list */
    size_t current_inner_count = 0;

    char *p = buf;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }

        /* look for section headers: c1_list, c2_list, trail_list */
        if (!strncmp(p, "c1_list", 7)) {
            sec = SEC_C1;
            p += 7;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            continue;
        }
        if (!strncmp(p, "c2_list", 7)) {
            sec = SEC_C2;
            p += 7;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            continue;
        }
        if (!strncmp(p, "trail_list", 10)) {
            sec = SEC_TRAIL;
            p += 10;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            trail_depth = 1;
            continue;
        }

        if (*p == ']') {
            if (sec == SEC_TRAIL) {
                if (trail_depth == 2) {
                    /* end of one inner trail — verify length */
                    if ((int)current_inner_count != expect_R + 1) {
                        fprintf(stderr, "%s: expected %d entries per trail, got %zu\n",
                                path, expect_R + 1, current_inner_count);
                        free(buf);
                        return 0;
                    }
                    current_inner_count = 0;
                    trail_depth = 1;
                } else {
                    sec = SEC_NONE;
                    trail_depth = 0;
                }
            } else {
                sec = SEC_NONE;
            }
            p++;
            continue;
        }

        if (*p == '[' && sec == SEC_TRAIL) {
            trail_depth = 2;
            p++;
            continue;
        }

        if (*p == ',') { p++; continue; }

        if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
            uint64_t lo, hi;
            if (!parse_hex128(p, &lo, &hi)) {
                fprintf(stderr, "%s: bad hex literal near `%.20s`\n", path, p);
                free(buf);
                return 0;
            }
            p += 34;   /* "0x" + 32 hex digits */

            /* Enforce the per-section cap during growth, BEFORE every
             * realloc that would push capacity past 100 000 entries.
             * A cap check only at end-of-parse would still allocate
             * gigabytes on an adversarial file inside the 16 MB limit. */
            const size_t PAIRS_CAP = 100000;
            if (sec == SEC_C1) {
                if (n_c1 >= PAIRS_CAP) {
                    fprintf(stderr, "%s: too many c1 entries (>= %zu)\n", path, PAIRS_CAP);
                    free(buf); return 0;
                }
                if (n_c1 == cap_c1) {
                    cap_c1 *= 2;
                    if (cap_c1 > PAIRS_CAP) cap_c1 = PAIRS_CAP;
                    state_t *tmp = (state_t *)realloc(out->c1, cap_c1 * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(c1) failed\n"); free(buf); return 0; }
                    out->c1 = tmp;
                }
                state_from_u128(out->c1[n_c1++], lo, hi);
            } else if (sec == SEC_C2) {
                if (n_c2 >= PAIRS_CAP) {
                    fprintf(stderr, "%s: too many c2 entries (>= %zu)\n", path, PAIRS_CAP);
                    free(buf); return 0;
                }
                if (n_c2 == cap_c2) {
                    cap_c2 *= 2;
                    if (cap_c2 > PAIRS_CAP) cap_c2 = PAIRS_CAP;
                    state_t *tmp = (state_t *)realloc(out->c2, cap_c2 * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(c2) failed\n"); free(buf); return 0; }
                    out->c2 = tmp;
                }
                state_from_u128(out->c2[n_c2++], lo, hi);
            } else if (sec == SEC_TRAIL && trail_depth == 2) {
                /* trail_list has (R+1) entries per pair, so cap_trail
                 * caps PAIRS_CAP * (R+1). */
                size_t TRAIL_CAP = PAIRS_CAP * (size_t)(expect_R + 1);
                if (n_tr >= TRAIL_CAP) {
                    fprintf(stderr, "%s: too many trail entries (>= %zu)\n", path, TRAIL_CAP);
                    free(buf); return 0;
                }
                if (n_tr == cap_tr) {
                    cap_tr *= 2;
                    if (cap_tr > TRAIL_CAP) cap_tr = TRAIL_CAP;
                    state_t *tmp = (state_t *)realloc(out->trail, cap_tr * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(trail) failed\n"); free(buf); return 0; }
                    out->trail = tmp;
                }
                state_from_u128(out->trail[n_tr++], lo, hi);
                current_inner_count++;
            } else {
                fprintf(stderr, "%s: hex literal outside any list\n", path);
                free(buf);
                return 0;
            }
            continue;
        }

        /* unknown char — skip */
        p++;
    }
    free(buf);

    if (n_c1 != n_c2) {
        fprintf(stderr, "%s: c1_list (%zu) vs c2_list (%zu) mismatch\n",
                path, n_c1, n_c2);
        trails_free(out);
        return 0;
    }
    if (n_tr != n_c1 * (size_t)(expect_R + 1)) {
        fprintf(stderr, "%s: trail_list has %zu entries, expected %zu\n",
                path, n_tr, n_c1 * (expect_R + 1));
        trails_free(out);
        return 0;
    }

    /* Sanity cap — a corrupted / adversarial trails file must not let
     * the attack allocate gigabytes of filter buffers downstream. */
    if (n_c1 > (size_t)100000) {
        fprintf(stderr, "%s: unreasonable n_pairs = %zu (cap is 100000)\n",
                path, n_c1);
        trails_free(out);
        return 0;
    }

    out->n_pairs = n_c1;
    out->R = expect_R;
    return 1;
}

/* ================================================================
 * Driver
 * ================================================================ */

static void print_keyspace_len(const rk_keyspace_t *ks)
{
    /* No trailing space before '\n' — editors that auto-strip
     * trailing whitespace on save would otherwise quietly corrupt
     * a diff of reproduce_output/ vs committed Results/. */
    for (int i = 0; i < 32; i++) {
        if (i > 0) putchar(' ');
        printf("%u", (unsigned)ks->count[i]);
    }
    putchar('\n');
}

/* Pick out the per-pair trail at index `which` (0 <= which <= R).
 * Produces a state_t[n_pairs] array that attack_r{k} can consume. */
static void slice_trail_at(const trails_file_t *tf, int which, state_t *out)
{
    int stride = tf->R + 1;
    for (size_t i = 0; i < tf->n_pairs; i++) {
        state_copy(out[i], tf->trail[i * stride + which]);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <6|7|8>\n", argv[0]);
        return 2;
    }
    /* Parse argv strictly — atoi silently accepts "6garbage" as 6. */
    char *_endptr = NULL;
    long _R_long = strtol(argv[1], &_endptr, 10);
    if (_endptr == argv[1] || *_endptr != '\0' || _R_long < 0 || _R_long > INT_MAX) {
        fprintf(stderr, "round count must be an integer (got \"%s\")\n", argv[1]);
        return 2;
    }
    int R = (int)_R_long;
    if (R < 6 || R > 8) {
        fprintf(stderr, "round count must be 6, 7, or 8\n");
        return 2;
    }

    rotating_common_init();

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    printf("### %d-round key-recovery ###\n", R);

    /* ---- load trails/pairs file ---- */
    char path[256];
    int _pn = snprintf(path, sizeof(path), "trails_%dr.txt", R);
    if (_pn < 0 || (size_t)_pn >= sizeof(path)) {
        fprintf(stderr, "path construction overflowed for R=%d\n", R);
        return 1;
    }
    trails_file_t tf = {0};
    if (!load_trails_file(path, R, &tf)) return 1;
    printf("NUM_PAIRS %zu\n", tf.n_pairs);

    /* ---- compute nk[4] from rk[4] ---- */
    state_t rk[4], nk[4];
    load_master_key(rk);
    normalize_key_schedule(nk, rk);
    make_k0(nk[0]);
    for (int i = 0; i < 4; i++) state_inv_perm(nk[i]);

    /* ---- attack_r1 ---- */
    state_t *tgt = (state_t *)malloc(tf.n_pairs * sizeof(state_t));

    rk_keyspace_t rk3_ks = {0};
    slice_trail_at(&tf, R - 1, tgt);
    attack_r1(tf.c1, tf.c2, tgt, tf.n_pairs, &rk3_ks);

    state_t nk3;
    make_k3(nk3, &rk3_ks);

    printf("### rk3_keyspace_1 ###\n");
    /* Under the rotating key schedule the success metric is the
     * normalised-key equality nk == nk[i] below — the rk_i raw-key
     * membership check is not meaningful here because equivalence
     * classes merge raw candidates, so we only print keyspace sizes
     * and the nk equality result. */
    printf("rk3_keyspace_1 length: ");
    print_keyspace_len(&rk3_ks);
    printf("nk3 == nk[3] : %s\n", state_eq(nk3, nk[3]) ? "True" : "False");

    /* ---- attack_r2 ---- */
    rk_keyspace_t rk2_ks = {0};
    slice_trail_at(&tf, R - 2, tgt);
    attack_r2(tf.c1, tf.c2, tgt, tf.n_pairs, nk3, &rk2_ks);

    state_t nk2;
    make_k3(nk2, &rk2_ks);

    printf("### rk2_keyspace_1 ###\n");
    printf("rk2_keyspace_1 length: ");
    print_keyspace_len(&rk2_ks);
    printf("nk2 == nk[2] : %s\n", state_eq(nk2, nk[2]) ? "True" : "False");

    /* ---- attack_r3 ---- */
    rk_keyspace_t rk1_ks = {0};
    slice_trail_at(&tf, R - 3, tgt);
    attack_r3(tf.c1, tf.c2, tgt, tf.n_pairs, nk3, nk2, &rk1_ks);

    state_t nk1;
    make_k3(nk1, &rk1_ks);

    printf("### rk1_keyspace ###\n");
    printf("rk1_keyspace length: ");
    print_keyspace_len(&rk1_ks);
    printf("nk1 == nk[1] : %s\n", state_eq(nk1, nk[1]) ? "True" : "False");

    /* ---- attack_r4 ---- */
    rk_keyspace_t rk0_ks = {0};
    slice_trail_at(&tf, R - 4, tgt);
    attack_r4(tf.c1, tf.c2, tgt, tf.n_pairs, nk3, nk2, nk1, &rk0_ks);

    printf("### rk0_keyspace ###\n");
    printf("rk0_keyspace length: ");
    print_keyspace_len(&rk0_ks);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) +
                     (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("Time: %.4fs\n", elapsed);

    free(tgt);
    trails_free(&tf);
    return 0;
}
