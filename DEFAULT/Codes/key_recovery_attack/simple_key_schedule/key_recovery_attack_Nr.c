/* key_recovery_attack_Nr.c — unified DEFAULT simple-key-schedule
 * key-recovery attack driver.
 *
 *   ./default_simple_attack 6     # reads trails_6r.txt (3 pairs) and runs
 *                                 #   attack_r1 .. attack_r456 up to depth 6
 *   ./default_simple_attack 7     # reads trails_7r.txt (2 pairs), up to depth 7
 *   ./default_simple_attack 8     # reads trails_8r.txt (2 pairs), up to depth 8
 *
 * The per-pair (c1, c2, trail) data plus the master key  mk  are read
 * from  trails_<N>r.txt  in the current directory.  Those files are
 * shipped with the artifact; see the README "Paper <-> artifact mapping"
 * table for how they were generated.
 *
 * trails_<N>r.txt format (identical to BAKSHEESH / DEFAULT rotating):
 *     mk = 0x<32 hex>
 *     c1_list = [ 0x<32 hex>, ... ]
 *     c2_list = [ 0x<32 hex>, ... ]
 *     trail_list = [ [ 0x<32 hex>, ... ],  # inner = N+1 entries
 *                    ... ]
 *
 * Conventions on trail indexing (mirrors the 6r/7r/8r inline drivers
 * this file supersedes):
 *     trail[0]   = plaintext diff
 *     trail[R]   = input diff to the last S-box layer (consumed by attack_r1)
 *     trail[N]   = ciphertext diff (= trail[R+1]; stored but not
 *                  referenced by the attack steps — kept for
 *                  validation by `trail_val_check_against_committed.py`)
 * where R = N-1 is the 0-indexed last round.
 */

#include "default_common.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * trails_<N>r.txt parser
 * ================================================================ */

typedef struct {
    int       N;            /* round count == argv; trail has N+1 states */
    size_t    n_pairs;
    uint64_t  mk_lo, mk_hi;
    state_t  *c1;
    state_t  *c2;
    state_t  *trail;        /* flat, n_pairs * (N+1) */
} trails_t;

static void trails_free(trails_t *t)
{
    free(t->c1); free(t->c2); free(t->trail);
    t->c1 = t->c2 = NULL; t->trail = NULL;
}

static int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int parse_hex128(const char *s, uint64_t *lo, uint64_t *hi)
{
    /* Expects s = "0x" + exactly 32 hex digits followed by a non-hex
     * separator.  Reject a 33rd hex digit so a typo'd literal doesn't
     * silently merge with the next one. */
    if (!(s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) return 0;
    s += 2;
    uint64_t h = 0, l = 0;
    for (int i = 0; i < 16; i++) {
        char c = s[i]; int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return 0;
        h = (h << 4) | d;
    }
    for (int i = 0; i < 16; i++) {
        char c = s[16 + i]; int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return 0;
        l = (l << 4) | d;
    }
    if (is_hex_digit(s[32])) return 0;   /* reject over-long literals */
    *lo = l; *hi = h;
    return 1;
}

static int load_trails(const char *path, int N, trails_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { perror("fseek"); fclose(f); return 0; }
    /* Cap at 16 MB — legitimate trails_<N>r.txt files are well under
     * 1 MB; anything larger is almost certainly corrupt and should
     * not be allowed to drive a multi-GB allocation. */
    const size_t MAX_TRAILS_FILE_SZ = 16 * 1024 * 1024;
    if ((size_t)sz > MAX_TRAILS_FILE_SZ) {
        fprintf(stderr, "%s: unreasonable file size %ld bytes (cap %zu)\n",
                path, sz, MAX_TRAILS_FILE_SZ);
        fclose(f);
        return 0;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fprintf(stderr, "trails_parse: malloc failed (%ld bytes)\n", sz + 1); fclose(f); return 0; }
    size_t nread = fread(buf, 1, (size_t)sz, f);
    if (nread != (size_t)sz) {
        fprintf(stderr, "trails_parse: short read on %s (expected %ld bytes, got %zu)\n", path, sz, nread);
        free(buf); fclose(f); return 0;
    }
    buf[sz] = '\0';
    fclose(f);

    enum { NONE, MK, C1, C2, TR } sec = NONE;

    size_t cap1 = 64, n1 = 0; out->c1 = malloc(cap1 * sizeof(state_t));
    size_t cap2 = 64, n2 = 0; out->c2 = malloc(cap2 * sizeof(state_t));
    size_t capT = 64 * (N + 1), nT = 0; out->trail = malloc(capT * sizeof(state_t));
    if (!out->c1 || !out->c2 || !out->trail) {
        fprintf(stderr, "trails_parse: OOM allocating c1/c2/trail buffers\n");
        free(buf); free(out->c1); free(out->c2); free(out->trail); return 0;
    }

    int  depth = 0;
    size_t inner = 0;
    int got_mk = 0;

    char *p = buf;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }

        if (!strncmp(p, "mk", 2) && !isalnum((unsigned char)p[2]) && p[2] != '_') {
            sec = MK;
            p += 2;
            /* Scan to the first '0' on THIS LINE only — do not cross a
             * newline, or we may accidentally eat past the mk=
             * assignment into the next section (c1_list's `[0x...`). */
            while (*p && *p != '0' && *p != '\n') p++;
            if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
                if (!parse_hex128(p, &out->mk_lo, &out->mk_hi)) {
                    fprintf(stderr, "%s: bad hex after mk=\n", path);
                    free(buf);
                    return 0;
                }
                got_mk = 1;
                p += 34;
                sec = NONE;
            }
            continue;
        }
        if (!strncmp(p, "c1_list", 7)) {
            sec = C1; p += 7;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            continue;
        }
        if (!strncmp(p, "c2_list", 7)) {
            sec = C2; p += 7;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            continue;
        }
        if (!strncmp(p, "trail_list", 10)) {
            sec = TR; p += 10;
            while (*p && *p != '[') p++;
            if (*p == '[') p++;
            depth = 1;
            continue;
        }
        if (*p == ']') {
            if (sec == TR) {
                if (depth == 2) {
                    if ((int)inner != N + 1) {
                        fprintf(stderr, "%s: wrong trail length (got %zu, expected %d)\n",
                                path, inner, N + 1);
                        free(buf); return 0;
                    }
                    inner = 0;
                    depth = 1;
                } else {
                    sec = NONE; depth = 0;
                }
            } else sec = NONE;
            p++;
            continue;
        }
        if (*p == '[' && sec == TR) { depth = 2; p++; continue; }
        if (*p == ',') { p++; continue; }

        if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
            uint64_t lo, hi;
            if (!parse_hex128(p, &lo, &hi)) {
                fprintf(stderr, "%s: bad hex near `%.20s`\n", path, p);
                free(buf); return 0;
            }
            p += 34;
            /* Enforce the per-section cap BEFORE each grow, not only
             * once at end-of-parse; a cap check at the end would still
             * allow multi-GB allocations on a 16 MB adversarial file. */
            const size_t PAIRS_CAP = 100000;
            if (sec == C1) {
                if (n1 >= PAIRS_CAP) {
                    fprintf(stderr, "%s: too many c1 entries (>= %zu)\n", path, PAIRS_CAP);
                    free(buf); return 0;
                }
                if (n1 == cap1) {
                    cap1 *= 2;
                    if (cap1 > PAIRS_CAP) cap1 = PAIRS_CAP;
                    state_t *tmp = realloc(out->c1, cap1 * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(c1) failed\n"); free(buf); return 0; }
                    out->c1 = tmp;
                }
                state_from_u128(out->c1[n1++], lo, hi);
            } else if (sec == C2) {
                if (n2 >= PAIRS_CAP) {
                    fprintf(stderr, "%s: too many c2 entries (>= %zu)\n", path, PAIRS_CAP);
                    free(buf); return 0;
                }
                if (n2 == cap2) {
                    cap2 *= 2;
                    if (cap2 > PAIRS_CAP) cap2 = PAIRS_CAP;
                    state_t *tmp = realloc(out->c2, cap2 * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(c2) failed\n"); free(buf); return 0; }
                    out->c2 = tmp;
                }
                state_from_u128(out->c2[n2++], lo, hi);
            } else if (sec == TR && depth == 2) {
                size_t TRAIL_CAP = PAIRS_CAP * (size_t)(N + 1);
                if (nT >= TRAIL_CAP) {
                    fprintf(stderr, "%s: too many trail entries (>= %zu)\n", path, TRAIL_CAP);
                    free(buf); return 0;
                }
                if (nT == capT) {
                    capT *= 2;
                    if (capT > TRAIL_CAP) capT = TRAIL_CAP;
                    state_t *tmp = realloc(out->trail, capT * sizeof(state_t));
                    if (!tmp) { fprintf(stderr, "trails_parse: realloc(trail) failed\n"); free(buf); return 0; }
                    out->trail = tmp;
                }
                state_from_u128(out->trail[nT++], lo, hi);
                inner++;
            }
            continue;
        }
        p++;
    }
    free(buf);

    if (n1 != n2) {
        fprintf(stderr, "%s: c1/c2 count mismatch (%zu vs %zu)\n", path, n1, n2);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    if (nT != n1 * (size_t)(N + 1)) {
        fprintf(stderr, "%s: trail count mismatch (got %zu, expected %zu)\n",
                path, nT, n1 * (N + 1));
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    if (!got_mk) {
        fprintf(stderr, "%s: mk not found\n", path);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    /* Sanity cap — a corrupted file must not let us allocate gigabytes
     * of filter buffers downstream. */
    if (n1 > (size_t)100000) {
        fprintf(stderr, "%s: unreasonable n_pairs = %zu (cap is 100000)\n", path, n1);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }

    out->N = N; out->n_pairs = n1;
    return 1;
}

/* ================================================================
 * Helpers
 * ================================================================ */

/* Slice per-pair trail[which] into the designated state_t buffer. */
static void slice_pair(const trails_t *t, int which, size_t pair_idx, state_t out)
{
    int stride = t->N + 1;
    state_copy(out, t->trail[pair_idx * stride + which]);
}

static double elapsed_seconds(struct timespec t0, struct timespec t1)
{
    return (double)(t1.tv_sec - t0.tv_sec)
         + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* ================================================================
 * Driver
 * ================================================================ */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <6|7|8>\n", argv[0]);
        return 2;
    }
    /* Parse argv strictly — atoi silently accepts "6garbage" as 6. */
    char *endptr = NULL;
    long N_long = strtol(argv[1], &endptr, 10);
    if (endptr == argv[1] || *endptr != '\0' || N_long < 0 || N_long > INT_MAX) {
        fprintf(stderr, "round count must be an integer (got \"%s\")\n", argv[1]);
        return 2;
    }
    int N = (int)N_long;
    if (N < 6 || N > 8) {
        fprintf(stderr, "round count must be 6, 7, or 8 (got %d)\n", N);
        return 2;
    }
    const int R = N - 1;  /* 0-indexed last round */

    default_common_init();

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    printf("### %d-round key-recovery ###\n", N);

    char path[64];
    int _pn = snprintf(path, sizeof(path), "trails_%dr.txt", N);
    if (_pn < 0 || (size_t)_pn >= sizeof(path)) {
        fprintf(stderr, "path construction overflowed for N=%d\n", N);
        return 1;
    }
    trails_t tf = {0};
    if (!load_trails(path, N, &tf)) return 1;
    printf("NUM_PAIRS %zu\n", tf.n_pairs);

    /* Master key — same normalisation the per-round inline drivers did:
     *   state_from_u128(mk_n, mk_lo, mk_hi);  state_inv_perm(mk_n); */
    state_t mk_n;
    state_from_u128(mk_n, tf.mk_lo, tf.mk_hi);
    state_inv_perm(mk_n);

    /* Per-pair sliced target diff scratch buffer. */
    state_t buf;

    /* ------------------------------------------------------------ r1 */
    r1_keyspace_t r1;
    r1_keyspace_init_full(&r1);
    for (size_t i = 0; i < tf.n_pairs; i++) {
        slice_pair(&tf, R, i, buf);
        attack_r1(buf, tf.c1[i], tf.c2[i], R, &r1);
    }
    printf("### r1_keyspace ###\n");
    printf("%s\n", mk_in_r1(mk_n, &r1) ? "mk in r1_keyspace"
                                       : "mk not in r1_keyspace");
    printf("r1_keyspace length:");
    for (int i = 0; i < 32; i++) printf(" %u", (unsigned)r1.count[i]);
    printf("\n");
    fflush(stdout);

    /* ------------------------------------------------------------ r2 */
    r2_keyspace_t r2;
    r2_keyspace_init_product(&r2, &r1);
    for (size_t i = 0; i < tf.n_pairs; i++) {
        slice_pair(&tf, R - 1, i, buf);
        attack_r2(buf, tf.c1[i], tf.c2[i], R, &r1, &r2);
    }
    printf("%s\n", mk_in_r2(mk_n, &r2) ? "mk in r2_keyspace"
                                       : "mk not in r2_keyspace");
    printf("r2_keyspace length:");
    for (int g = 0; g < 8; g++) printf(" %zu", r2.count[g]);
    printf("\n");
    fflush(stdout);

    /* ------------------------------------------------------------ r3 */
    r3_keyspace_t r3;
    r3_keyspace_init_product(&r3, &r2);
    for (size_t i = 0; i < tf.n_pairs; i++) {
        slice_pair(&tf, R - 2, i, buf);
        attack_r3(buf, tf.c1[i], tf.c2[i], R, &r1, &r2, &r3);
    }
    printf("%s\n", mk_in_r3(mk_n, &r3) ? "mk in r3_keyspace"
                                       : "mk not in r3_keyspace");
    printf("r3_keyspace length:");
    for (int gl = 0; gl < 2; gl++) printf(" %zu", r3.count[gl]);
    printf("\n");
    fflush(stdout);

    /* ------------------------------------------------------------ r4
     * (streamed initial filter via pair 0, standard filter for the rest)
     */
    r4_keyspace_t r4;
    r4_keyspace_init(&r4);
    {
        slice_pair(&tf, R - 3, 0, buf);
        attack_r456_from_r3_product(buf, tf.c1[0], tf.c2[0], R, &r3, &r4);
    }
    for (size_t i = 1; i < tf.n_pairs; i++) {
        slice_pair(&tf, R - 3, i, buf);
        attack_r456(buf, tf.c1[i], tf.c2[i], R, 4, &r4);
    }
    printf("%s\n", mk_in_r4(mk_n, &r4) ? "mk in r4_keyspace"
                                       : "mk not in r4_keyspace");
    printf("r4_keyspace length: %zu\n", r4.count);
    fflush(stdout);

    /* ------------------------------------------------------------ r5..rN
     * (generic depth filter; for depth k use trail[R - k + 1]).
     */
    for (int depth = 5; depth <= N; depth++) {
        int trail_idx = R - (depth - 1);    /* = R - depth + 1 */
        for (size_t i = 0; i < tf.n_pairs; i++) {
            slice_pair(&tf, trail_idx, i, buf);
            attack_r456(buf, tf.c1[i], tf.c2[i], R, depth, &r4);
        }
        if (mk_in_r4(mk_n, &r4))
            printf("mk in r%d_keyspace\n", depth);
        else
            printf("mk not in r%d_keyspace\n", depth);
        printf("r%d_keyspace length: %zu\n", depth, r4.count);
        fflush(stdout);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    printf("Time: %.4fs\n", elapsed_seconds(t_start, t_end));

    r4_keyspace_free(&r4);
    r3_keyspace_free(&r3);
    r2_keyspace_free(&r2);
    trails_free(&tf);
    return 0;
}
