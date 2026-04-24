/* key_recovery_Nr.c — unified BAKSHEESH key-recovery attack driver.
 *
 *   ./baksheesh_attack 4     # reads trails_4r.txt (30 pairs) and runs
 *                            #   attack_r1 .. attack_r4
 *   ./baksheesh_attack 5     # reads trails_5r.txt (10 pairs) and runs
 *                            #   attack_r1 .. attack_r5
 *
 * The per-pair (c1, c2, trail) data plus the master key  mk  are read
 * from  trails_<N>r.txt  in the current directory.  Those files are
 * shipped with the artifact; see the README "Paper ↔ artifact mapping"
 * table for how they were generated.
 */

#include "baksheesh_common.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================
 * trails_Nr.txt parser
 * ================================================================ */

typedef struct {
    int       R;
    size_t    n_pairs;
    uint64_t  mk_lo, mk_hi;
    state_t  *c1;
    state_t  *c2;
    state_t  *trail;   /* flat, n_pairs * (R+1) */
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
    /* Expects s = "0x" + exactly 32 hex digits followed by a
     * non-hex separator.  Reject a 33rd hex digit so a typo'd
     * literal doesn't silently merge with the next one. */
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
    if (is_hex_digit(s[32])) return 0;       /* reject over-long literals */
    *lo = l; *hi = h;
    return 1;
}

static int load_trails(const char *path, int R, trails_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { perror("fseek"); fclose(f); return 0; }
    /* Cap at 16 MB — legitimate trails_Nr.txt files are well under
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
    size_t capT = 64 * (R + 1), nT = 0; out->trail = malloc(capT * sizeof(state_t));
    if (!out->c1 || !out->c2 || !out->trail) {
        fprintf(stderr, "trails_parse: OOM allocating c1/c2/trail buffers\n");
        free(buf); free(out->c1); free(out->c2); free(out->trail); return 0;
    }

    int  depth = 0;
    size_t inner = 0;
    int got_mk = 0;

    char *p = buf;
    /*
     * Note on mk placement (cross-cipher): the BAKSHEESH attack ships
     * the master key as `mk = 0x...` inside the trails_{4,5}r.txt
     * file so the attack is fully driven by a single input file.
     * DEFAULT rotating hard-codes the mk in C; DEFAULT simple embeds
     * mk+trails inline per round-count.  See
     * `DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/
     *  key_recovery_on_rotating_key_schedule_Nr.c` for the rationale.
     */
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
                    if ((int)inner != R + 1) {
                        fprintf(stderr, "%s: wrong trail length\n", path);
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
                size_t TRAIL_CAP = PAIRS_CAP * (size_t)(R + 1);
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
        fprintf(stderr, "%s: c1/c2 count mismatch\n", path);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    if (nT != n1 * (size_t)(R + 1)) {
        fprintf(stderr, "%s: trail count mismatch\n", path);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    if (!got_mk) {
        fprintf(stderr, "%s: mk not found\n", path);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }
    /* Sanity cap — a corrupted file must not let us allocate
     * gigabytes of filter buffers downstream. */
    if (n1 > (size_t)100000) {
        fprintf(stderr, "%s: unreasonable n_pairs = %zu (cap is 100000)\n", path, n1);
        free(out->c1); free(out->c2); free(out->trail); return 0;
    }

    out->R = R; out->n_pairs = n1;
    return 1;
}

/* ================================================================
 * mk_nibbles = inv_perm(to_nibbles(mk rotated right by 35 bits))
 * ================================================================ */

static void compute_mk_nibbles(state_t out, uint64_t mk_lo, uint64_t mk_hi)
{
    /* right-rotate mk (128-bit) by 35 bits.  The branch below also
     * handles sh >= 64, but BOTH branches contain a (64 - sh) shift
     * that would be UB for sh == 0 or sh == 64 — assert the sh=35
     * hard-coding here so a future parameterisation cannot silently
     * introduce that UB. */
    int sh = 35;
    assert(sh > 0 && sh < 64);
    uint64_t rot_lo, rot_hi;
    if (sh < 64) {
        rot_lo = (mk_lo >> sh) | (mk_hi << (64 - sh));
        rot_hi = (mk_hi >> sh) | (mk_lo << (64 - sh));
    } else {
        int s2 = sh - 64;
        rot_lo = (mk_hi >> s2) | (mk_lo << (64 - s2));
        rot_hi = (mk_lo >> s2) | (mk_hi << (64 - s2));
    }
    state_from_u128(out, rot_lo, rot_hi);
    state_inv_perm(out);
}

/* ================================================================
 * Output helpers
 * ================================================================ */

static void print_keyspace_len(const rk_keyspace_t *ks)
{
    /* No trailing space before '\n' — avoids editor auto-strip
     * false diffs against the committed reference. */
    for (int i = 0; i < 32; i++) {
        if (i > 0) putchar(' ');
        printf("%u", (unsigned)ks->count[i]);
    }
    putchar('\n');
}

static int mk_in_r1_keyspace(const state_t mk_n, const rk_keyspace_t *ks)
{
    for (int i = 0; i < 32; i++) {
        uint8_t need = mk_n[i] & 0xF;
        int found = 0;
        for (uint8_t j = 0; j < ks->count[i]; j++)
            if (ks->cand[i][j] == need) { found = 1; break; }
        if (!found) return 0;
    }
    return 1;
}

static int mk_in_keyvec(const state_t mk_n, const keyvec_t *v)
{
    for (size_t i = 0; i < v->count; i++)
        if (state_eq(v->keys[i], mk_n)) return 1;
    return 0;
}

/* Slice per-pair trail[which] into a flat state_t[n_pairs] array. */
static void slice_trail_at(const trails_t *t, int which, state_t *out)
{
    int stride = t->R + 1;
    for (size_t i = 0; i < t->n_pairs; i++)
        state_copy(out[i], t->trail[i * stride + which]);
}

/* ================================================================
 * Driver
 * ================================================================ */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <4|5>\n", argv[0]);
        return 2;
    }
    /* Parse argv strictly — atoi silently accepts "4garbage" as 4. */
    char *endptr = NULL;
    long R_long = strtol(argv[1], &endptr, 10);
    if (endptr == argv[1] || *endptr != '\0' || R_long < 0 || R_long > INT_MAX) {
        fprintf(stderr, "round count must be an integer (got \"%s\")\n", argv[1]);
        return 2;
    }
    int R = (int)R_long;
    if (R != 4 && R != 5) {
        fprintf(stderr, "round count must be 4 or 5 (got %d)\n", R);
        return 2;
    }

    baksheesh_common_init();

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    char path[64];
    int _pn = snprintf(path, sizeof(path), "trails_%dr.txt", R);
    if (_pn < 0 || (size_t)_pn >= sizeof(path)) {
        fprintf(stderr, "path construction overflowed for R=%d\n", R);
        return 1;
    }
    trails_t tf = {0};
    if (!load_trails(path, R, &tf)) return 1;

    /* Print round-count header FIRST, then NUM_PAIRS, matching the
     * DEFAULT rotating driver's output ordering so cross-cipher diff
     * shapes line up. */
    printf("### %d-round key-recovery ###\n", R);
    printf("NUM_PAIRS %zu\n", tf.n_pairs);

    /* mk_nibbles = inv_perm(to_nibbles(right_rotate(mk, 35))) */
    state_t mk_n;
    compute_mk_nibbles(mk_n, tf.mk_lo, tf.mk_hi);

    state_t *tgt = (state_t *)malloc(tf.n_pairs * sizeof(state_t));

    /* -------------------- attack_r1 -------------------- */
    rk_keyspace_t r1_ks;
    slice_trail_at(&tf, R - 1, tgt);
    attack_r1(tf.c1, tf.c2, tgt, tf.n_pairs, &r1_ks);

    printf("### r1_keyspace ###\n");
    printf("%s\n", mk_in_r1_keyspace(mk_n, &r1_ks) ? "mk in r1_keyspace"
                                                   : "mk not in r1_keyspace");
    printf("r1_keyspace length: ");
    print_keyspace_len(&r1_ks);

    /* -------------------- attack_r2 -------------------- */
    keyvec_t r2_ks;
    keyvec_init(&r2_ks);
    slice_trail_at(&tf, R - 2, tgt);
    attack_r2(tf.c1, tf.c2, tgt, tf.n_pairs, &r1_ks, &r2_ks);

    printf("%s\n", mk_in_keyvec(mk_n, &r2_ks) ? "mk in r2_keyspace"
                                              : "mk not in r2_keyspace");
    printf("r2_keyspace length: %zu\n", r2_ks.count);

    /* -------------------- attack_r3 -------------------- */
    slice_trail_at(&tf, R - 3, tgt);
    attack_r3(tf.c1, tf.c2, tgt, tf.n_pairs, &r2_ks);
    printf("%s\n", mk_in_keyvec(mk_n, &r2_ks) ? "mk in r3_keyspace"
                                              : "mk not in r3_keyspace");
    printf("r3_keyspace length: %zu\n", r2_ks.count);

    /* -------------------- attack_r4 -------------------- */
    slice_trail_at(&tf, R - 4, tgt);
    attack_r4(tf.c1, tf.c2, tgt, tf.n_pairs, &r2_ks);
    printf("%s\n", mk_in_keyvec(mk_n, &r2_ks) ? "mk in r4_keyspace"
                                              : "mk not in r4_keyspace");
    printf("r4_keyspace length: %zu\n", r2_ks.count);

    /* -------------------- attack_r5 (only for 5r) -------------------- */
    if (R == 5) {
        slice_trail_at(&tf, R - 5, tgt);
        attack_r5(tf.c1, tf.c2, tgt, tf.n_pairs, &r2_ks);
        printf("%s\n", mk_in_keyvec(mk_n, &r2_ks) ? "mk in r5_keyspace"
                                                  : "mk not in r5_keyspace");
        printf("r5_keyspace length: %zu\n", r2_ks.count);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    printf("Time: %.4fs\n", elapsed);

    free(tgt);
    keyvec_free(&r2_ks);
    trails_free(&tf);
    return 0;
}
