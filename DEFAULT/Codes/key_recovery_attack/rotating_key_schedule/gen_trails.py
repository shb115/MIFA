"""
gen_trails.py — rotating-key-schedule attack data generator (parallel).

For a target round count R (6, 7, or 8) and a fixed master-key materialised
as rk0..rk3 (same values as hard-coded in
`key_recovery_on_rotating_key_schedule_Nr.c`):

  1. pick many random 128-bit plaintexts  p1  (p2 = p1 XOR INPUT_DIFF)
  2. encrypt both through R rounds of the reduced-round Layer cipher
     (rc indices [28-R .. 27], rotating key schedule  rk[r % 4])
  3. invoke Gurobi MILP to search for differential trails consistent with
     (INPUT_DIFF, c1 XOR c2) over R rounds; `PoolSolutions=2` short-circuits
     the many-trails case
  4. keep only single-trail tuples, emit them as Python-literal blocks
     compatible with the C driver's trails_{6,7,8}r.txt loader.

Parallelism: `--workers N` spawns N independent processes, each with its
own Gurobi Env and its own RNG stream.  Per-worker `--threads-per-worker`
controls intra-MILP parallelism (total CPU load ≈ N × threads-per-worker).

Run with any Python ≥ 3.9 (required by gurobipy 12.0) that has
`gurobipy==12.0.3` installed:
    python3 gen_trails.py --round 7 --want 80 --workers 10
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import random
import sys
import time
from typing import List, Optional, Tuple

import gurobipy as gp
from gurobipy import GRB

# --------------------------------------------------------------------------
# Cipher primitives (mirrors key_recovery_on_rotating_key_schedule_Nr.c)
# --------------------------------------------------------------------------

SBOX = [0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9,
        0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5]

BIT_PERM = [
     0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
     4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
     8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
    12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
    16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
    20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
    24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
    28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
]

DEFAULT_RC = [
    1, 3, 7, 15, 31, 62, 61, 59, 55, 47, 30, 60, 57, 51,
    39, 14, 29, 58, 53, 43, 22, 44, 24, 48, 33, 2, 5, 11
]

# Fixed master-key materialisation — matches rk0..rk3 of the rotating-6r
# Python driver.  We ship rk[] directly; the cipher code below uses rk[r % 4].
RK_HEX = [
    0x829B94B6F9B89B943986B2CB7DD8315F,
    0xD3D64E9A76439AC72349CC01CB887E05,
    0x0E8E1C09CB3B5798152F60FA09D9F45C,
    0x296FB8A0645D19574FFC52C937BA5EB9,
]


def to_nibbles(val: int) -> List[int]:
    return [(val >> (4 * i)) & 0xF for i in range(32)]


def from_nibbles(nibs: List[int]) -> int:
    v = 0
    for i, n in enumerate(nibs):
        v |= (n & 0xF) << (4 * i)
    return v


def sbox_state(s: List[int]) -> List[int]:
    return [SBOX[x & 0xF] for x in s]


def perm(msg: List[int]) -> List[int]:
    bits = [0] * 128
    for n in range(32):
        for b in range(4):
            bits[4 * n + b] = (msg[n] >> b) & 1
    pbits = [0] * 128
    for i in range(128):
        pbits[BIT_PERM[i]] = bits[i]
    out = [0] * 32
    for n in range(32):
        for b in range(4):
            out[n] |= pbits[4 * n + b] << b
    return out


def rc_add(s: List[int], r: int) -> List[int]:
    rc = DEFAULT_RC[r]
    bit_indices = [127, 23, 19, 15, 11, 7, 3]
    values = [1, (rc >> 5) & 1, (rc >> 4) & 1, (rc >> 3) & 1,
              (rc >> 2) & 1, (rc >> 1) & 1, rc & 1]
    out = list(s)
    for bi, v in zip(bit_indices, values):
        out[bi // 4] ^= (v << (bi % 4))
    return out


def key_add(s: List[int], k: List[int]) -> List[int]:
    return [a ^ b for a, b in zip(s, k)]


def encrypt_layer_reduced(p: List[int],
                          rk: List[List[int]],
                          R: int) -> List[int]:
    s = list(p)
    for r in range(28 - R, 28):
        s = sbox_state(s)
        s = perm(s)
        s = rc_add(s, r)
        s = key_add(s, rk[r % 4])
    return s


# --------------------------------------------------------------------------
# Gurobi MILP: "is there exactly one feasible trail, and what is it?"
# --------------------------------------------------------------------------

def count_trails_and_get(INPUT_DIFF: int,
                         OUTPUT_DIFF: int,
                         R: int,
                         env: gp.Env,
                         threads: int) -> Tuple[int, List[int]]:
    m = gp.Model("default_diff", env=env)
    m.setParam(GRB.Param.OutputFlag, 0)
    m.setParam(GRB.Param.Threads, threads)

    X = [[m.addVar(0, 1, 0, vtype=GRB.BINARY, name=f"X_{i}_{r}")
          for i in range(128)] for r in range(R + 1)]
    Y = [[m.addVar(0, 1, 0, vtype=GRB.BINARY, name=f"Y_{i}_{r}")
          for i in range(128)] for r in range(R)]

    for idx in range(128):
        m.addConstr(X[0][idx] == ((INPUT_DIFF >> idx) & 1))
        m.addConstr(X[R][idx] == ((OUTPUT_DIFF >> idx) & 1))

    for r in range(R):
        for sbox_idx in range(32):
            a = [X[r][4 * sbox_idx + k] for k in range(4)]
            b = [Y[r][4 * sbox_idx + k] for k in range(4)]
            m.addConstr( a[1] - a[0] - b[2] + b[1] - b[0] >= -2)
            m.addConstr( a[0] + b[3] + b[2] - b[1] >= 0)
            m.addConstr(-a[3] - a[2] - a[1] - a[0] - b[1] >= -4)
            m.addConstr( a[3] - a[2] - a[1] + b[3] + b[1] >= -1)
            m.addConstr( a[3] + a[2] - b[3] + b[2] - b[1] >= -1)
            m.addConstr( a[3] + a[2] + a[1] - b[2] >= 0)
            m.addConstr( a[3] + a[2] - a[1] + b[2] >= 0)
            m.addConstr( a[3] + b[3] + b[1] - b[0] >= 0)
            m.addConstr( a[3] - a[0] + b[2] + b[0] >= 0)
            m.addConstr(-a[0] - b[3] - b[2] + b[1] >= -2)
            m.addConstr( a[0] - b[3] + b[2] + b[1] >= 0)
            m.addConstr(-a[3] + a[2] - a[1] - b[2] >= -2)
            m.addConstr(-a[3] + a[2] + a[1] + b[2] >= 0)
            m.addConstr(-a[3] + b[3] + b[1] + b[0] >= 0)
            m.addConstr(-a[2] + a[1] - a[0] - b[0] >= -2)
            m.addConstr(-a[3] - b[3] - b[1] + b[0] >= -2)
            m.addConstr(-a[3] + a[0] - b[2] - b[0] >= -2)
            m.addConstr(-a[2] - a[1] + a[0] - b[0] >= -2)
            m.addConstr(-a[0] + b[3] - b[2] - b[1] >= -2)
            m.addConstr(-a[2] + a[1] + a[0] + b[0] >= 0)
            m.addConstr( a[3] + a[0] - b[2] + b[0] >= 0)
            m.addConstr( a[3] - b[3] - b[1] - b[0] >= -2)
            m.addConstr(-a[3] - a[0] + b[2] - b[0] >= -2)
            m.addConstr(-a[2] - a[1] - a[0] + b[0] >= -2)
        for idx in range(128):
            m.addConstr(Y[r][idx] == X[r + 1][BIT_PERM[idx]])

    m.setParam(GRB.Param.PoolSearchMode, 2)
    m.setParam(GRB.Param.PoolSolutions, 2)   # short-circuit when ≥ 2
    m.optimize()

    if m.Status not in (GRB.OPTIMAL, GRB.INTERRUPTED, GRB.SUBOPTIMAL):
        return 0, []

    n_sol = m.SolCount
    if n_sol == 0:
        return 0, []

    m.setParam(GRB.Param.SolutionNumber, 0)
    trail = []
    for r in range(R + 1):
        bits = [int(X[r][i].Xn > 0.5) for i in range(128)]
        val = 0
        for i, b in enumerate(bits):
            val |= b << i
        trail.append(val)
    return n_sol, trail


# --------------------------------------------------------------------------
# Worker process
# --------------------------------------------------------------------------

_WORKER_ENV: Optional[gp.Env] = None


def _worker_init(worker_idx: int):
    # Each worker creates its own Gurobi Env, with suppressed output.
    global _WORKER_ENV
    _WORKER_ENV = gp.Env(empty=True)
    _WORKER_ENV.setParam(GRB.Param.OutputFlag, 0)
    _WORKER_ENV.setParam(GRB.Param.LogToConsole, 0)
    _WORKER_ENV.start()


def _worker_task(job):
    """One plaintext-pair + MILP trial.

    `input_diff_pattern` is a small base value (e.g. 0x1 or 0x2) describing
    a single-bit flip in one nibble.  With `rotate_nibble = True` the
    effective input difference is  pattern << (4 * (seed mod 32))
    — i.e. the same bit-pattern is rotated through all 32 nibble
    positions across different trials.  This gives the filter uniform
    coverage of every key nibble, which a fixed fault position cannot.  """
    input_diff_pattern, rotate_nibble, R, threads, seed = job
    rnd = random.Random(seed)

    # The fault-pattern API assumes a 4-bit (single-nibble) pattern so
    # that shifting by 4*nib stays within 128 bits for every nib in
    # 0..31.  A wider pattern (e.g. 0x21 — two active nibbles) would
    # silently lose its top bits under the 128-bit mask for large nib;
    # reject that up front rather than silently produce a different
    # effective pattern than the user asked for.  Also reject the
    # all-zero pattern: with INPUT_DIFF == 0, p1 == p2 and every
    # MILP solve reduces to the trivial all-zero trail, which is
    # a technically-valid single solution but cryptanalytically
    # meaningless.
    if input_diff_pattern == 0:
        raise ValueError(
            "--input-diff 0x0 is degenerate (no fault); "
            "pass 0x1, 0x2, 0x4, or 0x8 instead."
        )
    if input_diff_pattern & ~0xF:
        raise ValueError(
            f"--input-diff 0x{input_diff_pattern:x} is wider than one nibble; "
            f"this script's --rotate-nibble assumes a 4-bit pattern."
        )

    if rotate_nibble:
        nib = rnd.randrange(32)
        INPUT_DIFF = (input_diff_pattern << (4 * nib)) & ((1 << 128) - 1)
    else:
        INPUT_DIFF = input_diff_pattern

    p1 = rnd.getrandbits(128)
    p2 = p1 ^ INPUT_DIFF
    rk = [to_nibbles(v) for v in RK_HEX]
    c1n = encrypt_layer_reduced(to_nibbles(p1), rk, R)
    c2n = encrypt_layer_reduced(to_nibbles(p2), rk, R)
    c1 = from_nibbles(c1n)
    c2 = from_nibbles(c2n)
    dout = c1 ^ c2
    t0 = time.time()
    n, trail = count_trails_and_get(INPUT_DIFF, dout, R,
                                    _WORKER_ENV, threads)
    dt = time.time() - t0
    return (seed, c1, c2, n, trail, dt)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def fmt_hex128(val: int) -> str:
    return f"0x{val:032X}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True, choices=(6, 7, 8))
    ap.add_argument("--want", type=int, default=80)
    ap.add_argument("--input-diff", type=lambda s: int(s, 0), default=0x01,
                    help="bit pattern of the single-bit fault (e.g. 0x1 or "
                         "0x2).  With --rotate-nibble, this pattern is "
                         "rotated through all 32 nibble positions; "
                         "otherwise the pattern is applied at nibble 0.")
    ap.add_argument("--rotate-nibble", action="store_true",
                    help="per trial, place the fault at a random nibble "
                         "position chosen uniformly over 0..31.  Matches the "
                         "paper's fault-diversity assumption — without it, "
                         "all faults land at nibble 0 and many key "
                         "positions get no filtering.")
    ap.add_argument("--seed", type=int, default=42,
                    help="RNG seed for the per-worker random stream "
                         "(default: 42).  Each committed trails_Nr.txt "
                         "file records the exact --seed used to produce "
                         "it in its header; inspect the file to see which "
                         "seed to pass for byte-level reproduction.")
    ap.add_argument("--workers", type=int, default=1,
                    help="number of parallel worker processes")
    ap.add_argument("--threads-per-worker", type=int, default=2,
                    help="Gurobi threads per MILP (CPU load = workers * this)")
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--max-trials", type=int, default=10000)
    args = ap.parse_args()

    R = args.round
    INPUT_DIFF = args.input_diff

    sys.stderr.write(f"[gen_trails] R={R}  INPUT_DIFF=0x{INPUT_DIFF:x}  "
                     f"want={args.want}  workers={args.workers}  "
                     f"threads-per-worker={args.threads_per_worker}\n")

    # Jobs are just (INPUT_DIFF, R, threads, seed); seed differentiates
    # plaintext pairs across workers.  We collect (seed, c1, c2, trail)
    # tuples so we can sort-by-seed at the end (see imap below).
    collected: List[Tuple[int, int, int, List[int]]] = []
    t_start = time.time()
    submitted = 0
    next_seed = args.seed

    with mp.Pool(processes=args.workers, initializer=_worker_init,
                 initargs=(0,)) as pool:
        # stream jobs via imap_unordered so we can stop as soon as we have
        # enough single-trail tuples
        def jobs_iter():
            nonlocal submitted, next_seed
            while submitted < args.max_trials:
                job = (INPUT_DIFF, args.rotate_nibble, R,
                       args.threads_per_worker, next_seed)
                next_seed += 1
                submitted += 1
                yield job

        # Use ordered imap (not imap_unordered) + post-hoc sort by seed
        # so that the emitted file is a deterministic function of
        # (--seed, --workers, --want, --round).  imap_unordered would
        # yield results in worker-completion order, which depends on
        # scheduling jitter and breaks byte-level reproducibility.
        for seed, c1, c2, n, trail, dt in pool.imap(
                _worker_task, jobs_iter(), chunksize=1):
            elapsed = time.time() - t_start
            sys.stderr.write(
                f"  [seed={seed}] c1^c2=0x{(c1^c2):032X}  #trails={n}  "
                f"milp_t={dt:.1f}s  collected={len(collected)}  "
                f"wall={elapsed:.1f}s\n")
            if n == 1:
                collected.append((seed, c1, c2, trail))
                if len(collected) >= args.want:
                    pool.terminate()
                    break

    # Sort by seed so two runs with identical args emit the same file
    # regardless of worker count / completion order.
    collected.sort(key=lambda t: t[0])
    # Drop the seed tag before downstream use (keeps the file format).
    collected = [(c1, c2, trail) for (_seed, c1, c2, trail) in collected]

    out_stream = open(args.out, "w") if args.out else sys.stdout
    pattern_desc = (f"pattern=0x{INPUT_DIFF:x}  " +
                    ("rotated across all 32 nibbles"
                     if args.rotate_nibble else "fixed at nibble 0"))
    rotate_flag = " --rotate-nibble" if args.rotate_nibble else ""
    out_stream.write(
        f"# Generated by gen_trails.py for R={R}, {pattern_desc}, "
        f"N={len(collected)}.\n"
        f"# To reproduce, run:\n"
        f"#   python3 gen_trails.py --round {R} "
        f"--input-diff 0x{INPUT_DIFF:x}{rotate_flag} "
        f"--want {args.want} --seed {args.seed} --out {args.out or '<name>'}\n"
        f"# Each trail's trail[0] is the effective INPUT_DIFF for that pair.\n\n"
    )
    out_stream.write("c1_list = [\n")
    for c1, _, _ in collected:
        out_stream.write(f"    {fmt_hex128(c1)},\n")
    out_stream.write("]\n\nc2_list = [\n")
    for _, c2, _ in collected:
        out_stream.write(f"    {fmt_hex128(c2)},\n")
    out_stream.write("]\n\ntrail_list = [\n")
    for _, _, trail in collected:
        out_stream.write("[\n")
        for v in trail:
            out_stream.write(f"    {fmt_hex128(v)},\n")
        out_stream.write("],\n")
    out_stream.write("]\n")
    if args.out:
        out_stream.close()
    sys.stderr.write(f"[gen_trails] done — {len(collected)} tuples "
                     f"in {time.time() - t_start:.1f}s\n")


if __name__ == "__main__":
    main()
