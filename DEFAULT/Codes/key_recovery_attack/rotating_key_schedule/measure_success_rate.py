#!/usr/bin/env python3
"""measure_success_rate.py — empirically measure the Sec. 4.4 success
probability for the DEFAULT rotating-schedule key-recovery attack at
round R ∈ {6, 7, 8}.

For each of --trials distinct seeds, this script:
  1. invokes gen_trails.py to build a fresh trails_<R>r.txt in a
     per-trial tempdir, with the paper's (input_diff, want) pair for
     that round;
  2. runs ./rotating_attack <R> in that tempdir (so the binary picks
     up its trails file by its relative-path convention);
  3. parses the three `nk{3,2,1} == nk[{3,2,1}] : True|False` lines
     and counts the trial as a success iff all three are True.

At the end, it reports the success-rate fraction together with a
Wilson 95% confidence interval so a reviewer can check whether the
paper's "> 95 % at nt = 25 / 11 / 9" claim is empirically supported
at the reviewer's machine's seed sample.

NOTE: gen_trails.py requires Gurobi — this script is Gurobi-dependent.
      The paper's > 95 % claim is not otherwise measured by the
      non-Gurobi reproduce.sh path; use the committed trails_Nr.txt
      files (single-seed runs) for that path.
"""

import argparse
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NK_LINE_RE = re.compile(r'^\s*nk([123])\s*==\s*nk\[[123]\]\s*:\s*(True|False)\s*$')

# Paper Sec. 4.4 settings (and the committed trails_*r.txt headers):
#   6r → input_diff 0x2, nt = 25
#   7r → input_diff 0x2, nt = 11
#   8r → input_diff 0x1, nt =  9
DEFAULTS_BY_ROUND = {
    6: {'want': 25, 'input_diff': '0x2'},
    7: {'want': 11, 'input_diff': '0x2'},
    8: {'want':  9, 'input_diff': '0x1'},
}


def run_cmd(argv, cwd, env=None):
    """Run `argv`; return (returncode, stdout, stderr)."""
    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True,
                          text=True, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def parse_nk_outcomes(stdout):
    """Return list of bools, one per `nk_i == nk[i] : ...` line."""
    outcomes = []
    for line in stdout.splitlines():
        m = NK_LINE_RE.match(line)
        if m:
            outcomes.append(m.group(2) == 'True')
    return outcomes


def wilson_ci(k, n, z=1.96):
    """Wilson 95% confidence interval for a binomial proportion k/n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def run_trial(*, seed, round_num, want, input_diff, workers, threads_per_worker,
              gen_trails, binary, env, keep_tmp):
    """Run one (gen_trails, rotating_attack) trial.  Return a dict."""
    tmp_ctx = tempfile.mkdtemp(prefix=f'mifa_success_{round_num}r_')
    tmp = Path(tmp_ctx)
    try:
        trails_out = tmp / f'trails_{round_num}r.txt'
        rc_g, out_g, err_g = run_cmd([
            sys.executable, str(gen_trails),
            '--round', str(round_num),
            '--input-diff', input_diff,
            '--rotate-nibble',
            '--want', str(want),
            '--seed', str(seed),
            '--workers', str(workers),
            '--threads-per-worker', str(threads_per_worker),
            '--out', str(trails_out),
        ], cwd=tmp)
        if rc_g != 0 or not trails_out.is_file():
            return {
                'seed': seed, 'success': False, 'outcomes': [],
                'note': f'gen_trails rc={rc_g}; err={err_g.strip()[:200]}',
                'tmp': str(tmp) if keep_tmp else None,
            }

        rc_a, out_a, err_a = run_cmd([str(binary), str(round_num)],
                                     cwd=tmp, env=env)
        if rc_a != 0:
            return {
                'seed': seed, 'success': False, 'outcomes': [],
                'note': f'rotating_attack rc={rc_a}; err={err_a.strip()[:200]}',
                'tmp': str(tmp) if keep_tmp else None,
            }

        outcomes = parse_nk_outcomes(out_a)
        # Success requires all three nk-equality lines to be True.  If
        # the binary emits fewer than three, count it as a failure so a
        # future output-format drift surfaces here, not silently.
        ok = (len(outcomes) == 3 and all(outcomes))
        return {
            'seed': seed, 'success': ok, 'outcomes': outcomes,
            'note': '', 'tmp': str(tmp) if keep_tmp else None,
        }
    finally:
        if not keep_tmp:
            # Best-effort cleanup — a crashed trial should not leak MBs.
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--round', type=int, required=True, choices=[6, 7, 8],
                    help="target round count (6, 7, or 8)")
    ap.add_argument('--trials', type=int, default=30,
                    help="number of distinct seeds to try (default 30)")
    ap.add_argument('--seed-start', type=int, default=1_000_000,
                    help="first seed; subsequent trials use seed-start+1, ...")
    ap.add_argument('--want', type=int, default=None,
                    help="gen_trails --want value (default: paper value for --round)")
    ap.add_argument('--input-diff', default=None,
                    help="gen_trails --input-diff (default: paper value for --round)")
    ap.add_argument('--workers', type=int, default=4,
                    help="gen_trails --workers per trial (default 4)")
    ap.add_argument('--threads-per-worker', type=int, default=2,
                    help="gen_trails --threads-per-worker (default 2)")
    ap.add_argument('--binary', default=None,
                    help="rotating_attack binary (default: ./rotating_attack next to this script)")
    ap.add_argument('--gen-trails', default=None,
                    help="gen_trails.py path (default: next to this script)")
    ap.add_argument('--omp-threads', type=int, default=None,
                    help="OMP_NUM_THREADS for the attack binary (default: inherit environment)")
    ap.add_argument('--keep-tmp', action='store_true',
                    help="do not delete per-trial tempdirs (for debugging)")
    ap.add_argument('--verbose', action='store_true',
                    help="print per-trial PASS/FAIL as it happens")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    binary = Path(args.binary) if args.binary else here / 'rotating_attack'
    gen_trails = Path(args.gen_trails) if args.gen_trails else here / 'gen_trails.py'

    if not binary.is_file() or not os.access(str(binary), os.X_OK):
        print(f"ERROR: rotating_attack binary not found / not executable: {binary}",
              file=sys.stderr)
        print(f"       Run `make` in {here} first.", file=sys.stderr)
        return 2
    if not gen_trails.is_file():
        print(f"ERROR: gen_trails.py not found: {gen_trails}", file=sys.stderr)
        return 2

    want = args.want if args.want is not None else DEFAULTS_BY_ROUND[args.round]['want']
    input_diff = args.input_diff if args.input_diff is not None \
        else DEFAULTS_BY_ROUND[args.round]['input_diff']

    env = os.environ.copy()
    if args.omp_threads is not None:
        env['OMP_NUM_THREADS'] = str(args.omp_threads)

    print(f"# measure_success_rate.py — Sec. 4.4 empirical success probability")
    print(f"# round={args.round}  want={want}  input_diff={input_diff}  "
          f"trials={args.trials}")
    print(f"# seeds: {args.seed_start} .. {args.seed_start + args.trials - 1}")
    print(f"# binary:     {binary}")
    print(f"# gen_trails: {gen_trails}")
    print("#")

    t0 = time.time()
    successes = 0
    failures = []
    errors = 0  # gen_trails / binary invocation errors (not counted as attack failures)
    for i in range(args.trials):
        seed = args.seed_start + i
        res = run_trial(
            seed=seed, round_num=args.round, want=want, input_diff=input_diff,
            workers=args.workers, threads_per_worker=args.threads_per_worker,
            gen_trails=gen_trails, binary=binary, env=env, keep_tmp=args.keep_tmp,
        )
        if res['note'] and ('gen_trails rc=' in res['note'] or 'rotating_attack rc=' in res['note']):
            # infrastructure failure — surface it but don't penalise the attack
            errors += 1
            print(f"  trial {i+1:>3}/{args.trials}  seed={seed:>10}  ERROR  "
                  f"({res['note']})", file=sys.stderr)
            continue
        if res['success']:
            successes += 1
            if args.verbose:
                print(f"  trial {i+1:>3}/{args.trials}  seed={seed:>10}  PASS")
        else:
            failures.append(res)
            print(f"  trial {i+1:>3}/{args.trials}  seed={seed:>10}  FAIL  "
                  f"outcomes={res['outcomes']}")

    elapsed = time.time() - t0
    total_attack_trials = args.trials - errors
    if total_attack_trials <= 0:
        print("ERROR: no attack trials completed (every trial errored out).",
              file=sys.stderr)
        return 1

    rate = successes / total_attack_trials
    lo, hi = wilson_ci(successes, total_attack_trials)
    print("")
    print(f"# Results (round={args.round}, nt={want}):")
    print(f"#   attack trials:   {total_attack_trials}  "
          f"(+ {errors} infrastructure error(s) excluded)")
    print(f"#   successes:       {successes}")
    print(f"#   failures:        {len(failures)}")
    print(f"#   success rate:    {rate*100:.2f}%  "
          f"(Wilson 95% CI: [{lo*100:.2f}%, {hi*100:.2f}%])")
    print(f"#   paper claim:     > 95 %")
    print(f"#   wall time:       {elapsed:.1f} s")
    # Exit 0 regardless of the rate — the observed rate is informational,
    # not an assertion (small samples legitimately fall below 95 %
    # sometimes).  A reviewer who wants CI enforcement can grep for the
    # "success rate:" line and threshold on it externally.
    return 0


if __name__ == '__main__':
    sys.exit(main())
