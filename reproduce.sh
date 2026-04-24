#!/usr/bin/env bash
#
# reproduce.sh — regenerate every non-Gurobi artifact for the TCHES 2026
#                MIFA artifact (both DEFAULT and BAKSHEESH).
#
# OUTPUT LOCATION
#   All regenerated files are written under `reproduce_output/` at the
#   repo root, mirroring the committed `Results/` tree:
#       reproduce_output/DEFAULT/Results/...
#       reproduce_output/BAKSHEESH/Results/...
#   The committed `DEFAULT/Results/` and `BAKSHEESH/Results/` trees are
#   NEVER touched — reviewers can diff the fresh tree against the
#   committed reference directly:
#       diff -r reproduce_output/DEFAULT/Results DEFAULT/Results
#
# Run from the repo root (this directory).  Gurobi-based experiments
# under {DEFAULT,BAKSHEESH}/Codes/find_diff_trail_with_single_sol/ are
# *not* run from here: they need a licence and take hours.  See the
# respective sections of README.md for the manual commands.

set -uo pipefail                       # NB: no -e — we trap per-section errors instead

# -------------------------------------------------------------------
# Flags:
#   --quick   skip DEFAULT simple 8r (needs ~40 GB RAM, ~20 min) and
#             verify_power_of_two (~80 min single-threaded).  Use
#             this on 16 GB machines or for a smoke run.  Produces
#             every other output file.
# -------------------------------------------------------------------
QUICK=0
FRESH=0
NO_ALL_DIFF_3R=0
for arg in "$@"; do
  case "$arg" in
    --quick)         QUICK=1 ;;
    --fresh)         FRESH=1 ;;
    --no-all-diff-3r) NO_ALL_DIFF_3R=1 ;;
    -h|--help)
      echo "usage: $0 [--quick] [--fresh] [--no-all-diff-3r]"
      echo "  --quick             skip DEFAULT simple 8r and verify_power_of_two"
      echo "  --fresh             rm -rf reproduce_output/ before running"
      echo "  --no-all-diff-3r    skip count_non_LS/all_diff_3r.py (30 GB RSS cap)"
      exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Resolve this script's directory so the script works from any CWD.
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# -----------------------------------------------------------------------------
# Prerequisite check — fail early with a clear message.
# -----------------------------------------------------------------------------
missing=0
for tool in gcc make python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[reproduce] ERROR: '$tool' not found on PATH" >&2
    missing=1
  fi
done

# Python version floor — every non-Gurobi script uses f-strings, which
# require Python ≥ 3.6, and a few scripts use math.comb / dict-insertion
# order, which require ≥ 3.8.  Guard up front so an ancient interpreter
# fails here, not mid-run inside a SyntaxError.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)"; then
    echo "[reproduce] ERROR: python3 version < 3.8 (need 3.8+ for f-strings + math.comb)" >&2
    missing=1
  fi
fi

# OpenMP probe — required by every C + OpenMP driver in this repo.
# Without this check the failure surfaces as a cryptic "cannot find
# -lgomp" mid-build halfway through the run.
if command -v gcc >/dev/null 2>&1; then
  _omp_tmp="$(mktemp -u 2>/dev/null || echo "/tmp/_mifa_ompcheck.$$")"
  if ! printf 'int main(void){return 0;}\n' \
         | gcc -fopenmp -x c - -o "$_omp_tmp" 2>/dev/null; then
    echo "[reproduce] ERROR: 'gcc -fopenmp' did not link successfully." >&2
    echo "[reproduce]        Install the OpenMP runtime, e.g.:" >&2
    echo "[reproduce]          sudo apt install libgomp1     # Debian / Ubuntu / WSL" >&2
    echo "[reproduce]          brew install libomp           # macOS" >&2
    echo "[reproduce]        On macOS the system 'gcc' is Apple Clang without OpenMP;"  >&2
    echo "[reproduce]        after 'brew install libomp' you may also need:"             >&2
    echo "[reproduce]          export CPPFLAGS=\"-I\$(brew --prefix libomp)/include -Xpreprocessor -fopenmp\""  >&2
    echo "[reproduce]          export LDFLAGS=\"-L\$(brew --prefix libomp)/lib -lomp\""  >&2
    missing=1
  fi
  rm -f "$_omp_tmp" 2>/dev/null || true
fi

# Preflight: every committed input the script ultimately depends on.
# A truncated clone / accidentally-deleted file should fail here, not
# a hundred lines later inside a C parser with a cryptic fopen error.
_required_inputs=(
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/simple_key_schedule/trails_6r.txt"
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/simple_key_schedule/trails_7r.txt"
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/simple_key_schedule/trails_8r.txt"
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/trails_6r.txt"
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/trails_7r.txt"
    "$REPO_ROOT/DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/trails_8r.txt"
    "$REPO_ROOT/BAKSHEESH/Codes/key_recovery_attack/trails_4r.txt"
    "$REPO_ROOT/BAKSHEESH/Codes/key_recovery_attack/trails_5r.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x1_5r_100000.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x1_6r_100000.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x1_7r_100000.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x2_4r_100000.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x2_5r_100000.txt"
    "$REPO_ROOT/DEFAULT/Codes/count_non_LS/0x2_6r_100000.txt"
)
# verify_power_of_two's input is only consumed in the non-quick path;
# a truncated clone that excludes verify_power_of_two/ should still be
# able to run the --quick smoke path.
if [ "$QUICK" -eq 0 ]; then
  _required_inputs+=(
    "$REPO_ROOT/DEFAULT/Codes/verify_power_of_two/8r_0x1_4pair_1000testnum_with_diff_trail.txt"
  )
fi
for f in "${_required_inputs[@]}"; do
  # Require a regular, readable, non-empty file.  -s alone would accept
  # a broken symlink whose target reports non-zero size, or a file the
  # current user cannot read — both of which would surface later as a
  # cryptic fopen error deep inside a C parser.
  if [ ! -f "$f" ]; then
    echo "[reproduce] ERROR: committed input missing: $f" >&2
    missing=1
  elif [ ! -r "$f" ]; then
    echo "[reproduce] ERROR: committed input not readable (check perms): $f" >&2
    missing=1
  elif [ ! -s "$f" ]; then
    echo "[reproduce] ERROR: committed input exists but is empty: $f" >&2
    missing=1
  fi
done

# Python modules used by at least one non-Gurobi script on the
# reproduce.sh path.
#   psutil — count_non_LS/all_diff_3r.py (always run)
#   numpy  — verify_power_of_two/analyze_key_recovery.py (only when
#            --quick is OFF; skipped otherwise)
PY_PATH="$(python3 -c 'import sys; print(sys.executable)' 2>/dev/null || echo python3)"
_py_mods=( psutil )
if [ "$QUICK" -eq 0 ]; then
  _py_mods+=( numpy )
fi
for mod in "${_py_mods[@]}"; do
  if ! python3 -c "import $mod" >/dev/null 2>&1; then
    echo "[reproduce] ERROR: python3 module '$mod' not found in:" >&2
    echo "[reproduce]          $PY_PATH" >&2
    if [ -n "${CONDA_PREFIX:-}" ] || [ -n "${VIRTUAL_ENV:-}" ]; then
      echo "[reproduce]        You appear to be inside a conda/venv env — install into that env:" >&2
      echo "[reproduce]          pip install $mod" >&2
      echo "[reproduce]        (\`sudo apt install python3-$mod\` would install into the SYSTEM python3," >&2
      echo "[reproduce]         which is NOT the one above — do not use apt inside an active env.)" >&2
    else
      echo "[reproduce]        fix:  sudo apt install python3-$mod" >&2
      echo "[reproduce]         or:  pip3 install --user $mod" >&2
      echo "[reproduce]        (If you use a conda/venv env, activate it first and run \`pip install $mod\`.)" >&2
    fi
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "[reproduce] Install the missing prerequisites and re-run." >&2
  exit 1
fi

echo "[reproduce] mode = $( [ "$QUICK" -eq 1 ] && echo 'quick (skipping DEFAULT simple 8r + verify_power_of_two)' || echo 'full' )"

# Rough total wall-time estimate so the reviewer knows the budget up
# front (ref machine: i7-12700K, 20 threads, 64 GB RAM).  Exact times
# vary per box — see the Resource budget table in README.md.
if [ "$QUICK" -eq 1 ]; then
  echo "[reproduce] estimated total wall time: ~3-5 min on the reference machine"
  echo "[reproduce]   (longer on <32 GB hosts where all_diff_3r.py skips p-values)"
else
  echo "[reproduce] estimated total wall time: ~100-115 min on the reference machine"
  echo "[reproduce]   (~20-35 min attacks + ~80 min verify_power_of_two single-threaded)"
fi

# Robust thread count: accept the user's OMP_NUM_THREADS only if it is
# a positive integer; otherwise fall back to nproc, sysctl, or 1.
if [ -z "${OMP_NUM_THREADS:-}" ] \
   || ! [[ "$OMP_NUM_THREADS" =~ ^[0-9]+$ ]] \
   || [ "$OMP_NUM_THREADS" -lt 1 ]; then
  OMP_NUM_THREADS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
fi
# final sanity clamp
if ! [[ "$OMP_NUM_THREADS" =~ ^[0-9]+$ ]] || [ "$OMP_NUM_THREADS" -lt 1 ]; then
  OMP_NUM_THREADS=1
fi
export OMP_NUM_THREADS
echo "[reproduce] using $OMP_NUM_THREADS threads"

# Output root — kept separate from committed Results/ so the reviewer
# can diff fresh vs committed without ever corrupting the reference.
OUT_ROOT="$REPO_ROOT/reproduce_output"
echo "[reproduce] writing outputs under $OUT_ROOT"
if [ "$FRESH" -eq 1 ] && [ -e "$OUT_ROOT" ]; then
  # Refuse to `rm -rf` a symlink, a bind-mount, or anything outside
  # the repo — all three would delete files the reviewer did not
  # intend to touch.  A real reproduce_output/ is a regular
  # directory sitting directly under $REPO_ROOT.
  if [ -L "$OUT_ROOT" ]; then
    echo "[reproduce] ERROR: $OUT_ROOT is a symlink; refusing to rm -rf through it." >&2
    echo "[reproduce]        Remove the symlink manually and re-run." >&2
    exit 1
  fi
  if [ ! -d "$OUT_ROOT" ]; then
    echo "[reproduce] ERROR: $OUT_ROOT exists but is not a directory; refusing --fresh." >&2
    exit 1
  fi
  _parent="$(cd -- "$(dirname -- "$OUT_ROOT")" && pwd)"
  if [ "$_parent" != "$REPO_ROOT" ]; then
    echo "[reproduce] ERROR: $OUT_ROOT is not directly under $REPO_ROOT; refusing --fresh." >&2
    exit 1
  fi
  echo "[reproduce] --fresh: removing existing $OUT_ROOT"
  rm -rf -- "$OUT_ROOT"
fi
if [ -d "$OUT_ROOT" ] && [ -n "$(ls -A "$OUT_ROOT" 2>/dev/null)" ]; then
  echo "[reproduce] NOTE: $OUT_ROOT already contains files from a previous run."
  echo "[reproduce]       Sections that run this time will overwrite their own"
  echo "[reproduce]       outputs; sections that do NOT run (e.g. --quick) will"
  echo "[reproduce]       leave the prior files in place.  For a clean baseline:"
  echo "[reproduce]         ./reproduce.sh --fresh   # or: rm -rf reproduce_output/"
fi
mkdir -p "$OUT_ROOT"

# Scrub any `.partial` files left behind by a previous Ctrl-C / SIGKILL
# so they do not surface as spurious "Only in reproduce_output/" lines
# in the next `diff -r`.  The .partial extension is only used by this
# script and by stats_diff_check.py's atomic writes, so this is safe.
find "$OUT_ROOT" -name '*.partial' -type f -delete 2>/dev/null || true

# -----------------------------------------------------------------------------
# Section-failure tracker — reproduce.sh intentionally keeps running after
# one experiment dies so the reviewer still gets every other output, but
# a ./reproduce.sh && diff -r chain must still see a non-zero exit code
# at the end if anything failed.
# -----------------------------------------------------------------------------
FAIL_COUNT=0
FAIL_LABELS=()

# Number of p-values all_diff_3r.py skipped due to its 30 GB RSS cap.
# Populated by the all_diff_3r section below (0 on ≥ 32 GB hosts);
# surfaced again in the final summary so a reviewer skimming the tail
# of the log cannot miss it.
SKIPPED_P_WARN=0

# -----------------------------------------------------------------------------
# run_section: run a command; on failure print a warning but keep going
# so later sections (different experiments) still produce their outputs.
# A reviewer with < 64 GB RAM can then still collect most outputs even
# if DEFAULT simple 8r dies.
# -----------------------------------------------------------------------------
run_section() {
  local label="$1"; shift
  echo "[reproduce] >>> ${label}"
  if "$@"; then
    echo "[reproduce] <<< ${label} ok"
  else
    echo "[reproduce] !!! ${label} FAILED (continuing)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_LABELS+=("${label}")
  fi
}

# -----------------------------------------------------------------------------
# safe_redirect_run OUTFILE CMD...
#
# Run CMD..., redirect its stdout into OUTFILE.partial, and on success
# atomically rename to OUTFILE.  On failure (non-zero exit of CMD),
# delete the .partial so the next `diff -r` does not surface a
# truncated file as "Files differ" without context.  Used for every
# Python script whose output reproduce.sh captures.  The C attacks
# use an equivalent inline `if ./cmd | tee ...partial; then mv else
# rm` pattern because they already run inside a per-cipher bash -c
# block that handles the build + multi-round loop.
# -----------------------------------------------------------------------------
safe_redirect_run() {
  local outfile="$1"; shift
  local tmp="${outfile}.partial"
  rm -f "$tmp"
  if "$@" > "$tmp"; then
    mv -f "$tmp" "$outfile"
    return 0
  else
    local rc=$?
    echo "[reproduce]     (command failed, removing partial: $tmp)" >&2
    rm -f "$tmp"
    return "$rc"
  fi
}

################################################################################
# DEFAULT
################################################################################
DEF_CODES="$REPO_ROOT/DEFAULT/Codes"
DEF_OUT="$OUT_ROOT/DEFAULT/Results"
mkdir -p "$DEF_OUT/key_recovery_attack/simple_key_schedule" \
         "$DEF_OUT/key_recovery_attack/rotating_key_schedule" \
         "$DEF_OUT/count_non_LS" \
         "$DEF_OUT/verify_power_of_two"
export DEF_CODES DEF_OUT

echo "============================================================"
echo "  DEFAULT / key_recovery_attack / simple_key_schedule"
echo "============================================================"
if [ "$QUICK" -eq 1 ]; then
  DEF_SIMPLE_ROUNDS_STR="6 7"
else
  DEF_SIMPLE_ROUNDS_STR="6 7 8"
fi
export DEF_SIMPLE_ROUNDS_STR
run_section "DEFAULT simple_key_schedule ($DEF_SIMPLE_ROUNDS_STR)" bash -c '
  set -euo pipefail
  cd "$DEF_CODES/key_recovery_attack/simple_key_schedule"
  make clean -s
  make -s
  # Use a proper array for the round list so we do not depend on
  # the ambient IFS value.
  read -r -a rounds <<< "$DEF_SIMPLE_ROUNDS_STR"
  for r in "${rounds[@]}"; do
    echo "[reproduce]   ${r}-round attack"
    out="$DEF_OUT/key_recovery_attack/simple_key_schedule/key_recovery_attack_${r}r.txt"
    rm -f "${out}.partial"
    # Clean up the .partial on any interrupt (SIGINT / SIGTERM /
    # subshell exit), not only on an explicit failure branch.
    trap "rm -f \"${out}.partial\"" EXIT
    if ./default_simple_attack "$r" | tee "${out}.partial"; then
      mv -f "${out}.partial" "${out}"
    else
      echo "[reproduce]     (default_simple_attack ${r}r failed, removing partial: ${out}.partial)" >&2
      rm -f "${out}.partial"
      exit 1
    fi
    trap - EXIT
  done
'

echo "============================================================"
echo "  DEFAULT / key_recovery_attack / rotating_key_schedule"
echo "============================================================"
run_section "DEFAULT rotating_key_schedule" bash -c '
  set -euo pipefail
  cd "$DEF_CODES/key_recovery_attack/rotating_key_schedule"
  make clean -s
  make -s
  for r in 6 7 8; do
    echo "[reproduce]   ${r}-round attack"
    out="$DEF_OUT/key_recovery_attack/rotating_key_schedule/key_recovery_on_rotating_key_schedule_${r}r.txt"
    rm -f "${out}.partial"
    trap "rm -f \"${out}.partial\"" EXIT
    if ./rotating_attack "$r" | tee "${out}.partial"; then
      mv -f "${out}.partial" "${out}"
    else
      echo "[reproduce]     (rotating ${r}r failed, removing partial: ${out}.partial)" >&2
      rm -f "${out}.partial"
      exit 1
    fi
    trap - EXIT
  done
'

echo "============================================================"
echo "  DEFAULT / count_non_LS"
echo "============================================================"
# Each of these prints a few kilobytes of analysis to stdout; we
# redirect (not tee) and route through safe_redirect_run so that a
# crash mid-write cleans up the .partial rather than leaving a
# truncated file in reproduce_output/.
run_section "DEFAULT count_non_LS 0x1_2-5r" \
  safe_redirect_run "$DEF_OUT/count_non_LS/0x1_2-5r_results.txt" \
    python3 "$DEF_CODES/count_non_LS/0x1_2-5r.py"
run_section "DEFAULT count_non_LS 0x2_3-5r" \
  safe_redirect_run "$DEF_OUT/count_non_LS/0x2_3-5r_results.txt" \
    python3 "$DEF_CODES/count_non_LS/0x2_3-5r.py"
if [ "$NO_ALL_DIFF_3R" -eq 1 ]; then
  echo "[reproduce] >>> DEFAULT count_non_LS all_diff_3r — SKIPPED (--no-all-diff-3r)"
else
  run_section "DEFAULT count_non_LS all_diff_3r" \
    safe_redirect_run "$DEF_OUT/count_non_LS/all_diff_3r.txt" \
      python3 "$DEF_CODES/count_non_LS/all_diff_3r.py"

  # Surface the SKIPPED_P_VALUES marker the script prints when its 30 GB
  # RSS cap trips.  On a ≥ 32 GB host this marker is "0" and we say
  # nothing; on a 16 GB host several p-values are legitimately skipped
  # and the output will diff against the committed reference (produced
  # on a 64 GB host).  Documenting that up front avoids the "did
  # something fail?" confusion in the final diff -r.
  _all_diff_txt="$DEF_OUT/count_non_LS/all_diff_3r.txt"
  if [ -f "$_all_diff_txt" ]; then
    _skipped_n="$(grep -E '^# SKIPPED_P_VALUES=[0-9]+' "$_all_diff_txt" \
                  | head -1 | awk -F= '{print $2}')"
    if [ -n "${_skipped_n:-}" ] && [ "$_skipped_n" -gt 0 ]; then
      echo "[reproduce] WARNING: all_diff_3r.py skipped ${_skipped_n} p-value(s)"
      echo "[reproduce]          due to its 30 GB RSS cap.  This is expected on"
      echo "[reproduce]          <32 GB hosts — the committed reference was"
      echo "[reproduce]          produced on a 64 GB host (no skips).  To skip"
      echo "[reproduce]          all_diff_3r.py entirely, re-run with --no-all-diff-3r."
      SKIPPED_P_WARN="${_skipped_n}"
    fi
  fi
fi

# stats_diff_check.py aggregates nibble-frequency stats over the shipped
# 0x{1,2}_*r_100000.txt samples.  It takes the output directory as argv[1]
# and writes its own files, so we pass the reproduce_output subdir
# directly rather than redirect its stdout.
run_section "DEFAULT count_non_LS stats_diff_check" \
  bash -c 'set -euo pipefail
           cd "$DEF_CODES/count_non_LS"
           python3 stats_diff_check.py "$DEF_OUT/count_non_LS"'

if [ "$QUICK" -eq 1 ]; then
  echo "============================================================"
  echo "  DEFAULT / verify_power_of_two — SKIPPED (--quick)"
  echo "============================================================"
else
  echo "============================================================"
  echo "  DEFAULT / verify_power_of_two"
  echo "  (MAX_TESTS=10 by default; takes ~80 min single-threaded)"
  echo "============================================================"
  # verify_power_of_two.py writes its own output file via argv[2];
  # wrap the invocation so that the file is only renamed on success.
  # Without this, a Ctrl-C anywhere in the ~80-minute run leaves a
  # truncated stats file that analyze_key_recovery.py then happily
  # reports a misleading "Unique-key recovery rate:" over.
  run_section "DEFAULT verify_power_of_two.py (MAX_TESTS=10)" bash -c '
    set -euo pipefail
    target="$DEF_OUT/verify_power_of_two/key_recovery_stats_10tests.txt"
    tmp="${target}.partial"
    trap "rm -f \"${tmp}\"" EXIT
    rm -f "${tmp}"
    mkdir -p "$(dirname "${target}")"
    python3 "$DEF_CODES/verify_power_of_two/verify_power_of_two.py" \
      "$DEF_CODES/verify_power_of_two/8r_0x1_4pair_1000testnum_with_diff_trail.txt" \
      "${tmp}" 10
    mv -f "${tmp}" "${target}"
    trap - EXIT
  '
  run_section "DEFAULT analyze_key_recovery.py" \
    safe_redirect_run "$DEF_OUT/verify_power_of_two/analyze_key_recovery_stats_10tests.txt" \
      python3 "$DEF_CODES/verify_power_of_two/analyze_key_recovery.py" \
        "$DEF_OUT/verify_power_of_two/key_recovery_stats_10tests.txt"
fi

################################################################################
# BAKSHEESH
################################################################################
BAK_CODES="$REPO_ROOT/BAKSHEESH/Codes"
BAK_OUT="$OUT_ROOT/BAKSHEESH/Results"
mkdir -p "$BAK_OUT/key_recovery_attack"
export BAK_CODES BAK_OUT
# (BAKSHEESH keyspace_prob_calc/prob.py is interactive and has no committed output.
#  BAKSHEESH count_non_LS scripts are not in the paper; they print to
#  stdout only and are not driven by reproduce.sh — run them by hand
#  if curious.)

echo "============================================================"
echo "  BAKSHEESH / key_recovery_attack  (C + OpenMP)"
echo "============================================================"
run_section "BAKSHEESH key_recovery_attack" bash -c '
  set -euo pipefail
  cd "$BAK_CODES/key_recovery_attack"
  make clean -s
  make -s
  for r in 4 5; do
    echo "[reproduce]   ${r}-round attack"
    out="$BAK_OUT/key_recovery_attack/baksheesh_${r}r.txt"
    rm -f "${out}.partial"
    trap "rm -f \"${out}.partial\"" EXIT
    if ./baksheesh_attack "$r" | tee "${out}.partial"; then
      mv -f "${out}.partial" "${out}"
    else
      echo "[reproduce]     (baksheesh_attack ${r}r failed, removing partial: ${out}.partial)" >&2
      rm -f "${out}.partial"
      exit 1
    fi
    trap - EXIT
  done
'

################################################################################
echo ""
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "[reproduce] done — all sections ok."
else
  echo "[reproduce] done — $FAIL_COUNT section(s) FAILED:"
  for _lbl in "${FAIL_LABELS[@]}"; do
    echo "[reproduce]   * ${_lbl}"
  done
fi
# Remind the reviewer what was skipped, so anyone reading only the
# tail of the log doesn't miss that not all sections ran.
_skipped=()
[ "$QUICK" -eq 1 ]       && _skipped+=("DEFAULT simple 8r + verify_power_of_two (--quick)")
[ "$NO_ALL_DIFF_3R" -eq 1 ] && _skipped+=("count_non_LS/all_diff_3r.py (--no-all-diff-3r)")
if [ "${#_skipped[@]}" -gt 0 ]; then
  echo "[reproduce] intentionally skipped:"
  for _s in "${_skipped[@]}"; do
    echo "[reproduce]   * ${_s}"
  done
fi
if [ "$SKIPPED_P_WARN" -gt 0 ]; then
  echo "[reproduce] WARNING: all_diff_3r.py skipped $SKIPPED_P_WARN p-value(s)"
  echo "[reproduce]          under the 30 GB RSS cap — diff vs the committed"
  echo "[reproduce]          reference will differ in the trailing skipped-p block."
fi
echo "[reproduce] Regenerated files are under:"
echo "[reproduce]   $OUT_ROOT"
echo "[reproduce] To compare against the committed reference:"
echo "[reproduce]   diff -r $OUT_ROOT/DEFAULT/Results    $REPO_ROOT/DEFAULT/Results"
echo "[reproduce]   diff -r $OUT_ROOT/BAKSHEESH/Results  $REPO_ROOT/BAKSHEESH/Results"
echo "[reproduce] Expected-diff caveats (NOT reproduction failures):"
echo "[reproduce]   * Final \`Time: %.4fs\` line in every C attack output varies per run."
echo "[reproduce]   * all_diff_3r.txt's '\''Total time: X.XXs'\'' line (~line 388 of 520) varies per run."
echo "[reproduce]   * DEFAULT/Results/verify_power_of_two/ is the full 1002-test run;"
echo "[reproduce]     reproduce.sh writes *_10tests.txt siblings (10-test sample)."
echo "[reproduce]   * Only-in-committed files under"
echo "[reproduce]     {DEFAULT,BAKSHEESH}/Results/find_diff_trail_with_single_sol/"
echo "[reproduce]     (5 *_solution_output.txt) — Gurobi-only, not reproduced here."
echo "[reproduce] Expected to match EXACTLY (no noise):"
echo "[reproduce]   * count_non_LS/{0x1_5-7r_results,0x2_4-6r_results}.txt (stats_diff_check — deterministic over fixed sample files)."
echo "[reproduce]   * count_non_LS/{0x1_2-5r_results,0x2_3-5r_results}.txt (analytic; no RNG)."
echo "[reproduce]   * All r*_keyspace length lines in every C attack output."
echo "[reproduce] Gurobi-based experiments under"
echo "[reproduce]   {DEFAULT,BAKSHEESH}/Codes/find_diff_trail_with_single_sol/"
echo "[reproduce] must be run manually — see README.md."

# Non-zero exit if anything failed so ./reproduce.sh && diff chains
# don't swallow a mid-run failure.
if [ "$FAIL_COUNT" -ne 0 ]; then
  exit 1
fi
exit 0
