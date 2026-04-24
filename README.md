# MIFA — Artifact for the TCHES 2026 paper (ePrint 2025/2070)

This repository contains the source code, input data, and experimental
results supporting the TCHES 2026 Issue&nbsp;3 paper
**"MIFA: An MILP-based Framework for Improving Differential Fault
Attacks"** (Shin *et al.*, IACR ePrint
[2025/2070](https://eprint.iacr.org/2025/2070)).

In one paragraph: MIFA uses an MILP (Mixed-Integer Linear
Programming) formulation to search for
differential trails that have a **single solution** under the target
cipher's S-box / permutation / key-schedule constraints.  Once such
single-solution trails are identified, a standard DFA template
using those trails recovers the key with far fewer fault injections
than prior DFA work — because each trail pins down more key bits,
and no candidate trail can be silently mistaken for another.

The paper applies the framework to two ciphers:

* **DEFAULT** (simple and rotating key schedules, 6-/7-/8-round Differential Fault Attacks, "DFAs") — see the DEFAULT section below
* **BAKSHEESH** (4-round and 5-round DFAs) — see the BAKSHEESH section below

Each cipher has its own top-level directory with a `Codes/` tree (source
and input data) and a `Results/` tree (pre-computed experiment output).

**License.** All artifact code and documentation is released under the
**MIT License** — see [`LICENSE`](LICENSE).  The only non-open-source
runtime dependency is Gurobi (academic license); see the
[Commercial / non-redistributable dependencies](#commercial--non-redistributable-dependencies) section
for how to run the artifact without it.

One-command reproduction of every non-Gurobi experiment for both
ciphers:

```bash
git clone https://github.com/shb115/MIFA.git && cd MIFA
./reproduce.sh             # full: ~20–35 min attacks + ~80 min verify_power_of_two
./reproduce.sh --quick     # smoke run: skips DEFAULT simple 8r (~40 GB RAM)
                           # and verify_power_of_two (~80 min).  The rest
                           # of the pipeline — simple 6r+7r, all rotating
                           # runs, BAKSHEESH 4r+5r, count_non_LS — still
                           # executes in full.  Total wall time on the
                           # reference machine (i7-12700K, 64 GB RAM) is
                           # ~3-5 min; smaller boxes take longer mainly
                           # because all_diff_3r.py skips p-values it
                           # cannot fit into its 30 GB RSS cap.
./reproduce.sh --fresh     # rm -rf reproduce_output/ before running
                           # (useful after a prior partial run).
./reproduce.sh --help      # print usage
```
> **If you only have 10 minutes:** run `./reproduce.sh --quick` on
> a box with ≥ 16 GB RAM.  This rebuilds every non-Gurobi output file
> except DEFAULT simple 8r and `verify_power_of_two`, verifies that
> all key-recovery attacks succeed, and finishes in ~3-5 min on the
> reference machine (a few more minutes on smaller boxes).
> **`--quick` on <32 GB boxes.**  `count_non_LS/all_diff_3r.py` is
> always run (including under `--quick`) and may take several minutes
> and/or skip some input differences under its 30 GB memory cap — see
> [DEFAULT Sec. 3](#default-sec-3--defaultcodescount_non_ls).  If you
> want the fastest-possible smoke run on a 16 GB box, skip
> `all_diff_3r.py` manually by editing `reproduce.sh`.

> **Where do regenerated files go?**  `./reproduce.sh` writes
> everything it produces into **`reproduce_output/`** at the repo
> root, mirroring the shipped `Results/` tree.  The committed
> `DEFAULT/Results/` and `BAKSHEESH/Results/` are the **reference**
> and are never touched — so a partial / crashed / Ctrl-C'd run can
> never corrupt them.  To compare a fresh run against the reference:
> ```bash
> diff -r reproduce_output/DEFAULT/Results    DEFAULT/Results
> diff -r reproduce_output/BAKSHEESH/Results  BAKSHEESH/Results
> ```
> `reproduce_output/` is `.gitignore`-d.

### <a id="glossary"></a>Glossary (terms used throughout this README)

| Term                          | Gloss                                                                                           |
| :---------------------------- | :---------------------------------------------------------------------------------------------- |
| DFA                           | Differential Fault Attack — recover the key by injecting single-bit faults and correlating (ciphertext, faulty ciphertext) pairs against a differential trail |
| MILP                          | Mixed-Integer Linear Programming (solved by Gurobi) — used to search for differential trails    |
| single-solution trail         | a round-by-round difference sequence `X_0 … X_R` that is the *unique* solution of the DDT (Differential Distribution Table) / bit-perm constraints given its input and output difference; MIFA's core building block |
| LS / non-LS nibble            | The nibble-value set that the round S-box stabilises (fixes or maps within itself); non-LS = anything outside it.  **LS differs per cipher: DEFAULT LS = {0, 6, 9, f}, BAKSHEESH LS = {0, 8}.**  The paper's Sec. 3.2 uses the DEFAULT LS to bound how many rounds the DEFAULT attack must cover; BAKSHEESH's LS appears in `BAKSHEESH/Codes/count_non_LS/` |
| fault pattern `0xN`           | single-bit fault flipping bit `log2(N)` of the chosen nibble — e.g. `0x1`→bit 0, `0x2`→bit 1, `0x4`→bit 2, `0x8`→bit 3 |
| simple key schedule           | DEFAULT variant where four round keys `rk0..rk3` are *independent* inputs (reused round-robin every 4 rounds across the full 80-round cipher) |
| rotating key schedule         | DEFAULT variant where `rk0..rk3` are derived from one master key by fixed permutations (also reused round-robin every 4 rounds); several master keys can yield the same sequence, so they form **equivalence classes** |
| normalised key `nk[i]`        | canonical representative of each rotating-schedule equivalence class; the artifact's success metric is `nk{i} == nk[{i}] : True` |
| DDT                           | Differential Distribution Table — for a given S-box, DDT[a][b] counts inputs x with S(x)⊕S(x⊕a) = b |
| MK / master key               | The 128-bit secret input to the cipher; the attack recovers it nibble-by-nibble                 |
| RSS                           | Resident Set Size — the portion of a process's memory that is kept in RAM (the number Peak-RAM tables quote) |
| WSL                           | Windows Subsystem for Linux — the reference environment `reproduce.sh` was developed on (Ubuntu 20.04 WSL 2) |

### Table of contents

0. [Glossary](#glossary)
1. [Repository layout](#repository-layout)
2. [Dependencies](#dependencies)
3. DEFAULT
   - [Sec. 1 simple-schedule key-recovery attack (C + OpenMP)](#default-sec-1--defaultcodeskey_recovery_attacksimple_key_schedule--c--openmp)
   - [Sec. 2 rotating-schedule key-recovery attack](#default-sec-2--defaultcodeskey_recovery_attackrotating_key_schedule)
   - [Sec. 3 non-LS nibble counts](#default-sec-3--defaultcodescount_non_ls)
   - [Sec. 4 power-of-two verification](#default-sec-4--defaultcodesverify_power_of_two)
   - [Sec. 5 single-solution trail search (MILP)](#default-sec-5--defaultcodesfind_diff_trail_with_single_sol--requires-gurobi)
   - [Sec. 6 reference cipher implementation](#default-sec-6--defaultcodesreference_code)
4. BAKSHEESH
   - [Sec. 1 key-recovery attack (C + OpenMP)](#baksheesh-sec-1--baksheeshcodeskey_recovery_attack--c--openmp)
   - [Sec. 2 non-LS nibble counts](#baksheesh-sec-2--baksheeshcodescount_non_ls)
   - [Sec. 3 probability calculator](#baksheesh-sec-3--baksheeshcodeskeyspace_prob_calc)
   - [Sec. 4 single-solution trail search (MILP)](#baksheesh-sec-4--baksheeshcodesfind_diff_trail_with_single_sol--requires-gurobi)
   - [Sec. 5 reference cipher implementation](#baksheesh-sec-5--baksheeshcodesreference_code)
5. [Paper ↔ artifact mapping](#paper--artifact-mapping)
6. [Resource budget](#resource-budget-single-run-summary)
7. [Reproducing `Results/`](#reproducing-results)
8. [Commercial / non-redistributable dependencies](#commercial--non-redistributable-dependencies)
9. [License](#license)
10. [Citation](#citation)

-------------------------------------------------------------------------------
## Repository layout

```
MIFA/  (repo root)
├── README.md                       this file
├── LICENSE                         MIT
├── CITATION.cff                    machine-readable citation metadata
├── .gitignore
├── .gitattributes                  enforce LF line-endings (reproduce.sh shebang)
├── reproduce.sh                    end-to-end reproducer (both ciphers)
├── reproduce_output/               ← created by reproduce.sh (git-ignored)
│
├── DEFAULT/
│   ├── Codes/
│   │   ├── count_non_LS/
│   │   ├── find_diff_trail_with_single_sol/
│   │   │   ├── trail_check/
│   │   │   └── trail_num/{0x1,0x2,0x8}/   #   data_*r.pkl + search scripts
│   │   │                                  #   0x8/ ships only scripts — see its own README.md
│   │   ├── key_recovery_attack/
│   │   │   ├── rotating_key_schedule/
│   │   │   │   ├── rotating_common.{h,c}   # C + OpenMP port
│   │   │   │   ├── key_recovery_on_rotating_key_schedule_Nr.c   #   unified driver (./rotating_attack 6|7|8)
│   │   │   │   ├── gen_trails.py           #   Gurobi pair/trail generator
│   │   │   │   ├── Makefile
│   │   │   │   └── trails_{6,7,8}r.txt     #   committed pair/trail data
│   │   │   └── simple_key_schedule/
│   │   │       ├── default_common.{h,c}    # C + OpenMP port
│   │   │       ├── key_recovery_attack_Nr.c   #   unified driver (./default_simple_attack 6|7|8)
│   │   │       ├── Makefile
│   │   │       └── trails_{6,7,8}r.txt     #   committed pair/trail data (mk + c1_list + c2_list + trail_list)
│   │   ├── reference_code/
│   │   │   ├── rotating_key_schedule/
│   │   │   └── simple_key_schedule/
│   │   └── verify_power_of_two/
│   └── Results/
│       ├── count_non_LS/
│       ├── find_diff_trail_with_single_sol/
│       ├── key_recovery_attack/
│       │   ├── rotating_key_schedule/
│       │   └── simple_key_schedule/
│       └── verify_power_of_two/
│
└── BAKSHEESH/
    ├── Codes/
    │   ├── count_non_LS/
    │   ├── find_diff_trail_with_single_sol/
    │   │   ├── trail_check/
    │   │   └── trail_num/{0x1,0x4,0x8}/
    │   ├── key_recovery_attack/
    │   │   ├── baksheesh_common.{h,c}     # C + OpenMP port
    │   │   ├── key_recovery_Nr.c          #   unified driver (./baksheesh_attack 4|5)
    │   │   ├── Makefile
    │   │   └── trails_{4,5}r.txt          #   pair/trail data
    │   ├── reference_code/
    │   └── keyspace_prob_calc/         # prob.py — analytic per-nibble keyspace calculator
    └── Results/
        ├── find_diff_trail_with_single_sol/
        └── key_recovery_attack/
```

-------------------------------------------------------------------------------
## Dependencies

Reference environment used to produce the committed `Results/` files:

| Component            | Minimum                | Tested version                 | Used by / notes                                                |
| -------------------- | ---------------------- | ------------------------------ | -------------------------------------------------------------- |
| GCC                  | 9.0 (needs OpenMP)     | 9.4.0                          | All C code in `Codes/**/*.c`; requires `-fopenmp`              |
| GNU Make             | 4.0                    | 4.2.1                          | Each `Codes/**/Makefile`                                       |
| Python (non-Gurobi)  | 3.8                    | 3.8.10 (system)                | All `.py` files outside `find_diff_trail_with_single_sol/` and `gen_trails.py` |
| Python (Gurobi)      | 3.9                    | 3.12.9 (miniforge)             | `gen_trails.py` + every `find_diff_trail_with_single_sol/` script — Gurobi 12 floor |
| NumPy                | 1.20                   | 2.3.4                          | only `DEFAULT/Codes/verify_power_of_two/analyze_key_recovery.py` |
| psutil               | 5.0                    | 7.2.2                          | `all_diff_3r.py` and BAKSHEESH `all_diff_check_2r.py` (memory cap)     |
| Gurobi (`gurobipy`)  | 10.0                   | 12.0.3                         | only `find_diff_trail_with_single_sol/` and the rotating-key-schedule trail generator — **commercial; academic license required** |
| OS                   | x86-64 Linux (also: WSL 2, macOS best-effort) | Ubuntu 20.04.4 LTS (WSL 2); also verified on Ubuntu 22.04 WSL 2 / GCC 11 and Ubuntu 22.04 native / GCC 11.4.0 | reference build environment; `reproduce.sh` has a `sysctl -n hw.ncpu` fallback for macOS, but macOS is **not** covered by the tested-version column |
| CPU                  | any x86-64             | Intel Core i7-12700K (12th Gen), 20 hardware threads | quoted wall-times assume this                |
| RAM                  | 16 GB (most), 64 GB (DEFAULT simple 8r) | 64 GB DDR           | see Resource budget table below                                |

Older `gcc` / `python3` that meet the minimum should also work but have
not been exercised.

On Ubuntu / WSL:

```bash
sudo apt install build-essential python3 python3-numpy python3-psutil
# Gurobi (only needed for find_diff_trail_with_single_sol/ and for
# regenerating rotating-key-schedule trail files; the committed trail
# files can be used without Gurobi):
#   https://www.gurobi.com/academia/academic-program-and-licenses/
python3 -m pip install --user gurobipy==12.0.3
```

> **If you run from a conda / venv environment**, the `sudo apt install`
> line installs into the *system* `python3` — not the conda / venv one
> that `./reproduce.sh` will actually call.  Activate the env first and
> install with `pip` instead:
> ```bash
> pip install numpy psutil gurobipy==12.0.3
> ```
> `./reproduce.sh` prints the exact `python3` path in its error
> message when a module is missing, so you can see which interpreter
> is being checked.

A single-thread run is supported by setting `OMP_NUM_THREADS=1` but is
roughly **20× slower** on the reference machine.

> **Note on binary portability.**  Every Makefile under
> `Codes/key_recovery_attack/**/Makefile` builds with
> `-O3 -march=native`, which targets the CPU of the build host.
> **Rebuild on every machine you run the artifact on** (that is what
> `./reproduce.sh` does — it always `make clean`-then-`make`-s each
> experiment before running).  Do not copy the compiled binaries
> between machines of different CPU families (e.g. ARM ↔ x86,
> different x86 microarchitectures): they may SIGILL on CPUs that lack
> an instruction the host compiler picked up.

### Repository footprint (committed data files)

A fresh `git clone` is roughly **35 MB** on disk.  Most of that is a
handful of plain-text sample files (no Git LFS; they live in the
regular working tree):

| File(s)                                                                                 | Size        |
| :-------------------------------------------------------------------------------------- | :---------- |
| `DEFAULT/Codes/verify_power_of_two/8r_0x1_4pair_1000testnum_with_diff_trail.txt`        | ≈ 2.3 MB    |
| `DEFAULT/Codes/count_non_LS/0x{1,2}_{…}r_100000.txt` (6 files)                          | ≈ 3.4 MB each (≈ 21 MB total) |
| `BAKSHEESH/Codes/count_non_LS/0x{4,8}_{…}r_100000.txt` (3 files)                        | ≈ 3.4 MB each (≈ 10 MB total) |
| `BAKSHEESH/Codes/reference_code/0x{4,8}_{…}r_1000.txt` (5 files)                        | ≈ 36 KB each |
| `DEFAULT/Codes/find_diff_trail_with_single_sol/trail_num/0x{1,2}/data_{…}r.pkl`         | ≈ 10–200 KB each |
| everything else (C + Python + Results)                                                  | < 2 MB       |

Plan for roughly 50 MB free disk on a `git clone`, plus the build /
`reproduce_output/` directory which adds up to another ~50 MB on a full
run.

===============================================================================
# DEFAULT

The DEFAULT cipher tree contains all experiments on the DEFAULT block
cipher (both *simple* and *rotating* key schedules, for 6-/7-/8-round
reduced variants).  The reduced-round key-recovery attacks under
`Codes/key_recovery_attack/` are implemented in C + OpenMP; all other
experiments (`count_non_LS/`, `verify_power_of_two/`,
`find_diff_trail_with_single_sol/`, `reference_code/`) are as written
in the paper, in Python or reference C.

-------------------------------------------------------------------------------
## DEFAULT Sec. 1 — `DEFAULT/Codes/key_recovery_attack/simple_key_schedule/` — C + OpenMP

A key-recovery attack on DEFAULT under the *simple* key schedule, for the
6-/7-/8-round reduced variants.  Implemented in C with OpenMP (Open
Multi-Processing) and reproduces the algorithmic description of the
paper exactly (the original
Python reference was removed after the C port was verified bit-for-bit
against it on the 6-round run — the C port is the single canonical
source going forward).

Parameters mirror the paper:

| Round | Fault pattern | Paper ref. |
| :---: | :-----------: | :--------- |
| 6     | `0x2`         | Sec. 4.3.1     |
| 7     | `0x2`         | Sec. 4.3.2     |
| 8     | `0x1`         | Sec. 4.3.3     |

> **Fault pattern notation.**  `0x1` = a single-bit fault flipping bit 0
> of the chosen nibble; `0x2` = flipping bit 1; and so on.  Each attack
> applies the chosen pattern at a fixed nibble position in the simple-
> schedule case, or at a *uniformly random* nibble position in the
> rotating-schedule case (see Sec. 2).

The driver peels the cipher off one round at a time from the ciphertext
end.  For an R-round attack (R ∈ {6, 7, 8}) the stage functions called
(in order, all defined in `default_common.c`) are:

| Stage | Function                        | Output                       |
| :---: | :------------------------------ | :--------------------------- |
| 1     | `attack_r1`                     | `r1_keyspace`                |
| 2     | `attack_r2`                     | `r2_keyspace`                |
| 3     | `attack_r3`                     | `r3_keyspace`                |
| 4     | `attack_r456_from_r3_product`   | `r4_keyspace`                |
| 5 … R | `attack_r456` (called R − 4 times) | successively narrower `r4_keyspace` |

So 6r triggers 6 stage calls, 7r triggers 7, 8r triggers 8.  The name
`attack_r456` is a legacy from the first 6-round driver (where this
function handled the last three rounds); it now handles any number of
remaining rounds via its `extra_rounds` argument.  After all R stages
the output is the master-key candidate set.

### Files

| File                              | Role                                               |
| --------------------------------- | -------------------------------------------------- |
| `default_common.h` / `.c`         | shared primitives (`inv_sbox`, `inv_perm`, packed keyspaces, attack stages) |
| `key_recovery_attack_Nr.c`        | unified driver (`./default_simple_attack 6|7|8`); reads the pair/trail data from `trails_<N>r.txt` |
| `trails_{6,7,8}r.txt`             | committed per-round pair/trail data (mk + `c1_list` + `c2_list` + `trail_list`); same file format as BAKSHEESH and DEFAULT rotating |
| `Makefile`                        | builds `default_simple_attack` with `-O3 -march=native -fopenmp` |

### Build & run

```bash
cd DEFAULT/Codes/key_recovery_attack/simple_key_schedule
make                                           # builds default_simple_attack
OMP_NUM_THREADS=$(nproc) ./default_simple_attack 6   # expects trails_6r.txt
OMP_NUM_THREADS=$(nproc) ./default_simple_attack 7   # expects trails_7r.txt
OMP_NUM_THREADS=$(nproc) ./default_simple_attack 8   # expects trails_8r.txt
```

Each invocation writes its report to stdout; the `./reproduce.sh` wrapper
captures them into
`DEFAULT/Results/key_recovery_attack/simple_key_schedule/key_recovery_attack_{6,7,8}r.txt`.

### Expected run times (20-thread OpenMP, reference machine)

| Round | Time    | Peak RSS | Notes                                  |
| ----- | ------- | -------- | -------------------------------------- |
| 6r    | < 0.1 s | tens of MB | three trails (`c1,c2`, `c3,c4`, `c5,c6`) |
| 7r    | ≈ 1 min | a few GB | two trails (`c1,c2`, `c3,c4`)          |
| 8r    | ≈ 20 min | peak up to ~40 GB RAM | two trails (`c1,c2`, `c3,c4`) |

8r's peak happens during the streamed cartesian product
`r3[0] × r3[1]`; a machine with **≥ 64 GB RAM** is recommended so
the ~40 GB working-set has enough OS / interpreter headroom.

### Sample output (6-round)

```
### 6-round key-recovery ###
NUM_PAIRS 3
### r1_keyspace ###
mk in r1_keyspace
r1_keyspace length: 8 4 4 4 4 4 4 8 8 4 8 8 4 8 4 4 4 8 8 8 8 4 4 4 8 4 4 4 4 4 8 4
mk in r2_keyspace
r2_keyspace length: 32 16 32 32 16 16 32 16
mk in r3_keyspace
r3_keyspace length: 32 32
mk in r4_keyspace
r4_keyspace length: 1
mk in r5_keyspace
r5_keyspace length: 1
mk in r6_keyspace
r6_keyspace length: 1
Time: 0.0310s
```
(The `Time:` line varies per run — hardware / scheduler noise.  The
value above matches the committed `key_recovery_attack_6r.txt`; a
fresh run typically finishes in 0.01–0.1 s.)

Each `r<k>_keyspace length:` row gives the number of surviving
candidates *per key nibble*.  A full 128-bit key is 32 nibbles, so the
first line (`r1_keyspace`) prints 32 per-nibble counts; the later lines
collapse the state into groups (8 groups of 4 nibbles for `r2_keyspace`,
2 halves of 16 nibbles for `r3_keyspace`) and eventually to a single
32-nibble keyspace of size 1.  The final `r<k>_keyspace length: 1`
together with `mk in r<k>_keyspace` on each line indicates that the
attack narrowed the last-round key down to the unique master key.

-------------------------------------------------------------------------------
## DEFAULT Sec. 2 — `DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/`

Key-recovery attack on DEFAULT under the *rotating* key schedule
(ePrint 2025/2070, Sec. 4.4).  The attack runs in C + OpenMP; the only
Python file under this directory is `gen_trails.py`, a Gurobi-backed
utility that generates the pair/trail data.

> **Reading the committed rotating output.**  Unlike the simple-
> schedule attack, the rotating output does **not** end with
> `r<k>_keyspace length: 1` — this is by design.  The rotating
> attack narrows each round key to an *equivalence class* (4-8
> candidates per nibble), not to a unique raw key; the final raw-
> key resolution (paper's Step 2) is out of scope for this artifact.
> **The success criterion is the three lines `nk3 == nk[3] : True`,
> `nk2 == nk[2] : True`, `nk1 == nk[1] : True`** (each normalised-
> key equivalence class was correctly recovered).  The trailing
> `rk0_keyspace` row showing per-nibble counts of mostly 4 (with a
> handful of 8s) is expected and matches the paper's Sec. 4.4
> discussion.

The unified C driver reads the appropriate pair/trail file at run time.
Parameters (fault pattern, number of trails `nt`) mirror the paper:

| Round | Fault pattern | `nt` (trails) | Paper ref. |
| :---: | :-----------: | :-----------: | :--------- |
| 6     | `0x2`         | 25            | Sec. 4.4.1     |
| 7     | `0x2`         | 11            | Sec. 4.4.2     |
| 8     | `0x1`         | 9             | Sec. 4.4.3     |

For every trial the same single-bit fault pattern is applied at a
*uniformly random nibble position* (the `--rotate-nibble` option of
`gen_trails.py`).  Without rotation, all faults would land at nibble 0
and many key positions would never get filtered — the rotation gives
the attack uniform coverage over all 32 key nibbles.

> **Equivalence classes and the `nk` variables.**  Under the rotating
> key schedule, the four round keys `rk0, rk1, rk2, rk3` are derived
> from a single master key and are related by fixed permutations.
> Several distinct master keys can therefore produce the same sequence
> `(rk0, rk1, rk2, rk3)`, so the attack cannot distinguish those master
> keys from each other — they form an **equivalence class**.  The
> artifact picks a canonical representative of each class, the
> **normalised key** `nk[i]`, and the success metric for each attack
> stage is the equality `nk{i} == nk[{i}] : True`, i.e. *the stage
> recovered the correct equivalence class* (not necessarily the raw
> `rk{i}` bits).  The `rk{i}_keyspace_1 length: …` rows give the per-
> nibble surviving raw-key candidate counts *within* the class.

The paper states that `nt = 25 / 11 / 9` is enough for success with
probability > 95 % for 6r / 7r / 8r respectively.  The 5 % tail means
that for some random seeds the attack may leave a few nibbles with an
unresolved equivalence-class ambiguity; if that happens on your
regeneration, rerun `gen_trails.py` with a different `--seed`.

> **Committed `trails_{6,7,8}r.txt` — seeds and patterns.**  Each
> shipped trails file records in its header comment the exact
> `gen_trails.py` command that produced it.  The committed seeds
> are `20260420` for 6r and 8r, and `11111` for 7r (the 7r run
> needed a different seed because the first-tried value did not
> land in the > 95 % tail at `nt = 11`).  `gen_trails.py`'s own
> default `--seed` is `42`; any seed that satisfies the ≥ 95 %
> success criterion is acceptable.
>
> **Reproducibility caveat.**  Even with the *same* `--seed`, the
> emitted `trails_Nr.txt` is guaranteed **byte-identical** to the
> committed reference only when `gen_trails.py` is run with
> `--workers 1 --threads-per-worker 1`.  With more workers, an early
> `pool.terminate()` (fires as soon as `--want` single-trail results
> are collected) races against worker-scheduling order, so which
> specific seeds land in the final file can vary between runs.  The
> emitted file is always *statistically equivalent* to the committed
> one (same `--want` single-trail trials drawn i.i.d. at the same
> seed), and the downstream C driver recovers the key with the same
> > 95 % success probability regardless.  For a literal `diff -r`
> match use `--workers 1 --threads-per-worker 1`.

### Dependencies

* C port: `gcc` with OpenMP only.
* `gen_trails.py`: **Gurobi** with `gurobipy==12.0.3` (one MILP per
  random plaintext pair, keep single-trail cases).  Required only to
  regenerate the shipped `trails_{6,7,8}r.txt`; the committed files are
  usable directly by the C driver.

### Usage

```bash
cd DEFAULT/Codes/key_recovery_attack/rotating_key_schedule

# C port — unified driver, same binary for all three round counts
make
OMP_NUM_THREADS=$(nproc) ./rotating_attack 6       # expects trails_6r.txt
OMP_NUM_THREADS=$(nproc) ./rotating_attack 7       # expects trails_7r.txt
OMP_NUM_THREADS=$(nproc) ./rotating_attack 8       # expects trails_8r.txt

# Regenerate the trail files (each run produces a fresh random sample
# that the C driver can attack with > 95 % probability).  The call to
# gurobipy requires Python ≥ 3.9 (gurobipy 12.0 floor); use whichever
# python3 on PATH satisfies that — e.g. a miniforge environment.
#
# The --seed values below are those recorded in each committed
# trails_Nr.txt header; with --workers 1 --threads-per-worker 1 they
# reproduce the shipped files byte-for-byte, and with more workers
# they produce a statistically-equivalent file (same seed, but
# scheduler races alter which single-trail seeds land in the first
# --want slots — see the "Reproducibility caveat" note above).  Any
# other seed satisfying the >95% criterion is also acceptable —
# gen_trails.py's own default is --seed 42.
python3 gen_trails.py --round 6 --input-diff 0x2 --rotate-nibble --want 25 \
    --seed 20260420 \
    --workers 10 --threads-per-worker 2 --out trails_6r.txt
python3 gen_trails.py --round 7 --input-diff 0x2 --rotate-nibble --want 11 \
    --seed 11111 \
    --workers 10 --threads-per-worker 2 --out trails_7r.txt
python3 gen_trails.py --round 8 --input-diff 0x1 --rotate-nibble --want 9  \
    --seed 20260420 \
    --workers 10 --threads-per-worker 2 --out trails_8r.txt

# Empirically measure the > 95 % success-probability claim from
# Sec. 4.4 by running gen_trails.py + ./rotating_attack across many
# seeds and reporting the pass/fail rate with a Wilson 95 % CI.
# Requires Gurobi (gen_trails is the bottleneck); each trial spins
# up a fresh tempdir with its own trails_<R>r.txt, so the committed
# trails_Nr.txt files are never touched.  Defaults match the paper:
#   --round 6 → (want=25, input-diff=0x2)
#   --round 7 → (want=11, input-diff=0x2)
#   --round 8 → (want= 9, input-diff=0x1)
python3 measure_success_rate.py --round 6 --trials 30
python3 measure_success_rate.py --round 7 --trials 30
python3 measure_success_rate.py --round 8 --trials 30
```

### Output shape

Each C run prints, for every of the four attack stages, the per-nibble
keyspace size and whether the recovered normalised key matches
ground truth (`nk3 == nk[3]`, `nk2 == nk[2]`, `nk1 == nk[1]`).  After
Step 1 the paper expects `rk0_keyspace` to collapse to a 2⁶⁴
*equivalent-key* space — visible here as most positions having 4
candidates and a handful having 8 (two merged equivalence classes).
Step 2 of the paper's attack, which narrows this to a unique master
key, is not implemented in this artifact (it requires additional
fault injections at much deeper rounds).

`./reproduce.sh` captures all three C outputs into
`DEFAULT/Results/key_recovery_attack/rotating_key_schedule/key_recovery_on_rotating_key_schedule_{6,7,8}r.txt`.

### Approx. run times (20-thread OpenMP)

| Step                             | 6r        | 7r        | 8r        |
| -------------------------------- | --------- | --------- | --------- |
| Attack (C)                       | < 0.05 s  | < 0.05 s  | < 0.05 s  |
| Trail generation (Gurobi)        | ≈ 1 s     | ≈ 2 s     | ≈ 90 s    |

-------------------------------------------------------------------------------
## DEFAULT Sec. 3 — `DEFAULT/Codes/count_non_LS/`

Counts the expected number of **non-LS** (non-Linear-Structure) active
nibbles after a given number of rounds for different input differences.
Here "LS" is the nibble-value set {0, 6, 9, f} that the DEFAULT S-box
stabilises (fixes or maps within itself); non-LS = anything outside
that set.  The paper's Sec. 3.2 uses this count to bound how many
rounds the attack must cover.

### Files

| Script                   | Purpose                                                                   |
| ------------------------ | ------------------------------------------------------------------------- |
| `0x1_2-5r.py`            | round-by-round analysis for input-difference pattern `p = 0x1` (prints rounds 5, 4, 3, 2) |
| `0x2_3-5r.py`            | round-by-round analysis for `p = 0x2` (prints rounds 5, 4, 3)             |
| `all_diff_3r.py`         | exhaustive 3-round analysis across all 128 single-bit input differences (runs with a 30 GB soft-memory cap; may skip some input differences — **see note below**) |
| `stats_diff_check.py`    | small utility: counts nibble frequencies in the `0x*_*r_100000.txt` sample data files |

Input sample files consumed by `stats_diff_check.py` (six files total):
`0x1_5r_100000.txt`, `0x1_6r_100000.txt`, `0x1_7r_100000.txt`,
`0x2_4r_100000.txt`, `0x2_5r_100000.txt`, `0x2_6r_100000.txt`.

### Usage

```bash
cd DEFAULT/Codes/count_non_LS
# Write under the top-level reproduce_output/ tree, mirroring
# reproduce.sh — the committed Results/ reference is never touched.
OUT=../../../reproduce_output/DEFAULT/Results/count_non_LS
mkdir -p "$OUT"
python3 0x1_2-5r.py    > "$OUT/0x1_2-5r_results.txt"
python3 0x2_3-5r.py    > "$OUT/0x2_3-5r_results.txt"
python3 all_diff_3r.py > "$OUT/all_diff_3r.txt"

# stats_diff_check.py takes the output directory as argv[1] and
# defaults to a local `stats_diff_output/` subdirectory next to this
# script, so running it casually does NOT overwrite the committed
# Results/ tree.  Pass "$OUT" to have it also land under
# reproduce_output/ for a unified diff workflow.
python3 stats_diff_check.py                                  # → ./stats_diff_output/0x{1_5-7,2_4-6}r_results.txt
python3 stats_diff_check.py "$OUT"                           # → under reproduce_output/
# python3 stats_diff_check.py ../../Results/count_non_LS     #   explicitly overwrite committed Results/
```

`stats_diff_check.py` produces the committed
`DEFAULT/Results/count_non_LS/{0x1_5-7r_results,0x2_4-6r_results}.txt`
files — aggregate-per-round nibble-frequency statistics for the shipped
sample files.  `./reproduce.sh` runs it under the `count_non_LS`
section, writing results into `reproduce_output/DEFAULT/Results/count_non_LS/`;
the output is deterministic (reads fixed sample files) so a `diff -r`
against the committed reference should match exactly.

> **Note on `all_diff_3r.py` memory cap.**  The script enforces a soft
> 30 GB RSS cap on its *own* process (`psutil`).  Because the OS,
> Python interpreter, and any concurrent work all need headroom on top
> of that, in practice you want a machine with at least **32 GB total
> RAM** (cap at 30 GB, ≥ 32 GB total RAM for OS / interpreter
> headroom).  Input differences whose per-round state explosion would
> exceed the 30 GB process cap are **skipped** and listed at the end
> of the output under a `"skipped p values"` banner.  On a 16 GB box
> expect several `p` values to be skipped — this is expected
> behaviour, not a bug.  The committed
> `DEFAULT/Results/count_non_LS/all_diff_3r.txt` was produced on a
> 64 GB box and so has no skips; diffs against it on smaller machines
> will legitimately differ in the trailing skipped-list block.

-------------------------------------------------------------------------------
## DEFAULT Sec. 4 — `DEFAULT/Codes/verify_power_of_two/`

Large-scale Monte-Carlo verification that the number of surviving
key-candidates after **attack rounds 1 and 2** matches the power-of-two
prediction of the paper (Appendix A.2).  The paper makes the power-of-
two claim specifically for `r1_keyspace` (per-nibble counts) and
`r2_keyspace` (per-group counts) — the later rounds 3–8 shrink to a
unique candidate through Cartesian-product intersection and are not
claimed to be individually powers of two; `analyze_key_recovery.py`
still reports their `log2(candidates)` for completeness, but those
numbers are expected to converge to 0 (unique-key) rather than to
match any predicted power-of-two.

### Files

| File                                                 | Role                                                                       |
| ---------------------------------------------------- | -------------------------------------------------------------------------- |
| `verify_power_of_two.py`                             | main test harness                                                          |
| `analyze_key_recovery.py`                            | post-processes the stats file into aggregate log₂ counts                   |
| `8r_0x1_4pair_1000testnum_with_diff_trail.txt`        | 1010 unique master keys on disk, each with up to 4 ciphertext pairs + the 9-step differential trail; `verify_power_of_two.py` analyses the 1002 MKs that have exactly 4 pairs (the 8 MKs with fewer pairs are surfaced to stdout as a single `Skipping 8 MK(s) with < 4 pairs: Test IDs [...]` line — not written into the stats file). The filename's `1000testnum` rounds the 1010 figure to the nearest hundred |

### Usage

```bash
cd DEFAULT/Codes/verify_power_of_two
# verify_power_of_two.py INPUT_TXT OUTPUT_TXT MAX_TESTS
#   all three arguments are optional.  The defaults are the shipped
#   sample next to this script, a sibling stats output, and
#   MAX_TESTS = 0 (unlimited — the full 1002-test run that matches
#   the committed reference).  Pass a positive integer to cap.
# NOTE: this example writes under the top-level reproduce_output/
# tree, mirroring reproduce.sh — the committed Results/ reference
# is never touched.
mkdir -p ../../../reproduce_output/DEFAULT/Results/verify_power_of_two
python3 verify_power_of_two.py \
    8r_0x1_4pair_1000testnum_with_diff_trail.txt \
    ../../../reproduce_output/DEFAULT/Results/verify_power_of_two/key_recovery_stats_10tests.txt \
    10
python3 analyze_key_recovery.py \
    ../../../reproduce_output/DEFAULT/Results/verify_power_of_two/key_recovery_stats_10tests.txt \
  > ../../../reproduce_output/DEFAULT/Results/verify_power_of_two/analyze_key_recovery_stats_10tests.txt
```

`verify_power_of_two.py` is CPU-bound and single-threaded.  On the
reference machine (i7-12700K, single thread) each test takes roughly
**8 minutes**.  The **committed** `key_recovery_stats.txt` and
`analyze_key_recovery_stats.txt` were produced with all 1002 tests
(≈ 130 CPU-hours; `MAX_TESTS = 0`).  `./reproduce.sh` runs with
`MAX_TESTS = 10` (~80 min) and writes its output to `*_10tests.txt`
sibling files under `reproduce_output/`, **so the committed 1002-test
stats are preserved** for byte-level comparison.  Pass `0` as
`MAX_TESTS` to regenerate the full-1002 file.

-------------------------------------------------------------------------------
## DEFAULT Sec. 5 — `DEFAULT/Codes/find_diff_trail_with_single_sol/` — requires Gurobi

Finds **single-solution differential trails** through DEFAULT.
"Single-solution" means: given a fixed input difference at round 0 and
a fixed output difference at round R, only one sequence of intermediate
round differences `X_1, X_2, …, X_{R-1}` is simultaneously consistent
with the S-box DDT and the bit-permutation across every round.  This is
exactly MIFA's core contribution — an MILP formulation (Gurobi, solved
with `PoolSearchMode=2` so every feasible solution is enumerated) that
identifies such pairs of (input diff, output diff) whose connecting
trail is uniquely determined.  These trails are precisely the ones the
key-recovery attacks in Sec. 1 and Sec. 2 use to pin down each round key.

### Structure

```
find_diff_trail_with_single_sol/
├── trail_check/                          # verifying a specific trail
│   ├── trail_search_on_default.py        # uses Gurobi PoolSearchMode=2 to enumerate all solutions
│   └── trail_val_check.py                # verifies hard-coded 6/7/8r trails against the DDT (no Gurobi)
└── trail_num/                            # searching for trails across random starting differences
    ├── 0x1/
    │   ├── trail_num_search_on_default.py
    │   ├── data_check.py                 # reads data_{6,7,8}r.pkl, reports solution ratios
    │   └── data_{6,7,8}r.pkl             # precomputed Gurobi run results (boolean array)
    ├── 0x2/                              # same, for input diff 0x2; only data_{6,7}r.pkl ships — the 8-round attacks use the 0x1 fault pattern (see Sec. 4.3.3 / Sec. 4.4.3), so data_8r.pkl for 0x2 is deliberately not included
    └── 0x8/                              # scripts only; run to regenerate a .pkl
```

`trail_num_search_on_default.py` writes its result directly to
`data_{N}r.pkl` in the current directory (overwriting any prior pkl
for the same round).  `TARGET_ROUND` is taken from `argv[1]` or falls
back to the in-script default.

### Gurobi setup

`gurobipy` requires a license.  Academic users can obtain one from
<https://www.gurobi.com/academia/academic-program-and-licenses/>.

### Usage

```bash
# Enumerate trails — writes {round}r_0x{INPUT_DIFF:x}_solution_output.txt
# in CWD for each of round = 6, 7, 8 (or pass a single round as argv[1]).
# Paper INPUT_DIFF mapping: 6r→0x2, 7r→0x2, 8r→0x1 (Sec. 4.3/4.4).
cd DEFAULT/Codes/find_diff_trail_with_single_sol/trail_check
python3 trail_search_on_default.py           # all three rounds
# python3 trail_search_on_default.py 8       # just 8r (writes 8r_0x1_*)

# Drop the regenerated outputs under reproduce_output/ (mirroring
# the reproduce.sh discipline — never touch the committed Results/
# tree directly).  Diff against the committed reference afterwards.
mkdir -p ../../../../reproduce_output/DEFAULT/Results/find_diff_trail_with_single_sol
cp 6r_0x2_solution_output.txt \
   7r_0x2_solution_output.txt \
   8r_0x1_solution_output.txt \
   ../../../../reproduce_output/DEFAULT/Results/find_diff_trail_with_single_sol/

# No-Gurobi sanity check of the hard-coded example trails.
python3 trail_val_check.py

# No-Gurobi sanity check that the trails the attacks actually use
# (inline trails in ../../key_recovery_attack/simple_key_schedule/
# and the committed trails_Nr.txt files) are DDT-consistent end-to-end.
# Runs without a Gurobi license — uses the DEFAULT S-box DDT directly.
python3 trail_val_check_against_committed.py

# Stochastic search across 1000 random output differences, for input 0x1.
# Pass the target round as argv[1]; the script writes data_{round}r.pkl
# directly into the current directory (overwriting any prior pkl).
cd ../trail_num/0x1
python3 trail_num_search_on_default.py 6        # long-running; writes data_6r.pkl
python3 data_check.py                           # reports the solution ratio
```

### DDT-to-inequalities pipeline (how the 24 / 26 constraints below the S-box were obtained)

The S-box DDT constraints in `trail_search_on_default.py`
(**24 inequalities**) and `trail_search_on_baksheesh.py`
(**26 inequalities**) are not written by hand — they are the minimal
two-level logic cover of the DDT truth table emitted by the
**Espresso** logic minimiser (`Espresso.exe`, the Berkeley tool
distributed with Berkeley VLSI CAD).  The pipeline was:

1. Enumerate all 256 nibble-pair input/output difference vectors
   `(a, b)` and tag each with the boolean `DDT[a][b] > 0`.
2. Write the 256 rows as a single PLA file (`.type fd`, 8 inputs,
   1 output) in Espresso's input format.
3. Run `Espresso.exe input.pla > output.pla`; the output's ON-set is
   the minimal sum-of-products cover.
4. Translate each product term into a single linear inequality
   `± a_i ± b_j + … ≥ -k` (where k is the number of negated
   literals in the product) — this converts the boolean logic cover
   into the H-representation of the same feasible region.

The ≥ relation is preserved by the conversion; verifying this against
the DDT is what the in-source comment labels "verified exhaustively
over all 256 (a,b) nibble pairs".  Regenerating the constraints for a
different S-box is therefore a matter of emitting a fresh PLA file and
rerunning Espresso — no MILP / convex-hull toolchain needed.

### Inspecting the full Gurobi solution pool (advanced)

`trail_search_on_default.py` and `trail_search_on_baksheesh.py` both
cap Gurobi's solution pool at `PoolSolutions = 2` — the Sec. 3.1
"single-solution" claim only needs to distinguish "exactly 1" from
"≥ 2", and a small cap lets Gurobi short-circuit as soon as a second
trail is found.  To inspect the *full* solution pool for a given pair
(e.g. enumerate N > 1 trails for manual review, or double-check a
"SolCount == 1" pair with a wider cap), pass `POOL_CAP=N` in the
environment:

```bash
POOL_CAP=100 python3 trail_search_on_default.py 6
POOL_CAP=100 python3 trail_search_on_baksheesh.py 4
```

The existing `.pkl` files in `trail_num/0x1/` and `trail_num/0x2/` are
pre-computed outputs.  Because Gurobi runs take hours and require a
license, `reproduce.sh` **does not** re-run these; they must be regenerated
manually if desired.

-------------------------------------------------------------------------------
## DEFAULT Sec. 6 — `DEFAULT/Codes/reference_code/`

Textbook-style C implementations of the DEFAULT cipher — the *full*
80-round cipher (`default.c`) and the reduced variants used in the
attacks (`default_reduced.c` / `default_rotating_reduced.c`).  These are
meant as a specification-style reference, not part of the attack pipeline.

### Build

```bash
cd DEFAULT/Codes/reference_code/simple_key_schedule
gcc -O2 default.c -o default
./default                                 # prints four test vectors
gcc -O2 default_reduced.c -o default_reduced
./default_reduced 6                        # <round-count>

# rotating key schedule
cd ../rotating_key_schedule
gcc -O2 default.c -o default && ./default
gcc -O2 default_rotating_reduced.c -o default_rotating_reduced && ./default_rotating_reduced
# note: default_rotating_reduced hard-codes its test parameters and takes
# no CLI arguments, unlike simple_key_schedule's default_reduced which
# takes `<round-count>` as argv[1].
```

===============================================================================
# BAKSHEESH

The BAKSHEESH cipher tree mirrors DEFAULT's `Codes/` / `Results/`
layout.  Only the BAKSHEESH **single-solution trail search** (Sec. 3.1 of
the paper) is part of the paper's claims; the key-recovery attacks
(4-round / 5-round), the non-LS nibble statistics, and the probability
calculator under this tree are *not* in the paper.  They are additional
experiments included with this artifact to illustrate that the MIFA
framework carries over to BAKSHEESH without modification.

-------------------------------------------------------------------------------
## BAKSHEESH Sec. 1 — `BAKSHEESH/Codes/key_recovery_attack/`  (C + OpenMP)

Two reduced-round differential-fault attacks on BAKSHEESH (4-round and
5-round), implemented in C + OpenMP.  The unified driver
`key_recovery_Nr.c` reads the pair/trail data from a `.txt` file next
to the binary and then runs `attack_r1 … attack_r4` (4-round) or
`attack_r1 … attack_r5` (5-round).  Each `attack_rN` is the N-th
stage of the attack: it peels one more round off the ciphertext end,
intersecting the surviving keyspace with what the next fault trail
allows.  BAKSHEESH-specific primitives (S-box, rc-add,
`circ_left_shift` key-schedule step, three-phase `attack_r2`) live in
`baksheesh_common.{h,c}`.

| Round | NUM_PAIRS | Pair/trail file |
| :---: | :-------: | --------------- |
| 4     | 30        | `trails_4r.txt` |
| 5     | 10        | `trails_5r.txt` |

Both `NUM_PAIRS` values are chosen generously so that every per-nibble
keyspace is well filtered across every intermediate stage.

### Usage

```bash
cd BAKSHEESH/Codes/key_recovery_attack
make
OMP_NUM_THREADS=$(nproc) ./baksheesh_attack 4    # reads trails_4r.txt
OMP_NUM_THREADS=$(nproc) ./baksheesh_attack 5    # reads trails_5r.txt
```

Run times (20-thread OpenMP, reference machine): **4r ≈ 0.8 s,
5r ≈ 0.6 s**.  Both runs recover the master key uniquely
(`mk in r{4,5}_keyspace`, `r{4,5}_keyspace length: 1`).

-------------------------------------------------------------------------------
## BAKSHEESH Sec. 2 — `BAKSHEESH/Codes/count_non_LS/`

Differential analysis of BAKSHEESH under single-bit faults of various
positions (same role as DEFAULT's `count_non_LS`, though the BAKSHEESH
variant is **not referenced by the paper** — it is an artifact-only
demonstration).  Four scripts:

| Script                       | Purpose                                                                                      |
| ---------------------------- | -------------------------------------------------------------------------------------------- |
| `0x4_diff_check.py`          | per-round DDT + bit-perm expectation analysis for input difference `p = 0x4` (no file I/O)   |
| `0x8_diff_check.py`          | per-round DDT + bit-perm expectation analysis for input difference `p = 0x8` (no file I/O)   |
| `all_diff_check_2r.py`       | 2-round exhaustive analysis across all single-bit fault positions                            |
| `monte_diff.py`              | Monte-Carlo hex-character-frequency counter over the shipped `0x{4,8}_*r_100000.txt` samples |

Sample data (`0x4_4r_100000.txt`, `0x4_5r_100000.txt`,
`0x8_4r_100000.txt`) live alongside these scripts; they were
originally generated by the reference C cipher in
`BAKSHEESH/Codes/reference_code/` and are consumed only by
`monte_diff.py`.  The three `*_diff_check.py` scripts are
probabilistic (no file I/O) — they mirror DEFAULT's `0x1_2-5r.py` role.

### Usage

```bash
cd BAKSHEESH/Codes/count_non_LS
python3 all_diff_check_2r.py  # prints to stdout
python3 0x4_diff_check.py     # prints to stdout
python3 0x8_diff_check.py     # prints to stdout
python3 monte_diff.py         # reads the shipped .txt samples, prints hex-frequency stats
```

`./reproduce.sh` does not drive these scripts (they print to stdout
and their outputs are not part of any paper claim); run them by hand
if you want to inspect their numbers.

> **Round depth divergence in this directory.**  `0x4_diff_check.py`
> iterates 4 rounds (rounds 5 → 2), `0x8_diff_check.py` only 3 rounds
> (rounds 5 → 3).  The 0x8 variant stops at round 3 because the
> active-nibble set expands past a practical memory budget before
> round 2 — see the note in the 0x8 script.  For round-2 stats
> across all single-bit fault patterns, use `all_diff_check_2r.py`
> (which enforces its own memory cap).

-------------------------------------------------------------------------------
## BAKSHEESH Sec. 3 — `BAKSHEESH/Codes/keyspace_prob_calc/`

Contains `prob.py`, a small interactive calculator that, given  n_t
(number of trails used) and  b  (probability that a trail is
non-useful), reports the distribution over the remaining per-nibble
keyspace sizes (16, 8, 4, 2) and their log₂-expectation.  Used while
deriving the paper's trail-count tables.  (The directory is **not**
the BAKSHEESH analogue of DEFAULT's Monte-Carlo `verify_power_of_two/`;
it is only an interactive analytic calculator, hence the more specific
name.)

```bash
cd BAKSHEESH/Codes/keyspace_prob_calc
python3 prob.py
# Example interactive session — enter these when prompted:
#   n_t = 30             (number of trails, e.g. the 4-round attack ships 30)
#   b   = 21.21875/32    (per-trail non-useful probability; script
#                         computes a = 1 - b itself.  Plain decimals
#                         like 0.663 also work.)
# The script then prints the probability distribution over
# remaining per-nibble keyspace sizes {16, 8, 4, 2}.
```

-------------------------------------------------------------------------------
## BAKSHEESH Sec. 4 — `BAKSHEESH/Codes/find_diff_trail_with_single_sol/` — requires Gurobi

Same structure as DEFAULT's Sec. 5: `trail_check/` has the MILP
trail-search script (`trail_search_on_baksheesh.py`) and a validator
(`trail_val_check.py`); `trail_num/0x{1,4,8}/` holds the pre-computed
`.pkl` solution-count arrays and the search scripts that produce them.
All MILP-based searches need Gurobi; `./reproduce.sh` skips them.

### Structure

```
find_diff_trail_with_single_sol/
├── trail_check/
│   ├── trail_search_on_baksheesh.py      # MILP trail enumerator (PoolSearchMode=2)
│   └── trail_val_check.py                # DDT validator (no Gurobi)
└── trail_num/
    ├── 0x1/
    │   ├── trail_num_search_on_baksheesh.py
    │   ├── data_check.py                 # reads data_{4,5}r.pkl, reports ratio
    │   └── data_{4,5}r.pkl               # precomputed Gurobi run results
    ├── 0x4/                              # same, for input diff 0x4
    └── 0x8/                              # same, for input diff 0x8
```

### Usage

```bash
# Enumerate trails — writes {round}r_0x1_solution_output.txt in CWD
# for each of round = 4, 5 (or pass a single round as argv[1]).
cd BAKSHEESH/Codes/find_diff_trail_with_single_sol/trail_check
python3 trail_search_on_baksheesh.py          # both rounds
# python3 trail_search_on_baksheesh.py 5      # just 5r

# Drop the regenerated outputs under reproduce_output/ (mirroring
# reproduce.sh's discipline — never touch the committed Results/).
mkdir -p ../../../../reproduce_output/BAKSHEESH/Results/find_diff_trail_with_single_sol
cp 4r_0x1_solution_output.txt 5r_0x1_solution_output.txt \
   ../../../../reproduce_output/BAKSHEESH/Results/find_diff_trail_with_single_sol/

# No-Gurobi sanity check of hard-coded trails
python3 trail_val_check.py

# Stochastic search across 1000 random output differences for each
# fault pattern.  Pass the target round as argv[1]; the script
# writes data_{round}r.pkl directly into the current directory
# (overwriting any prior pkl).
cd ../trail_num/0x1
python3 trail_num_search_on_baksheesh.py 4    # writes data_4r.pkl
python3 data_check.py                         # reports the ratio
```

The existing `.pkl` files in `trail_num/0x{1,4,8}/` are pre-computed
outputs; because Gurobi runs take hours and require a license,
`reproduce.sh` does not re-run them.  BAKSHEESH scripts explicitly
set `PoolSolutions = 10000` (matching the cap used to produce the
committed pkls); DEFAULT scripts leave Gurobi's default cap, so the
raw integer pools differ between ciphers.  `data_check.py` only
reads `.count(1)`, so the single-solution ratio it reports is
unaffected by this asymmetry.

-------------------------------------------------------------------------------
## BAKSHEESH Sec. 5 — `BAKSHEESH/Codes/reference_code/`

`baksheesh.c` (full 35-round cipher) and `baksheesh_reduced.c`
(encrypt for a configurable number of rounds only) plus the sample
data they produce:

  * `0x4_{4,5,6}r_1000.txt`, `0x8_{4,5}r_1000.txt` — 1000 (c1, c2)
    pairs under fault `0x4` / `0x8` at the stated round counts; the
    MK is printed at the top of each file.  These are the samples
    `trail_num/0x{4,8}/` and `count_non_LS/monte_diff.py` consume.
  * `4r.txt` — a small human-readable 4-round sanity trace:
    `mk1`, then per-pair `(p1^p2, c1, c2)` blocks under fault `0x1`.
    Useful for debugging; not referenced by any script.

Build with a plain `gcc`:

```bash
cd BAKSHEESH/Codes/reference_code
gcc -O2 baksheesh.c -o baksheesh          && ./baksheesh
gcc -O2 baksheesh_reduced.c -o baksheesh_reduced
./baksheesh_reduced 4 1000                # <round-count> <sample-count>
```

===============================================================================
## Paper ↔ artifact mapping

The table below ties each experimental claim in the paper (IACR ePrint
[2025/2070](https://eprint.iacr.org/2025/2070)) to the script that
produces it and the file under `Results/` where the pre-computed output
is archived.  `D/` = `DEFAULT/`, `B/` = `BAKSHEESH/` (path prefixes
shortened for readability).

| Paper ref.   | What it shows                                | Script / driver (relative path)                                                         | Output (`Results/…`)                                                                 |
| :----------- | :------------------------------------------- | :-------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- |
| Sec. 3.1         | DEFAULT — specific (input diff, output diff) pairs that admit a unique round-by-round trail (MILP witness for Sec. 3.1's core construction) | `D/Codes/find_diff_trail_with_single_sol/trail_check/trail_search_on_default.py`        | `D/Results/find_diff_trail_with_single_sol/{6,7}r_0x2_solution_output.txt` + `8r_0x1_solution_output.txt` (8-round attack uses fault `0x1`, see Sec. 4.3.3 / 4.4.3)       |
| Sec. 3.1         | DEFAULT — trail-density statistics over 1000 random output differences, showing single-solution trails are plentiful enough to drive the DFA | `D/Codes/find_diff_trail_with_single_sol/trail_num/0x{1,2}/trail_num_search_on_default.py` | `D/Codes/find_diff_trail_with_single_sol/trail_num/0x1/data_{6,7,8}r.pkl` + `…/0x2/data_{6,7}r.pkl` (0x2 has no 8r because the 8-round attacks use fault pattern 0x1) |
| Sec. 3.1         | BAKSHEESH — existence of single-solution trails (MIFA carries over to a different S-box / bit-perm pair) | `B/Codes/find_diff_trail_with_single_sol/trail_check/trail_search_on_baksheesh.py`    | `B/Results/find_diff_trail_with_single_sol/{4,5}r_0x1_solution_output.txt`           |
| Sec. 3.1         | BAKSHEESH — trail-density statistics (sibling of the DEFAULT row above) | `B/Codes/find_diff_trail_with_single_sol/trail_num/0x{1,4,8}/trail_num_search_on_baksheesh.py` | `B/Codes/find_diff_trail_with_single_sol/trail_num/0x{1,4,8}/data_{4,5}r.pkl` |
| Sec. 3.2         | DEFAULT — expected count of non-Linear-Structure (non-LS, i.e. non-{0, 6, 9, f}) active nibbles per round, justifying Sec. 3.2's round bound | `D/Codes/count_non_LS/0x1_2-5r.py`, `0x2_3-5r.py`, `all_diff_3r.py`, `stats_diff_check.py` | `D/Results/count_non_LS/{0x1_2-5r,0x2_3-5r,0x1_5-7r,0x2_4-6r}_results.txt` + `all_diff_3r.txt` |
| Sec. 4.3.1       | DEFAULT simple-schedule DFA, 6 rounds, fault `0x2` — committed stdout shows `mk in r_keyspace` and `r_keyspace length: 1` (master key recovered uniquely) | `D/Codes/key_recovery_attack/simple_key_schedule/` → `./default_simple_attack 6` (reads `trails_6r.txt`)   | `D/Results/key_recovery_attack/simple_key_schedule/key_recovery_attack_6r.txt`       |
| Sec. 4.3.2       | same claim at 7 rounds (fault `0x2`)           | same, `./default_simple_attack 7` (reads `trails_7r.txt`)                                              | `…/key_recovery_attack_7r.txt`                                                       |
| Sec. 4.3.3       | same claim at 8 rounds (fault `0x1`)           | same, `./default_simple_attack 8` (reads `trails_8r.txt`)                                              | `…/key_recovery_attack_8r.txt`                                                       |
| Sec. 4.4.1       | DEFAULT rotating-schedule DFA, 6r, fault `0x2`, `nt = 25` — committed stdout shows `nk{3,2,1} == nk[{3,2,1}] : True` (each of the first three stages recovers the correct equivalence class) plus an `rk0_keyspace` row whose per-nibble counts are mostly 4 with at most a handful of 8s (merged equivalence classes).  The paper's Step 2 that resolves `rk0` itself is out of scope for this artifact (it requires additional fault injections at deeper rounds). | `D/Codes/key_recovery_attack/rotating_key_schedule/` → `./rotating_attack 6`        | `D/Results/key_recovery_attack/rotating_key_schedule/key_recovery_on_rotating_key_schedule_6r.txt` |
| Sec. 4.4.2       | same claim at 7 rounds (`nt = 11`, fault `0x2`) | same, `./rotating_attack 7`                                                          | `…/key_recovery_on_rotating_key_schedule_7r.txt`                                     |
| Sec. 4.4.3       | same claim at 8 rounds (`nt = 9`, fault `0x1`)  | same, `./rotating_attack 8`                                                          | `…/key_recovery_on_rotating_key_schedule_8r.txt`                                     |
| Appendix A.2 | power-of-two keyspace prediction for **rounds 1 and 2** verified by Monte-Carlo over 1002 test keys; rounds 3–8 converge to a unique key (not themselves powers of two — see DEFAULT Sec. 4) | `D/Codes/verify_power_of_two/verify_power_of_two.py` + `analyze_key_recovery.py`        | `D/Results/verify_power_of_two/{key_recovery_stats,analyze_key_recovery_stats}.txt`  |
| *not in paper* | additional experiment — BAKSHEESH 4r/5r DFA demonstrates the MIFA trails also recover BAKSHEESH's master key | `B/Codes/key_recovery_attack/` → `./baksheesh_attack {4,5}`                              | `B/Results/key_recovery_attack/baksheesh_{4,5}r.txt`                                 |
| *not in paper* | additional experiment — BAKSHEESH non-LS counts (sibling of Sec. 3.2; stdout-only demo, no committed output) | `B/Codes/count_non_LS/all_diff_check_2r.py`, `0x{4,8}_diff_check.py`                 | (stdout only; not driven by `./reproduce.sh`)                                        |
| *not in paper* | additional utility — interactive probability calculator that reproduces the paper's trail-count tables | `B/Codes/keyspace_prob_calc/prob.py`                                                    | (interactive; no committed output)                                                   |

> **Note on `data_{*}r.pkl` paths.**  The trail-density MILP scripts
> (`trail_num_search_on_*.py`) write their results in-place next to the
> script, under `Codes/find_diff_trail_with_single_sol/trail_num/0x*/`;
> that is also where the pre-computed `.pkl` files are committed.  They
> are *not* copied into `Results/` because the README's structure
> diagrams (below) and the existing `data_check.py` loaders expect them
> at their in-tree location.

> **DEFAULT `0x8/` directory: scripts only, no committed pkls.** The
> `DEFAULT/Codes/find_diff_trail_with_single_sol/trail_num/0x8/`
> subdirectory ships the harness (`trail_num_search_on_default.py` +
> `data_check.py`) without pre-computed `data_{6,7,8}r.pkl` files —
> the paper's claims only use `0x1` and `0x2` fault-input statistics,
> so `0x8/` is kept for reproducibility extension but does not drive
> any row of the mapping table above.  Running the MILP script here
> (with a target round via argv) regenerates a `data_{N}r.pkl`
> locally; it is not required for Artifacts Functional evaluation.

-------------------------------------------------------------------------------
## Resource budget (single-run summary)

Wall-times measured on the reference machine (Intel Core i7-12700K,
20 hardware threads, 64 GB RAM; Ubuntu 20.04.4 LTS on WSL 2).
Memory is peak resident set.

| Experiment                                             | Wall time           | Peak RAM  | Threads | Needs Gurobi |
| :----------------------------------------------------- | :------------------ | :-------- | :-----: | :----------: |
| DEFAULT simple 6r                                      | < 0.1 s             | tens of MB| 20      | —            |
| DEFAULT simple 7r                                      | ≈ 1 min             | a few GB  | 20      | —            |
| DEFAULT simple 8r                                      | ≈ 20 min            | ≈ 40 GB   | 20      | —            |
| DEFAULT rotating 6r / 7r / 8r (each)                   | < 0.05 s            | < 100 MB  | 20      | —            |
| DEFAULT rotating trail search (MILP) 6r / 7r / 8r      | 1 s / 2 s / 90 s    | < 1 GB    | 10      | ✔            |
| DEFAULT `count_non_LS` (`0x1`, `0x2`, `all_diff_3r`)   | minutes             | up to 30 GB process-cap (~32 GB total RAM recommended; smaller hosts skip some `p` values — see DEFAULT Sec. 3) | 1 | — |
| DEFAULT `verify_power_of_two` (MAX_TESTS=10)          | ~80 min      | < 1 GB    | 1       | —            |
| DEFAULT `find_diff_trail_with_single_sol`              | hours per config.   | depends   | Gurobi  | ✔            |
| BAKSHEESH 4r / 5r                                      | ≈ 0.8 s / 0.6 s     | < 1 GB    | 20      | —            |
| BAKSHEESH `count_non_LS`                               | seconds to minutes  | < 1 GB    | 1       | —            |
| BAKSHEESH `find_diff_trail_with_single_sol`            | hours per config.   | depends   | Gurobi  | ✔            |

The **Artifact Functional** path (what `./reproduce.sh` rebuilds) is all
of the "Needs Gurobi = —" rows.  On the reference machine this takes
≈ 20–25 minutes for everything except `verify_power_of_two`, which adds
another ~80 min (single-threaded, `MAX_TESTS = 10`).  If the
reviewer skips `verify_power_of_two`, the rest finishes in about
half an hour, dominated by DEFAULT simple 8r.

-------------------------------------------------------------------------------
## Reproducing `Results/`

| Experiment                                                    | Reproducer                        |
| ------------------------------------------------------------- | --------------------------------- |
| `DEFAULT/Results/key_recovery_attack/simple_key_schedule/`    | `./reproduce.sh`                  |
| `DEFAULT/Results/key_recovery_attack/rotating_key_schedule/`  | `./reproduce.sh`                  |
| `DEFAULT/Results/count_non_LS/`                               | `./reproduce.sh`                  |
| `DEFAULT/Results/verify_power_of_two/`                        | `./reproduce.sh`                  |
| `DEFAULT/Results/find_diff_trail_with_single_sol/`            | manual (Gurobi) — see DEFAULT Sec. 5  |
| `BAKSHEESH/Results/key_recovery_attack/`                      | `./reproduce.sh`                  |
| *(no `BAKSHEESH/Results/count_non_LS/`)*                      | manual, stdout-only — see BAKSHEESH Sec. 2 |
| `BAKSHEESH/Results/find_diff_trail_with_single_sol/`          | manual (Gurobi) — see BAKSHEESH Sec. 4 |

`./reproduce.sh` writes every regenerated file under
`reproduce_output/` (a sibling of `DEFAULT/` and `BAKSHEESH/` at the
repo root); it never touches inputs under `Codes/` and **never**
touches the committed `Results/` trees.  Each experiment is
independent and can be stopped / resumed at that granularity.

**Expected diff vs committed `Results/`.**  Run
```bash
diff -r reproduce_output/DEFAULT/Results    DEFAULT/Results
diff -r reproduce_output/BAKSHEESH/Results  BAKSHEESH/Results
```
The following diffs are **expected** (not reproduction failures):

1. **C attack `Time: %.4fs` lines** vary run-to-run (hardware /
   scheduling noise).  The rest of each output — `r*_keyspace length:
   …`, `mk in r*_keyspace`, `nk* == nk[*] : True` — should match the
   committed file byte-for-byte.

2. **`count_non_LS/all_diff_3r.txt`**: the script emits a single
   `--- All analyses completed (Total time: X.XXs) ---` line
   **mid-file** (≈ line 388 of 520 in the committed reference,
   right before the "Final Results: Ranking…" block).  That one
   line carries a per-run wall-time; the rest of the file should
   match byte-for-byte.  **On <32 GB RAM hosts** the tail of this
   file also grows a `### Skipped p values ###` block because
   `all_diff_3r.py` enforces a 30 GB RSS cap — those extra lines
   are an environmental artefact, not a reproduction failure.

3. **`verify_power_of_two/`**: in full mode, `diff -r` lists four
   "Only in" entries under this directory, all expected:
   - `Only in reproduce_output/DEFAULT/Results/verify_power_of_two/`:
     `key_recovery_stats_10tests.txt`, `analyze_key_recovery_stats_10tests.txt`
   - `Only in DEFAULT/Results/verify_power_of_two/`:
     `key_recovery_stats.txt`, `analyze_key_recovery_stats.txt`

   `reproduce.sh` writes the 10-test subset to `*_10tests.txt` sibling
   files; the committed reference is the full 1002-test run (~130
   CPU-hours).  `analyze_key_recovery.py` on the 10-test output
   should still report `Unique-key recovery rate: 100.00%`.

4. **`find_diff_trail_with_single_sol/*_solution_output.txt`**
   (5 files total — `6r_0x2`, `7r_0x2`, `8r_0x1` under DEFAULT and
   `4r_0x1`, `5r_0x1` under BAKSHEESH): these are Gurobi MILP
   outputs, which `reproduce.sh` does not re-run.  Because the
   script never creates the sibling `reproduce_output/.../find_diff_trail_with_single_sol/`
   directory either, `diff -r` surfaces this as a single
   **directory-level** entry
   `Only in <cipher>/Results/: find_diff_trail_with_single_sol`
   (one line per cipher, hiding the 5 files inside).  This is
   normal — see DEFAULT Sec. 5 / BAKSHEESH Sec. 4 for the manual
   Gurobi regeneration recipe.

5. **`--quick` mode additionally skips DEFAULT simple 8r** (the
   ~40 GB attack) **and the entire `verify_power_of_two` section**
   (~80 min).  Under `--quick`, `diff -r` therefore also shows:
   - `Only in DEFAULT/Results/key_recovery_attack/simple_key_schedule/`:
     `key_recovery_attack_8r.txt`
   - `Only in DEFAULT/Results/verify_power_of_two/`:
     `key_recovery_stats.txt`, `analyze_key_recovery_stats.txt`
   These are expected under `--quick`; use the full `./reproduce.sh`
   on a ≥ 64 GB box to regenerate them.

**What to do if `./reproduce.sh` prints `FAILED`.**  The script wraps
every experiment in a `run_section` helper that prints a `FAILED
(continuing)` line and moves on; this keeps later sections usable even
if an earlier one OOM-kills (DEFAULT simple 8r needs ~40 GB RAM).
Because every output goes into `reproduce_output/`, a partial file
there is harmless — just delete `reproduce_output/` and re-run, or
re-run the single failing command from the README.  A `--quick` run
avoids both common failure modes.

-------------------------------------------------------------------------------
## Commercial / non-redistributable dependencies

The only non-open-source dependency anywhere in this artifact is
**Gurobi Optimizer** (with its Python binding `gurobipy`), used in:

* `DEFAULT/Codes/find_diff_trail_with_single_sol/` (all MILP scripts)
* `DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/gen_trails.py`
* `BAKSHEESH/Codes/find_diff_trail_with_single_sol/` (all MILP scripts)

Gurobi is commercial software; free academic licences are available at
<https://www.gurobi.com/academia/academic-program-and-licenses/>.
Reviewers **without** a Gurobi license can still reproduce every result
that feeds into a paper claim: all trail-search outputs consumed by
downstream experiments are committed in binary form
(`Codes/find_diff_trail_with_single_sol/trail_num/0x*/data_*.pkl`,
 `Results/find_diff_trail_with_single_sol/**/*_solution_output.txt`,
 `Codes/key_recovery_attack/rotating_key_schedule/trails_{6,7,8}r.txt`),
and the non-Gurobi `./reproduce.sh` path alone regenerates every
`Results/*.txt` referenced by the paper's tables.

-------------------------------------------------------------------------------
## License

This artifact is released under the MIT License — see [`LICENSE`](LICENSE)
for the full text.  All source code in `DEFAULT/Codes/`,
`BAKSHEESH/Codes/`, and the top-level scripts were authored for this
paper; no third-party source is bundled.  The artifact depends on
unmodified releases of GCC, GNU Make, Python / NumPy, and (optionally)
Gurobi, each distributed under its own upstream license.

-------------------------------------------------------------------------------
## Citation

If you use this artifact, please cite the paper:

```bibtex
@article{MIFA-TCHES-2026,
  author  = {Hanbeom Shin and Insung Kim and Sunyeop Kim and
             Byoungjin Seok and Deukjo Hong and Jaechul Sung and
             Seokhie Hong and Sangjin Lee and Dongjae Lee},
  title   = {{MIFA}: An {MILP}-based Framework for Improving Differential
             Fault Attacks},
  journal = {IACR Transactions on Cryptographic Hardware and Embedded Systems},
  volume  = {2026},
  number  = {3},
  year    = {2026},
  note    = {IACR ePrint 2025/2070. \url{https://eprint.iacr.org/2025/2070}}
}
```

The proceedings entry will be updated (volume, issue, pages, DOI) once
the TCHES 2026 Issue 3 volume is published.  The pre-print is permanent
at <https://eprint.iacr.org/2025/2070>.
