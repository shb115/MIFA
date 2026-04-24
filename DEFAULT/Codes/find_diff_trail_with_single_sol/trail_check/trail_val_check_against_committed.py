#!/usr/bin/env python3
"""trail_val_check_against_committed.py — DDT-validate every trail the
committed attack drivers actually consume at runtime:

  1. Every trail in
     DEFAULT/Codes/key_recovery_attack/simple_key_schedule/trails_{6,7,8}r.txt
  2. Every trail in
     DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/trails_{6,7,8}r.txt
  3. Every trail in
     BAKSHEESH/Codes/key_recovery_attack/trails_{4,5}r.txt

For each trail (X_0, X_1, ..., X_R), verify that every S-box transition
(X_i nibble -> inv_perm(X_{i+1}) nibble) is a valid DDT entry for the
respective cipher's S-box.  Prints per-source OK/FAIL summaries and
exits with rc=1 iff any trail fails.

Unlike the sibling `trail_val_check.py` (which validates three hand-
picked example trails), this script reads the exact trails the attack
drivers consume at runtime, closing the gap between "we have a DDT
validator" and "the validator actually audited the trails that run."
No Gurobi required — uses only the S-box / bit-perm tables.
"""

import re
import sys
from pathlib import Path


# ================================================================
# Cipher tables
# ================================================================

# DEFAULT S-box (from DEFAULT/Codes/reference_code/simple_key_schedule/default.c)
DEFAULT_SBOX = [
    0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9,
    0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5,
]

# BAKSHEESH S-box (from BAKSHEESH/Codes/reference_code/baksheesh.c)
BAKSHEESH_SBOX = [
    0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe,
    0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1,
]

# Both ciphers share the same 128-bit bit-permutation; see
# DEFAULT/Codes/reference_code/simple_key_schedule/default.c and
# BAKSHEESH/Codes/reference_code/baksheesh.c.
BIT_PERM = [
    0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
    4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
    8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
   12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
   16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
   20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
   24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
   28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31,
]


def build_ddt(sbox):
    ddt = [[0] * 16 for _ in range(16)]
    for i in range(16):
        for j in range(16):
            ddt[i ^ j][sbox[i] ^ sbox[j]] += 1
    return ddt


def build_inv_bit_perm():
    inv = [0] * 128
    for i, v in enumerate(BIT_PERM):
        inv[v] = i
    return inv


INV_BIT_PERM = build_inv_bit_perm()


def apply_inv_perm(x):
    """Inverse bit-permutation on a 128-bit integer using the same
    MSB-first / LSB-first reversal convention as `trail_val_check.py`
    (kept identical so the two validators report byte-consistent
    nibble indices for the same trail)."""
    x_bits = format(x, '0128b')[::-1]       # LSB-first
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[INV_BIT_PERM[j]] = x_bits[j]
    return int(''.join(y_bits)[::-1], 2)    # back to MSB-first integer


def check_trail(X, ddt):
    """X = [X_0, X_1, ..., X_R].  For each round i in 0..R-1, verify
    DDT[X_i nibble][inv_perm(X_{i+1}) nibble] > 0 at every nibble pos.
    Return (all_ok, bad_round, bad_nibble_idx, bad_x_nibble, bad_y_nibble)."""
    R = len(X) - 1
    if R < 1:
        return (False, -1, -1, -1, -1)
    for i in range(R):
        y_i = apply_inv_perm(X[i + 1])
        for n in range(32):
            xn = (X[i] >> (4 * n)) & 0xF
            yn = (y_i >> (4 * n)) & 0xF
            if ddt[xn][yn] == 0:
                return (False, i, n, xn, yn)
    return (True, None, None, None, None)


# ================================================================
# Parse trail_list from trails_Nr.txt
# (used by DEFAULT simple, DEFAULT rotating, and BAKSHEESH drivers)
# ================================================================

_HEX_128 = re.compile(r'0x[0-9A-Fa-f]{32}')


def parse_trails_file(txt_path):
    """Return list[list[int]] — one entry per inner [0x..., ...] block
    under `trail_list = [ ... ]`.  The BAKSHEESH files include an
    additional top-level `mk = 0x...` line; that literal is excluded
    because we only scan inside the trail_list brackets."""
    src = Path(txt_path).read_text(encoding='utf-8', errors='replace')
    anchor = src.find('trail_list')
    if anchor < 0:
        return []
    # Walk to the opening bracket of the outer list.
    i = anchor
    while i < len(src) and src[i] != '[':
        i += 1
    if i >= len(src):
        return []

    inner_lists = []
    depth = 0
    inner_start = -1
    while i < len(src):
        c = src[i]
        if c == '[':
            depth += 1
            if depth == 2:
                inner_start = i
        elif c == ']':
            if depth == 2 and inner_start >= 0:
                chunk = src[inner_start:i + 1]
                inner_lists.append([int(h, 16) for h in _HEX_128.findall(chunk)])
                inner_start = -1
            depth -= 1
            if depth == 0:
                break
        i += 1
    return inner_lists


# ================================================================
# Validation driver
# ================================================================

def validate_source(label, trails, ddt, expected_len=None):
    print(f"### {label} — {len(trails)} trail(s)")
    fails = 0
    if not trails:
        print("  (no trails found — nothing to validate)")
        return 0
    for k, X in enumerate(trails):
        if expected_len is not None and len(X) != expected_len:
            print(f"  trail {k:>4}: [WARN] has {len(X)} states, expected {expected_len}")
        ok, bad_i, bad_n, xn, yn = check_trail(X, ddt)
        if ok:
            # Only print every trail for small sources; otherwise print
            # a single aggregate line at the end to keep output readable
            # when a trails_Nr.txt carries dozens of entries.
            if len(trails) <= 10:
                print(f"  trail {k:>4}: [OK]   {len(X)} states, all "
                      f"32*{len(X)-1} S-box transitions valid")
        else:
            fails += 1
            print(f"  trail {k:>4}: [FAIL] round {bad_i}, nibble {bad_n}: "
                  f"DDT[0x{xn:x}][0x{yn:x}]=0")
    if len(trails) > 10 and fails == 0:
        print(f"  all {len(trails)} trails: [OK]  every S-box transition valid")
    return fails


def here():
    return Path(__file__).resolve().parent


def repo_root():
    # script lives at DEFAULT/Codes/find_diff_trail_with_single_sol/trail_check/
    # => four parents up is the repo root.
    return here().parent.parent.parent.parent


def main():
    root = repo_root()
    ddt_default = build_ddt(DEFAULT_SBOX)
    ddt_baksheesh = build_ddt(BAKSHEESH_SBOX)

    total_fails = 0

    print("====================================================================")
    print(" DDT validation of EVERY committed trail consumed by the attacks")
    print("====================================================================")

    # ---- DEFAULT simple-schedule trails ------------------------------
    for N in (6, 7, 8):
        txt = root / (
            'DEFAULT/Codes/key_recovery_attack/simple_key_schedule/'
            f'trails_{N}r.txt'
        )
        if not txt.is_file():
            print(f"WARNING: {txt} not found — skipping.", file=sys.stderr)
            continue
        trails = parse_trails_file(txt)
        total_fails += validate_source(
            f"DEFAULT simple {N}r — {txt.name}",
            trails, ddt_default, expected_len=N + 1,
        )

    # ---- DEFAULT rotating-schedule trails ----------------------------
    for R in (6, 7, 8):
        txt = root / (
            'DEFAULT/Codes/key_recovery_attack/rotating_key_schedule/'
            f'trails_{R}r.txt'
        )
        if not txt.is_file():
            print(f"WARNING: {txt} not found — skipping.", file=sys.stderr)
            continue
        trails = parse_trails_file(txt)
        total_fails += validate_source(
            f"DEFAULT rotating {R}r — {txt.name}",
            trails, ddt_default, expected_len=R + 1,
        )

    # ---- BAKSHEESH trails --------------------------------------------
    for R in (4, 5):
        txt = root / f'BAKSHEESH/Codes/key_recovery_attack/trails_{R}r.txt'
        if not txt.is_file():
            print(f"WARNING: {txt} not found — skipping.", file=sys.stderr)
            continue
        trails = parse_trails_file(txt)
        total_fails += validate_source(
            f"BAKSHEESH {R}r — {txt.name}",
            trails, ddt_baksheesh, expected_len=R + 1,
        )

    print()
    if total_fails == 0:
        print("SUCCESS: every committed trail is DDT-consistent.")
        return 0
    print(f"FAILURE: {total_fails} trail(s) had at least one invalid S-box transition.")
    return 1


if __name__ == '__main__':
    sys.exit(main())
