"""analyze_key_recovery.py — Post-processes `key_recovery_stats.txt` into aggregate log2 counts
and per-round non-unique-candidate histograms.

The paper's Appendix A.2 predicts that the per-nibble (round 1) /
per-group (round 2) candidate counts are always *powers of two*
(i.e. every raw value is in {1, 2, 4, 8, 16}).  The mean-log2 metric
reported below is necessary but not sufficient for that claim — a
mix of 4s and 8s would yield a mean of ~2.58 that *looks* integer-ish
without every individual value being a power of two.  To verify the
full claim, this script additionally prints the per-value histogram
of rounds 1 and 2 and an "all-values-are-powers-of-two?" boolean."""

import os
import re
import math
import numpy as np
from collections import Counter


def _is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0


def analyze_stats_file(filename):
    # Print only the basename so that reruns from a different CWD
    # produce byte-identical first lines (stable diff-against-reference).
    print(f"Analyzing {os.path.basename(filename)}...\n")

    with open(filename, 'r') as f:
        content = f.read()

    # Split test cases
    blocks = content.split('------------------------------')

    total_tests = 0
    success_count = 0

    # Data storage
    # round_bits[r] = [log2(c1), log2(c2), ...] : Store bit length of candidate counts
    round_bits = {i: [] for i in range(1, 9)}

    # Raw per-sample candidate counts for rounds 1 and 2 (used by the
    # per-value histogram / power-of-two check).  We skip rounds 3+ here
    # because Appendix A.2 only predicts rounds 1 and 2; the downstream
    # rounds Cartesian-collapse to a unique candidate (see the comment
    # block at the top of this module).
    round_raw = {1: [], 2: []}

    # [Added] Initialize dictionary to count cases where candidates != 1 for Round 4~8
    non_one_counts = {i: 0 for i in range(4, 9)}

    for block in blocks:
        if not block.strip():
            continue

        total_tests += 1

        # 1. Check MK Found
        r8_match = re.search(r"Round 8 Candidates: (\d+)", block)
        mk_match = re.search(r"MK in R8: (True|False)", block)

        if r8_match and mk_match:
            count = int(r8_match.group(1))
            found = (mk_match.group(1) == 'True')
            # Success if only 1 candidate remains and it is the correct key
            if count == 1 and found:
                success_count += 1

        # 2. Parse candidate counts per round and convert to log2

        # Round 1 (List)
        r1_match = re.search(r"Round 1 Candidates \(per nibble\): \[(.*?)\]", block)
        if r1_match:
            vals = [int(x.strip()) for x in r1_match.group(1).split(',')]
            # Apply log2 to each element (candidate count) to get bits
            round_bits[1].extend([math.log2(v) if v > 0 else 0 for v in vals])
            round_raw[1].extend(vals)

        # Round 2 (List)
        r2_match = re.search(r"Round 2 Candidates \(per group\): \[(.*?)\]", block)
        if r2_match:
            vals = [int(x.strip()) for x in r2_match.group(1).split(',')]
            round_bits[2].extend([math.log2(v) if v > 0 else 0 for v in vals])
            round_raw[2].extend(vals)

        # Round 3 (List)
        r3_match = re.search(r"Round 3 Candidates \(per half\): \[(.*?)\]", block)
        if r3_match:
            vals = [int(x.strip()) for x in r3_match.group(1).split(',')]
            round_bits[3].extend([math.log2(v) if v > 0 else 0 for v in vals])

        # Round 4~8 (Single Value)
        for r in range(4, 9):
            match = re.search(f"Round {r} Candidates: (\d+)", block)
            if match:
                val = int(match.group(1))
                round_bits[r].append(math.log2(val) if val > 0 else 0)

                # [Added] Increment count if candidate count is not 1
                if val != 1:
                    non_one_counts[r] += 1

    # --- Print Results ---
    print(f"=== Analysis Results ===")
    print(f"Total Tests: {total_tests}")
    print(f"Unique-key recovery count: {success_count}")
    if total_tests > 0:
        print(f"Unique-key recovery rate: {success_count/total_tests*100:.2f}%")
    print(f"(\"Unique-key recovery\" = Round 8 yields exactly 1 candidate"
          f" AND that candidate is the true MK.)")
    print("-" * 30)

    # The paper's Appendix A.2 predicts the per-nibble / per-group
    # remaining keyspace for rounds 1 and 2 only (before the keyspace
    # collapses in rounds 3-8).  Print those two lines under a header
    # that emphasises which rounds the paper actually predicts.
    print("Appendix A.2 power-of-two prediction (rounds 1, 2 only):")
    for r in (1, 2):
        bits_list = round_bits[r]
        if bits_list:
            avg_bits = np.mean(bits_list)
            print(f"Round {r}: {avg_bits:.4f} bits (approx. 2^{avg_bits:.2f})")
        else:
            print(f"Round {r}: No data")

    # Mean log2 is necessary but not sufficient for "every value is a
    # power of two" — print the per-value histogram so the claim is
    # directly verifiable, and an all-powers-of-two boolean that flips
    # to False as soon as any non-power-of-two value is observed.
    print("")
    print("Per-value histogram (rounds 1, 2) — Appendix A.2 powers-of-two check:")
    for r in (1, 2):
        vals = round_raw[r]
        if not vals:
            print(f"Round {r}: No data")
            continue
        hist = Counter(vals)
        # Sort keys for a deterministic, easy-to-scan output line.
        hist_str = ", ".join(f"{k}: {hist[k]}" for k in sorted(hist.keys()))
        all_pow2 = all(_is_power_of_two(v) for v in vals)
        non_pow2 = sorted({v for v in vals if not _is_power_of_two(v)})
        print(f"Round {r}: {{{hist_str}}}  "
              f"(total {len(vals)}, all powers of two? {all_pow2})")
        if not all_pow2:
            # Surface the offending values so a reviewer can jump
            # straight to them in the raw stats file.
            print(f"         non-power-of-two values observed: {non_pow2}")

    print("-" * 30)
    print("Post-prediction collapse (rounds 3-8, trending to a unique key):")
    for r in range(3, 9):
        bits_list = round_bits[r]
        if bits_list:
            avg_bits = np.mean(bits_list)
            print(f"Round {r}: {avg_bits:.4f} bits (approx. 2^{avg_bits:.2f})")
        else:
            print(f"Round {r}: No data")

    # [Added] Print counts where candidates != 1 for Round 4+
    print("-" * 30)
    print("Count of non-unique candidates (Candidates != 1) for Round 4+:")
    for r in range(4, 9):
        print(f"Round {r}: {non_one_counts[r]}")

if __name__ == "__main__":
    import os, sys
    here = os.path.dirname(os.path.abspath(__file__))
    stats_path = sys.argv[1] if len(sys.argv) > 1 \
        else os.path.join(here, "key_recovery_stats.txt")
    analyze_stats_file(stats_path)
