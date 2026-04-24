"""0x8_diff_check.py — Per-round analysis of BAKSHEESH under input difference p = 0x8."""

from itertools import product

# (same S-box, perm, to_nibbles, all_output_patterns as the sibling scripts)
# --- Shared definitions begin ---
# BAKSHEESH S-box
sbox = [0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe,
        0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1]

# Bit permutation
baksheesh_bit_perm = [
     0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
     4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
     8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
    12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
    16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
    20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
    24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
    28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
]

def perm(msg):
    state_bits = [0] * 128
    for nibble in range(32):
        for bit in range(4):
            state_bits[4 * nibble + bit] = (msg[nibble] >> bit) & 0x1
    perm_bits = [0] * 128
    for bit in range(128):
        perm_bits[baksheesh_bit_perm[bit]] = state_bits[bit]
    cip = [0] * 32
    for nibble in range(32):
        for bit in range(4):
            cip[nibble] ^= perm_bits[4 * nibble + bit] << bit
    return cip

def to_nibbles(val):
    return [(val >> (4 * i)) & 0xF for i in range(32)]

def all_output_patterns(patterns_with_probs, sbox):
    N = len(sbox)
    ddt = [[0]*N for _ in range(N)]
    for dx in range(N):
        for x in range(N):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    aggregated_outputs = {}
    for dx_arr, prob_in in patterns_with_probs:
        per_pos = []
        for dx in dx_arr:
            if dx == 0:
                per_pos.append([(0, 1.0)])
            else:
                row = ddt[dx]
                possible_dys = [(dy, count / N) for dy, count in enumerate(row) if count > 0]
                per_pos.append(possible_dys)
        for combo in product(*per_pos):
            output_pattern = tuple(item[0] for item in combo)
            prob_sbox_layer = 1.0
            for item in combo:
                prob_sbox_layer *= item[1]
            total_prob = prob_in * prob_sbox_layer
            aggregated_outputs[output_pattern] = aggregated_outputs.get(output_pattern, 0) + total_prob
    return [(list(p), pr) for p, pr in aggregated_outputs.items()]
# --- Shared definitions end ---


def calculate_expected_other_active_nibbles(round_results, round_name):
    """
    From a per-round result, compute the expected number of active nibbles
    whose value is NOT in {0, 8} (the non-LS group).
    """
    excluded_group = {0, 8}

    expected_count = 0.0

    # iterate over every possible pattern and its probability
    for pattern, prob in round_results:
        # count the nibbles in this pattern that match the condition
        count_in_pattern = 0
        for nibble_value in pattern:
            if nibble_value not in excluded_group:
                count_in_pattern += 1

        # accumulate (count * probability)
        expected_count += count_in_pattern * prob

    print(f"--- {round_name} ---")
    print(f"  expected number of active nibbles NOT in {excluded_group}: {expected_count:.8f}\n")
    return expected_count


# --- main analysis for p = 0x8 ---
print("### Per-round analysis for p = 0x8 ###\n")

# NOTE on round depth: this script iterates 3 rounds (r5 → r4 → r3)
# whereas the `0x4_diff_check.py` sibling iterates 4 rounds (adding r2).
# For fault pattern 0x8 the per-round expansion of the active-nibble
# set blows up past a practical memory budget before round 2 is
# reached; use `all_diff_check_2r.py` (which enforces a memory cap)
# for round-2 stats across all single-bit fault patterns.

# input difference
p = 0x8

# start with the initial difference pattern at probability 1.0
p_n_prob = [(to_nibbles(p), 1.0)]

# --- Round 5 ---
r5 = all_output_patterns(p_n_prob, sbox)
r5_perm = [(perm(pat), pr) for pat, pr in r5]
calculate_expected_other_active_nibbles(r5_perm, "Round-5 output (r5_perm)")

# --- Round 4 ---
r4 = all_output_patterns(r5_perm, sbox)
r4_perm = [(perm(pat), pr) for pat, pr in r4]
calculate_expected_other_active_nibbles(r4_perm, "Round-4 output (r4_perm)")

# --- Round 3 ---
r3 = all_output_patterns(r4_perm, sbox)
r3_perm = [(perm(pat), pr) for pat, pr in r3]
calculate_expected_other_active_nibbles(r3_perm, "Round-3 output (r3_perm)")
