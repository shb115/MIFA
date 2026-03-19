import time
from itertools import product

# --- Function Definitions (Same as before) ---
# Given S-box
sbox = [0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9,
        0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5]

# Given bit permutation
default_bit_perm = [
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
        perm_bits[default_bit_perm[bit]] = state_bits[bit]
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
# --- End of Function Definitions ---


def calculate_expected_other_active_nibbles(round_results, round_name):
    """
    Calculates and prints the expected number of active nibbles in the round results
    that are NOT in the set {0, 6, 9, 0xf}.
    """
    # Excluded group (0 is not an active nibble, so it's naturally excluded from active count,
    # but listed here for clarity as per the logic requested)
    excluded_group = {0, 6, 9, 0xf}
    
    expected_count = 0.0
    
    # Iterate over each possible pattern and its probability
    for pattern, prob in round_results:
        # Count nibbles in the current pattern that meet the condition
        count_in_pattern = 0
        for nibble_value in pattern:
            if nibble_value not in excluded_group:
                count_in_pattern += 1
        
        # Add (count in pattern * probability of pattern) to total expectation
        expected_count += count_in_pattern * prob
    
    print(f"--- {round_name} ---")
    print(f"  Expected number of active nibbles NOT in '{excluded_group}': {expected_count:.8f}\n")
    return expected_count


# --- Main Analysis Logic for p=0x1 ---
print("### Starting Round-by-Round Analysis for p=0x1 ###\n")

# Input difference
p = 0x1

# Start with initial difference pattern and probability 1.0
p_n_prob = [(to_nibbles(p), 1.0)]

# --- Round 5 Analysis ---
r5 = all_output_patterns(p_n_prob, sbox)
r5_perm = [(perm(pat), pr) for pat, pr in r5]
calculate_expected_other_active_nibbles(r5_perm, "Round 5 Output (r5_perm)")

# --- Round 4 Analysis ---
r4 = all_output_patterns(r5_perm, sbox)
r4_perm = [(perm(pat), pr) for pat, pr in r4]
calculate_expected_other_active_nibbles(r4_perm, "Round 4 Output (r4_perm)")

# --- Round 3 Analysis ---
r3 = all_output_patterns(r4_perm, sbox)
r3_perm = [(perm(pat), pr) for pat, pr in r3]
calculate_expected_other_active_nibbles(r3_perm, "Round 3 Output (r3_perm)")

# --- Round 2 Analysis ---
r2 = all_output_patterns(r3_perm, sbox)
r2_perm = [(perm(pat), pr) for pat, pr in r2]
calculate_expected_other_active_nibbles(r2_perm, "Round 2 Output (r2_perm)")