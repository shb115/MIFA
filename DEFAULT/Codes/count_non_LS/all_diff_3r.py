import time
import os
import psutil  # Import for checking memory usage
from itertools import product
import gc

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

def calculate_target_group_sum(round_results):
    expected_counts = [0.0] * 16
    for pattern, prob in round_results:
        for nibble_value in pattern:
            expected_counts[nibble_value] += prob
    target_group = {0, 6, 9, 0xf}
    target_sum = sum(expected_counts[v] for v in target_group)
    return target_sum

# --- Main Analysis Loop (Modified to 3 Rounds) ---
print("### Starting 3-Round Analysis and Automatic Analysis for All p ###")
print("Limiting memory usage to 30GB.")

# --- Settings ---
MEMORY_LIMIT_GB = 30
MEMORY_LIMIT_BYTES = MEMORY_LIMIT_GB * 1024**3
process = psutil.Process(os.getpid())
skipped_p_values = []
results = []
total_start_time = time.time()

for i in range(128):
    p = 1 << i
    print(f"\n[{i+1}/128] Analyzing p = 0x{p:x}...")
    
    try:
        # Perform 3-round simulation for each p
        p_n_prob = [(to_nibbles(p), 1.0)]

        # --- Round 5 ---
        r5 = all_output_patterns(p_n_prob, sbox)
        r5_perm = [(perm(pat), pr) for pat, pr in r5]
        if process.memory_info().rss > MEMORY_LIMIT_BYTES:
            raise MemoryError("RAM limit exceeded after Round 5")

        # --- Round 4 ---
        r4 = all_output_patterns(r5_perm, sbox)
        r4_perm = [(perm(pat), pr) for pat, pr in r4]
        if process.memory_info().rss > MEMORY_LIMIT_BYTES:
            raise MemoryError("RAM limit exceeded after Round 4")

        # --- Round 3 ---
        r3 = all_output_patterns(r4_perm, sbox)
        r3_perm = [(perm(pat), pr) for pat, pr in r3]
        if process.memory_info().rss > MEMORY_LIMIT_BYTES:
            raise MemoryError("RAM limit exceeded after Round 3")
        
        # --- Integrate and analyze 3-round results ---
        all_rounds_combined = r5_perm + r4_perm + r3_perm
        target_sum = calculate_target_group_sum(all_rounds_combined)
        results.append({'p': p, 'sum': target_sum})
        print(f"  -> Done. Target group expectation sum: {target_sum:.6f}")

    except MemoryError as e:
        mem_usage_gb = process.memory_info().rss / 1024**3
        print(f"  -> Memory limit exceeded ({mem_usage_gb:.2f}GB). Skipping to next p. (Details: {e})")
        skipped_p_values.append(p)
        # Clean up memory
        del p_n_prob
        if 'r5' in locals(): del r5
        if 'r5_perm' in locals(): del r5_perm
        if 'r4' in locals(): del r4
        if 'r4_perm' in locals(): del r4_perm
        if 'r3' in locals(): del r3
        if 'r3_perm' in locals(): del r3_perm
        gc.collect()
        continue

print(f"\n--- All analyses completed (Total time: {time.time() - total_start_time:.2f}s) ---")

# Sort results by 'sum' in ascending order
results.sort(key=lambda x: x['sum'])

# Final Results: Rank all by 'Other' group sum (Descending)
print("\n### Final Results: Ranking of Expectation Sum for 'Non-{0,6,9,f}' Group (3-Round) ###")
if results:
    TOTAL_EXPECTATION = 96.0  # 3 rounds * 32 nibbles
    for i, res in enumerate(results):
        p_val = res['p']
        target_sum_val = res['sum']
        # Calculate sum for 'Other' group
        other_sum_val = TOTAL_EXPECTATION - target_sum_val
        
        # Print rank, p-value, and sums based on 'Other' group sum
        print(f" Rank {i+1:>3}: p = 0x{p_val:<32x} | 'Other' Group Sum: {other_sum_val:.8f} ('0,6,9,f' Group Sum: {target_sum_val:.8f})")
else:
    print("No p-values were successfully analyzed, so ranking cannot be generated.")

# --- Print p-values that were skipped due to memory limit ---
if skipped_p_values:
    print("\n### p-values skipped due to memory limit (30GB) ###")
    for p_val in skipped_p_values:
        print(f"  - 0x{p_val:x}")
else:
    print("\nAll p-values analyzed successfully (No memory limit exceeded)")