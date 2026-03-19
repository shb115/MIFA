import re
import math
import numpy as np

def analyze_stats_file(filename):
    print(f"Analyzing {filename}...\n")
    
    with open(filename, 'r') as f:
        content = f.read()

    # Split test cases
    blocks = content.split('------------------------------')
    
    total_tests = 0
    success_count = 0
    
    # Data storage
    # round_bits[r] = [log2(c1), log2(c2), ...] : Store bit length of candidate counts
    round_bits = {i: [] for i in range(1, 9)}
    
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
            
        # Round 2 (List)
        r2_match = re.search(r"Round 2 Candidates \(per group\): \[(.*?)\]", block)
        if r2_match:
            vals = [int(x.strip()) for x in r2_match.group(1).split(',')]
            round_bits[2].extend([math.log2(v) if v > 0 else 0 for v in vals])

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
    print(f"Success Count: {success_count}")
    if total_tests > 0:
        print(f"Success Rate: {success_count/total_tests*100:.2f}%")
    print("-" * 30)
    
    print("Average Remaining Entropy (Average of log2(candidates)):")
    for r in range(1, 9):
        bits_list = round_bits[r]
        if bits_list:
            avg_bits = np.mean(bits_list)
            # Print exponent format (2^k) as often used in papers
            print(f"Round {r}: {avg_bits:.4f} bits (approx. 2^{avg_bits:.2f})")
        else:
            print(f"Round {r}: No data")
            
    # [Added] Print counts where candidates != 1 for Round 4+
    print("-" * 30)
    print("Count of non-unique candidates (Candidates != 1) for Round 4+:")
    for r in range(4, 9):
        print(f"Round {r}: {non_one_counts[r]}")

if __name__ == "__main__":
    analyze_stats_file("key_recovery_stats.txt")