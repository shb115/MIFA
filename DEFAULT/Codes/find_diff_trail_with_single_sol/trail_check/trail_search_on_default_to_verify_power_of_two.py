import gurobipy as gp
from gurobipy import GRB
import sys
import re

# Configuration variables
INPUT_FILE = "8r_0x1_4pair_1000testnum.txt"
OUTPUT_FILE = "8r_0x1_4pair_1000testnum_with_diff_trail.txt"
TARGET_ROUND = 8
INPUT_DIFF = 1
NUM_PROC = 100  # Number of threads (cores) to use

# bit-perm table
bit_perm = [
    0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3, 
    4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7, 
    8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11, 
   12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15, 
   16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19, 
   20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23, 
   24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27, 
   28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31 
]

def parse_input_file(filename):
    """Parses data from the text file and returns it as a list."""
    data_list = []
    
    with open(filename, 'r') as f:
        content = f.read()
        
    # Extract mk, c1, c2, c1^c2 using regex
    pattern = re.compile(r"mk:(0x[0-9A-Fa-f]+)\s+c1:(0x[0-9A-Fa-f]+)\s+c2:(0x[0-9A-Fa-f]+)\s+c1\^c2:(0x[0-9A-Fa-f]+)")
    
    matches = pattern.findall(content)
    for match in matches:
        entry = {
            'mk': match[0],
            'c1': match[1],
            'c2': match[2],
            'output_diff_str': match[3],
            'output_diff_int': int(match[3], 16)
        }
        data_list.append(entry)
        
    return data_list

def solve_milp(target_round, input_diff, output_diff_val):
    """Finds solutions using MILP and returns the result and solution count."""
    try:
        # Gurobi environment setup (disable logging, set number of threads)
        Env = gp.Env(empty=True)
        Env.setParam("OutputFlag", 0) 
        Env.setParam("Threads", NUM_PROC) # Use 100 cores as requested
        Env.start()
        
        model = gp.Model("default_diff", env=Env)
        
        # Init variables
        X = [[] for _ in range(target_round + 1)]
        Y = [[] for _ in range(target_round)]

        for round_idx in range(target_round + 1):
            for idx in range(128):
                X[round_idx].append(model.addVar(vtype=GRB.BINARY, name=f"X_{idx}_{round_idx}"))
        for round_idx in range(target_round):
            for idx in range(128):
                Y[round_idx].append(model.addVar(vtype=GRB.BINARY, name=f"Y_{idx}_{round_idx}"))

        # Input / Output Constraints
        for idx in range(128):
            i = (input_diff >> idx) & 0x1
            model.addConstr(X[0][idx] == i)
            
            j = (output_diff_val >> idx) & 0x1
            model.addConstr(X[target_round][idx] == j)

        # S-box & Permutation Constraints
        for round_idx in range(target_round):
            # S-box
            for sbox_idx in range(32):
                a = [X[round_idx][4*sbox_idx + k] for k in range(4)]
                b = [Y[round_idx][4*sbox_idx + k] for k in range(4)]
                
                # S-box inequalities
                model.addConstr(a[1] - a[0] - b[2] + b[1] - b[0] >= -2)
                model.addConstr(a[0] + b[3] + b[2] - b[1] >= 0)
                model.addConstr(- a[3] - a[2] - a[1] - a[0] - b[1] >= -4)
                model.addConstr(a[3] - a[2] - a[1] + b[3] + b[1] >= -1)
                model.addConstr(a[3] + a[2] - b[3] + b[2] - b[1] >= -1)
                model.addConstr(a[3] + a[2] + a[1] - b[2] >= 0)
                model.addConstr(a[3] + a[2] - a[1] + b[2] >= 0)
                model.addConstr(a[3] + b[3] + b[1] - b[0] >= 0)
                model.addConstr(a[3] - a[0] + b[2] + b[0] >= 0)
                model.addConstr(- a[0] - b[3] - b[2] + b[1] >= -2)
                model.addConstr(a[0] - b[3] + b[2] + b[1] >= 0)
                model.addConstr(- a[3] + a[2] - a[1] - b[2] >= -2)
                model.addConstr(- a[3] + a[2] + a[1] + b[2] >= 0)
                model.addConstr(- a[3] + b[3] + b[1] + b[0] >= 0)
                model.addConstr(- a[2] + a[1] - a[0] - b[0] >= -2)
                model.addConstr(- a[3] - b[3] - b[1] + b[0] >= -2)
                model.addConstr(- a[3] + a[0] - b[2] - b[0] >= -2)
                model.addConstr(- a[2] - a[1] + a[0] - b[0] >= -2)
                model.addConstr(- a[0] + b[3] - b[2] - b[1] >= -2)
                model.addConstr(- a[2] + a[1] + a[0] + b[0] >= 0)
                model.addConstr(a[3] + a[0] - b[2] + b[0] >= 0)
                model.addConstr(a[3] - b[3] - b[1] - b[0] >= -2)
                model.addConstr(- a[3] - a[0] + b[2] - b[0] >= -2)
                model.addConstr(- a[2] - a[1] - a[0] + b[0] >= -2)

            # Bit Permutation
            for idx in range(128):
                model.addConstr(Y[round_idx][idx] == X[round_idx+1][bit_perm[idx]])

        # Optimize
        model.setParam(GRB.Param.PoolSearchMode, 2)
        model.setParam(GRB.Param.PoolSolutions, 2000) 
        model.optimize()
        
        solutions = []
        if model.Status == GRB.OPTIMAL:
            count = model.SolCount
            if count == 1: # Extract detailed info only if it is a unique solution
                model.setParam(GRB.Param.SolutionNumber, 0)
                sol_trace = []
                for r_idx in range(target_round + 1):
                    bits = ""
                    for idx in range(128):
                        val = int(round(X[r_idx][idx].Xn))
                        bits += str(val)
                    bits = bits[::-1] 
                    hex_val = "".join([format(int(bits[i:i+4], 2), 'X') for i in range(0, 128, 4)])
                    sol_trace.append(f"X_{r_idx} = {hex_val}")
                solutions = sol_trace
            return count, solutions
        else:
            return 0, []
            
    except gp.GurobiError as e:
        print(f"Error code {e.errno}: {e}")
        return 0, []
    except AttributeError:
        print("Encountered an attribute error")
        return 0, []

def main():
    print(f"Reading {INPUT_FILE}...")
    data_list = parse_input_file(INPUT_FILE)
    print(f"Total entries found: {len(data_list)}")
    
    unique_count = 0
    
    with open(OUTPUT_FILE, 'w') as f_out:
        for idx, entry in enumerate(data_list):
            print(f"[{idx+1}/{len(data_list)}] Solving for output diff: {entry['output_diff_str']} ...", end=" ", flush=True)
            
            sol_count, sol_trace = solve_milp(TARGET_ROUND, INPUT_DIFF, entry['output_diff_int'])
            
            print(f"Solutions found: {sol_count}")
            
            if sol_count == 1:
                unique_count += 1
                f_out.write(f"mk: {entry['mk']}\n")
                f_out.write(f"c1: {entry['c1']}\n")
                f_out.write(f"c2: {entry['c2']}\n")
                f_out.write(f"c1^c2: {entry['output_diff_str']}\n")
                f_out.write(f"\nNumber of solutions found: 1\n")
                f_out.write(f"\n--- Solution 1 ---\n")
                for line in sol_trace:
                    f_out.write(f"{line}\n")
                f_out.write("\n" + "="*30 + "\n\n")
                f_out.flush()

    print(f"\nDone. Found {unique_count} unique deterministic trails.")
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()