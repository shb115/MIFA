import gurobipy as gp
from gurobipy import GRB
import sys
import pickle

TEST_NUM = 1
TARGET_ROUND = 8
INPUT_DIFF = 2

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

NUM_PROC = 100

output_diff =[[ 
    0x38C8CECC1CCD237B0F6CBF9FEBD550D0,
    0x919D9CCECC5FFADCD5EFB17985AEAFA7,
    0xC49479EEC820DBC5C4F3A6B4B7183841,
],
[
0x1BA8475CE7EB7B68B66B61E3E633D54A,
0x68B93E9CCF579F454582FDD149A34035,
0xE58C9DB948AF630C2711BF8AB15EA794,
],
[
0x2B8C46F9A268A5A1B3F4E17885944086,
0x4AEA7BC5CC9429A1678B848C0C97CB1A,
]
]


for OUTPUT_DIFF in output_diff[TARGET_ROUND-6]:

    Env = gp.Env('env')
    Env.setParam(GRB.Param.Threads, NUM_PROC)

    default_diff = gp.Model("default_diff", env = Env)

    WORDSIZE = 4

    # Init. GUROBI VAR.
    X=[[] for i in range(TARGET_ROUND+1)]
    Y=[[] for i in range(TARGET_ROUND)]

    for round_idx in range(TARGET_ROUND+1):
        for idx in range(128):
            X[round_idx].append(default_diff.addVar(0,1,0,vtype=GRB.BINARY,name="X_%d_%d"%(idx,round_idx)))
    for round_idx in range(TARGET_ROUND):
        for idx in range(128):
            Y[round_idx].append(default_diff.addVar(0,1,0,vtype=GRB.BINARY,name="Y_%d_%d"%(idx,round_idx)))

    #Input, Output Constraint
    for idx in range(128):
        i=(INPUT_DIFF>>idx)&0x1
        default_diff.addConstr(X[0][idx]==i)
        j=(OUTPUT_DIFF>>idx)&0x1
        default_diff.addConstr(X[TARGET_ROUND][idx]==j)

    #addConstraint
    for round_idx in range(TARGET_ROUND):
        #Modeling for sbox
        for sbox_idx in range(32):
            a = [X[round_idx][4*sbox_idx], X[round_idx][4*sbox_idx+1], X[round_idx][4*sbox_idx+2], X[round_idx][4*sbox_idx+3]]
            b = [Y[round_idx][4*sbox_idx], Y[round_idx][4*sbox_idx+1], Y[round_idx][4*sbox_idx+2], Y[round_idx][4*sbox_idx+3]]

            default_diff.addConstr(a[1] - a[0] - b[2] + b[1] - b[0] >= -2)
            default_diff.addConstr(a[0] + b[3] + b[2] - b[1] >= 0)
            default_diff.addConstr(- a[3] - a[2] - a[1] - a[0] - b[1] >= -4)
            default_diff.addConstr(a[3] - a[2] - a[1] + b[3] + b[1] >= -1)
            default_diff.addConstr(a[3] + a[2] - b[3] + b[2] - b[1] >= -1)
            default_diff.addConstr(a[3] + a[2] + a[1] - b[2] >= 0)
            default_diff.addConstr(a[3] + a[2] - a[1] + b[2] >= 0)
            default_diff.addConstr(a[3] + b[3] + b[1] - b[0] >= 0)
            default_diff.addConstr(a[3] - a[0] + b[2] + b[0] >= 0)
            default_diff.addConstr(- a[0] - b[3] - b[2] + b[1] >= -2)
            default_diff.addConstr(a[0] - b[3] + b[2] + b[1] >= 0)
            default_diff.addConstr(- a[3] + a[2] - a[1] - b[2] >= -2)
            default_diff.addConstr(- a[3] + a[2] + a[1] + b[2] >= 0)
            default_diff.addConstr(- a[3] + b[3] + b[1] + b[0] >= 0)
            default_diff.addConstr(- a[2] + a[1] - a[0] - b[0] >= -2)
            default_diff.addConstr(- a[3] - b[3] - b[1] + b[0] >= -2)
            default_diff.addConstr(- a[3] + a[0] - b[2] - b[0] >= -2)
            default_diff.addConstr(- a[2] - a[1] + a[0] - b[0] >= -2)
            default_diff.addConstr(- a[0] + b[3] - b[2] - b[1] >= -2)
            default_diff.addConstr(- a[2] + a[1] + a[0] + b[0] >= 0)
            default_diff.addConstr(a[3] + a[0] - b[2] + b[0] >= 0)
            default_diff.addConstr(a[3] - b[3] - b[1] - b[0] >= -2)
            default_diff.addConstr(- a[3] - a[0] + b[2] - b[0] >= -2)
            default_diff.addConstr(- a[2] - a[1] - a[0] + b[0] >= -2)

        #Modeling for bit-perm
        for idx in range(128):
            default_diff.addConstr(Y[round_idx][idx]==X[round_idx+1][bit_perm[idx]])

    #start optimize!!
    default_diff.setParam(GRB.Param.PoolSearchMode, 2)  # Search for all possible solutions
    default_diff.optimize()

    if default_diff.Status == GRB.OPTIMAL or default_diff.Status == GRB.INTERRUPTED or default_diff.Status == GRB.SUBOPTIMAL:
        num_solutions = default_diff.SolCount
        with open(f"{TARGET_ROUND}r_0x2_solution_output.txt", "a") as f:
            f.write(f"Number of solutions found: {num_solutions}\n")
            for sol_num in range(num_solutions):
                default_diff.setParam(GRB.Param.SolutionNumber, sol_num)
                f.write(f"\n--- Solution {sol_num+1} ---\n")
                for round_idx in range(TARGET_ROUND + 1):
                    bits = ""
                    for idx in range(128):
                        val = int(round(X[round_idx][idx].Xn))
                        bits += str(val)
                    bits = bits[::-1]  # Reverse bit order (MSB <-> LSB)
                    hex_nibbles = [format(int(bits[i:i+4], 2), 'X') for i in range(0, 128, 4)]
                    f.write(f"0x{''.join(hex_nibbles)}\n")