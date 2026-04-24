"""trail_search_on_baksheesh.py — MILP trail-search for BAKSHEESH: for each (input_diff, output_diff)
pair in this file, enumerate all feasible DDT-consistent trails
and emit unique ones to `{round}r_0x1_solution_output.txt`."""

import gurobipy as gp
from gurobipy import GRB
import sys
import os

# Rounds covered by this artifact.  Override via CLI,
#   python3 trail_search_on_baksheesh.py 4
# or by setting TARGET_ROUNDS below.  Output goes to
#   {round}r_0x1_solution_output.txt in CWD (input diff is hard-coded
#   to a single-bit 0x1 pattern in the input_diff table below).
if len(sys.argv) > 1:
    TARGET_ROUNDS = [int(sys.argv[1])]
else:
    TARGET_ROUNDS = [4, 5]

# Gurobi thread cap.  0 = "let Gurobi choose" (default all cores).
# Override with  NUM_PROC=N  in the environment for deterministic runs.
NUM_PROC = int(os.environ.get("NUM_PROC", 0))

# Gurobi solution-pool cap for the per-pair MILP.  PoolSolutions=2 is
# enough for Sec. 3.1's "single-solution" determination (we only need
# to distinguish "exactly 1" from "≥ 2").  To inspect the full pool
# for a given pair (e.g. enumerate N > 1 for manual review), set
#   POOL_CAP=N  in the environment, e.g.
#   POOL_CAP=100 python3 trail_search_on_baksheesh.py 4
POOL_CAP = int(os.environ.get("POOL_CAP", 2))

# bit-perm
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

# The input_diff table below sweeps all 32 single-bit fault positions
# (bit 0 of every nibble, i.e. nibble 31, 30, …, 1, 0), repeated twice
# for a total of 64 entries that pair 1-to-1 with the 64 entries of
# output_diff[] below.  An earlier revision only swept 16 even-nibble
# positions on a mirror-symmetry argument; the sweep is now exhaustive
# over all nibble positions (odd and even alike) so the Sec. 3.1 claim
# does not rely on any structural-equivalence assumption between
# mirrored positions.
#
# Ordering: nibbles 31, 30, 29, …, 1, 0 twice; each nibble position
# therefore gets 2 independent output-difference samples drawn from
# the committed 64-entry output_diff[] list.  2 samples per position
# is enough to confirm single-solution trails are plentiful at every
# position; a reviewer who wants more samples per position can lift
# the `* 2` factor (and extend output_diff[] correspondingly).
input_diff = [(1 << (4 * i)) for i in range(31, -1, -1)] * 2

output_diff =[
    0xEA3B649C7513117DBB6B9F3FF61BBD6B,
    0xC7A85A140B314B0D329D590B13D585B5,
    0xCE85E57634255932409159D2F1F37BBD,
    0x1825042B808A018B468581C7230A0461,
    0x39FE03F9C8D7401E22E36475E379AC83,
    0x288F11B810E7239FB77F57A0D5118F79,
    0x57B0F133D8B3AC015C157C88F426B7E2,
    0xEF2D3AADCECBF5B2FCFAB40D8CCC111A,
    0xF03CF4EE07E8333E1C5F231E5810F590,
    0x63E0B3313D11E00DDC904000C604B2E7,
    0xC200D72A5694741CC1DAFF9EF1E210D3,
    0x27C57CDE92193CF4A898EF0A9666BDF1,
    0xC00195E114005E698B0216C110CFF7F9,
    0x45070643AB0AA309485D0810262E8C82,
    0xDC94F8149E5E2212F7200231512963B0,
    0x18FCAEC5B6A730D89AB0B1E6BCBDC457,
    0x8EEFF9BD4437D5691C89D991D890967F,
    0xA222128A525581D28962E08945313154,
    0xDB253ED5409FFE7F0E2675BB391E6EBB,
    0x4A881A80755445C012822062D1502131,
    0x15055156628A286961454805AA2A0A92,
    0x225377129AB833B94D998D1826828EA4,
    0x48983ACCBF21A4E63A74D04EF207663A,
    0xB72CBB5B15AC8FB16C77E7AA15235AE3,
    0xBA95BFBF494D8A1FA50E06201D6B2A7E,
    0x3AC3FB0EA377CFC25BBF93CBE194223C,
    0xFF43852C816166B42311BB9FFFD695CF,
    0x9223C988D940517468EE383A42651391,
    0x91B3B7855FC171A8A361B982E650F62B,
    0x96099D8C27A4C647785260239923320C,
    0xC86920F1D46004339482A081B09313A6,
    0x2E175036319708368B0C54D0C769048D,
    0x1FAB1197FA3A637498D733579FD010D7,
    0x0397011449E288AA4C3C4414122C0022,
    0x9270FBC8F99E572D10F3BF16F0BA7D84,
    0x5087A3419AA359A91C7A2959629580AE,
    0x90C898090266945CC331028609996841,
    0x49F672CEEE7A687049EDACB9335947FA,
    0x848BFD7A75BC1A3D0574323A3D74099F,
    0xE420BCDD7A3654AEE5D10737FA013A9B,
    0xE42AFFEC298936B394633DE280A4B735,
    0xB485704B53AB602EAABCA174AD6A6CCB,
    0x2B475F07C7CBC56A3764CA1869EA6716,
    0x415510158A88A28A441544542A00A222,
    0x4B9436D33417609E7BF18921D2A5FB75,
    0x62E04B57A8CA5D9099D1A768E4A62DC4,
    0x326E644E35C1101D3817F8005DDF184B,
    0x7003C703C21258CA79F0E82014B046EA,
    0x81B14D918F0791B66604193907657FFE,
    0x4535CE6960DB8ED3C907907BFF4E4C3A,
    0x040153D0487F21C8C18C6264305D13B0,
    0x4B7C6E98866E8E30D1D8258E09379A26,
    0xE03448832896E0F84EE10036E36C10F1,
    0x37035A70872902BF1F42C98C66ACAEAC,
    0x46FD1A5CA354A8E4C0B19E52A033A7B9,
    0x8892AA38018595806068C8E235212551,
    0xA293064605AB2E630AFCD81D48442588,
    0x14E9B2BFDA21826A6C2229B73ED7743F,
    0x5202C132B186E3A49D4E64C2642E74CC,
    0x7BE36EA3AB70D1FAA47CBADDD00C645A,
    0x03D99B412B8A2884136738000BB23E22,
    0x9C9E1FBE815BE43030ED5DF3BFE49DD0,
    0x49093226831E9205938001000F422400,
    0x407D6045A01AC600C0E797C158195262,
]

NUM_PAIRS = 64

for TARGET_ROUND in TARGET_ROUNDS:
 # truncate the per-round output at the start of each round so that
 # repeated script runs do not accumulate stale trails on top of the
 # fresh MILP output
 open(f"{TARGET_ROUND}r_0x1_solution_output.txt", "w").close()
 for pair_idx in range(NUM_PAIRS):
    INPUT_DIFF = input_diff[pair_idx]
    OUTPUT_DIFF = output_diff[pair_idx]

    Env = gp.Env('gurobi.log')
    Env.setParam(GRB.Param.Threads, NUM_PROC)
    Env.setParam(GRB.Param.OutputFlag, 0)   # silence the per-pair Gurobi log

    baksheesh_diff = gp.Model("baksheesh_diff", env = Env)

    WORDSIZE = 4

    # Init. GUROBI VAR.
    X=[[] for i in range(TARGET_ROUND+1)]
    Y=[[] for i in range(TARGET_ROUND)]

    for round_idx in range(TARGET_ROUND+1):
        for idx in range(128):
            X[round_idx].append(baksheesh_diff.addVar(0,1,0,vtype=GRB.BINARY,name="X_%d_%d"%(idx,round_idx)))
    for round_idx in range(TARGET_ROUND):
        for idx in range(128):
            Y[round_idx].append(baksheesh_diff.addVar(0,1,0,vtype=GRB.BINARY,name="Y_%d_%d"%(idx,round_idx)))

    #Input, Output Constraint
    for idx in range(128):
        i=(INPUT_DIFF>>idx)&0x1
        baksheesh_diff.addConstr(X[0][idx]==i)
        j=(OUTPUT_DIFF>>idx)&0x1
        baksheesh_diff.addConstr(X[TARGET_ROUND][idx]==j)

    #addConstraint
    for round_idx in range(TARGET_ROUND):
        # ================================================================
        # S-box DDT constraints — 26 linear inequalities modelling
        # "(a, b) is a valid input→output difference through the BAKSHEESH
        # S-box" ⇔ DDT[a][b] > 0.  The inequality set is the minimal
        # cover of the valid-transition bit-vectors obtained by feeding
        # the DDT truth table into Espresso (Espresso.exe, the two-level
        # logic minimiser) — see README "DDT-to-inequalities pipeline"
        # for the exact invocation.  See paper Sec. 3.1 for the MIFA
        # formulation this implements; verified exhaustively over all
        # 256 (a,b) nibble pairs to accept exactly DDT[a][b] > 0.
        # ================================================================
        for sbox_idx in range(32):
            a = [X[round_idx][4*sbox_idx], X[round_idx][4*sbox_idx+1], X[round_idx][4*sbox_idx+2], X[round_idx][4*sbox_idx+3]]
            b = [Y[round_idx][4*sbox_idx], Y[round_idx][4*sbox_idx+1], Y[round_idx][4*sbox_idx+2], Y[round_idx][4*sbox_idx+3]]

            baksheesh_diff.addConstr( a[3] - b[2] - b[1] - b[0] >= -2)
            baksheesh_diff.addConstr(- a[3] + b[2] - b[1] - b[0] >= -2)
            baksheesh_diff.addConstr(- a[3] - b[2] + b[1] - b[0] >= -2)
            baksheesh_diff.addConstr(a[3] + b[2] + b[1] - b[0] >= 0)
            baksheesh_diff.addConstr(- a[3] - b[2] - b[1] + b[0] >= -2)
            baksheesh_diff.addConstr(a[3] + b[2] - b[1] + b[0] >= 0)
            baksheesh_diff.addConstr(a[3] - b[2] + b[1] + b[0] >= 0)
            baksheesh_diff.addConstr(- a[3] + b[2] + b[1] + b[0] >= 0)
            baksheesh_diff.addConstr(- a[3] - a[2] - a[1] + a[0] - b[3] >= -3)
            baksheesh_diff.addConstr(a[3] + a[2] + a[1] + a[0] - b[3] >= 0)
            baksheesh_diff.addConstr(a[3] - a[2] - a[1] + a[0] + b[3] >= -1)
            baksheesh_diff.addConstr(- a[2] + a[1] - a[0] - b[3] - b[2] >= -3)
            baksheesh_diff.addConstr(a[2] + a[1] + a[0] + b[3] - b[2] >= 0)
            baksheesh_diff.addConstr(- a[2] + a[1] - a[0] + b[3] + b[2] >= -1)
            baksheesh_diff.addConstr(- a[3] + a[2] + a[1] - a[0] - b[1] >= -2)
            baksheesh_diff.addConstr(- a[2] - a[1] - a[0] - b[3] - b[1] >= -4)
            baksheesh_diff.addConstr(a[2] - a[1] + a[0] - b[2] - b[1] >= -2)
            baksheesh_diff.addConstr(a[3] + a[2] + a[1] - a[0] + b[1] >= 0)
            baksheesh_diff.addConstr(- a[2] - a[1] - a[0] + b[3] + b[1] >= -2)
            baksheesh_diff.addConstr(a[2] - a[1] + a[0] + b[2] + b[1] >= 0)
            baksheesh_diff.addConstr(- a[2] + a[1] + a[0] - b[3] - b[0] >= -2)
            baksheesh_diff.addConstr(a[2] + a[1] + a[0] + b[2] - b[0] >= 0)
            baksheesh_diff.addConstr(a[2] - a[1] - a[0] - b[1] - b[0] >= -3)
            baksheesh_diff.addConstr(- a[3] + a[2] + a[1] + a[0] + b[0] >= 0)
            baksheesh_diff.addConstr(- a[2] + a[1] + a[0] + b[3] + b[0] >= 0)
            baksheesh_diff.addConstr(a[2] - a[1] - a[0] + b[1] + b[0] >= -1)

        #Modeling for bit-perm
        for idx in range(128):
            baksheesh_diff.addConstr(Y[round_idx][idx]==X[round_idx+1][bit_perm[idx]])

    #start optimize!!
    baksheesh_diff.setParam(GRB.Param.PoolSearchMode, 2)  # enumerate every feasible solution
    # PoolSolutions — we only need to distinguish "exactly 1" from
    # "≥ 2" for Sec. 3.1's single-solution determination; see the
    # DEFAULT sibling for the full rationale.  Override via the
    # POOL_CAP env var to inspect the full pool for a given pair.
    baksheesh_diff.setParam(GRB.Param.PoolSolutions, POOL_CAP)
    baksheesh_diff.optimize()

    # Always write a record per (input_diff, output_diff) pair so that
    # reviewers can see the full sweep outcome — INFEASIBLE pairs are
    # informative too (they say "no single-bit fault works here").
    status_name = {
        GRB.OPTIMAL:     "OPTIMAL",
        GRB.INFEASIBLE:  "INFEASIBLE",
        GRB.INF_OR_UNBD: "INF_OR_UNBD",
        GRB.UNBOUNDED:   "UNBOUNDED",
        GRB.TIME_LIMIT:  "TIME_LIMIT",
        GRB.INTERRUPTED: "INTERRUPTED",
        GRB.SUBOPTIMAL:  "SUBOPTIMAL",
    }.get(baksheesh_diff.Status, f"STATUS_{baksheesh_diff.Status}")

    if baksheesh_diff.Status in (GRB.OPTIMAL, GRB.INTERRUPTED, GRB.SUBOPTIMAL):
        num_solutions = baksheesh_diff.SolCount
        with open(f"{TARGET_ROUND}r_0x1_solution_output.txt", "a") as f:
            f.write(f"Number of solutions found: {num_solutions}\n")
            # Only when exactly one trail exists do we emit the trail —
            # paper Sec. 3.1's claim is about single-solution trails.
            if num_solutions == 1:
                for sol_num in range(num_solutions):
                    baksheesh_diff.setParam(GRB.Param.SolutionNumber, sol_num)
                    f.write(f"\n--- Solution {sol_num+1} ---\n")
                    for round_idx in range(TARGET_ROUND + 1):
                        bits = ""
                        for idx in range(128):
                            val = int(round(X[round_idx][idx].Xn))
                            bits += str(val)
                        bits = bits[::-1]  # reverse bit order (MSB <-> LSB)
                        hex_nibbles = [format(int(bits[i:i+4], 2), 'X') for i in range(0, 128, 4)]
                        f.write(f"0x{''.join(hex_nibbles)}\n")
                    f.write(f"\n")
    else:
        # Non-optimal outcome — record it so the sweep log is complete.
        with open(f"{TARGET_ROUND}r_0x1_solution_output.txt", "a") as f:
            f.write(f"Number of solutions found: 0 (status={status_name})\n")


