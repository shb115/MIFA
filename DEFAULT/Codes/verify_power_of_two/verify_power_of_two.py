from itertools import product
import time
import re
import sys
from typing import List

# ==========================================
# 1. Original Logic (Helpers & Attack Functions)
# ==========================================

# Given S-box
sbox = [0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9,
        0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5]

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

default_rc = [
    1, 3, 7, 15, 31, 62, 61, 59, 55, 47, 30, 60, 57, 51,
    39, 14, 29, 58, 53, 43, 22, 44, 24, 48, 33, 2, 5, 11
]

# Initialize Inverse S-box
inv_sbox_table = [0] * 16

# Construct Inverse Transformation
for i in range(16):
    inv_sbox_table[sbox[i]] = i

# Generate Inverse Permutation
inv_perm_table = [0] * 128
for i, j in enumerate(default_bit_perm):
    inv_perm_table[j] = i

def inv_sbox(msg):
    cip = [0 for i in range(32)]
    # replacing nibble values of state with sbox values
    for nibble_idx, nibble in enumerate(msg):
        cip[nibble_idx] = inv_sbox_table[nibble]
    
    return cip 

def inv_perm(msg):
    # storing the state values into bits
    state_bits = [0 for i in range(128)]
    for nibble in range(32):
        for bit in range(4):
            state_bits[4 * nibble + bit] = (msg[nibble] >> bit) & 0x1

    # permute the bits
    perm_bits = [0 for i in range(128)]
    for bit in range(128):
        perm_bits[inv_perm_table[bit]] = state_bits[bit]

    # making cip from permute bits
    cip = [0 for i in range(32)]
    for nibble in range(32):
        cip[nibble] = 0
        for bit in range(4):
            cip[nibble] ^= perm_bits[4 * nibble + bit] << bit

    return cip

def default_rc_add(s: List[int], r: int) -> List[int]:
    s = s.copy()
    rc = default_rc[r]
    
    # Extract each bit
    c5 = (rc >> 5) & 1  # bit 5
    c4 = (rc >> 4) & 1
    c3 = (rc >> 3) & 1
    c2 = (rc >> 2) & 1
    c1 = (rc >> 1) & 1
    c0 = rc & 1

    # Bit indices based on C code
    bit_indices = [127, 23, 19, 15, 11, 7, 3]
    values =      [1,   c5, c4, c3, c2, c1, c0]

    for bit_index, val in zip(bit_indices, values):
        nibble_index = bit_index // 4
        bit_pos = bit_index % 4  # 0 = LSB, 3 = MSB
        s[nibble_index] ^= (val << bit_pos)
    
    return s

def attack_r1(target_diff, c1, c2, r1_keyspace):
    dec_c1 = default_rc_add(c1,7)
    dec_c2 = default_rc_add(c2,7)
    dec_c1 = inv_perm(dec_c1)
    dec_c2 = inv_perm(dec_c2)
    
    for i in range(32):  # Total 128 bits / 4 bits    
        new_keyspace=[]
        for k in r1_keyspace[i]:  # All nibble values            
            u1 = dec_c1[i] ^ k
            u2 = dec_c2[i] ^ k
            #print(hex(u1),hex(u2))
            sbox_diff = inv_sbox_table[u1] ^ inv_sbox_table[u2]
            #print(hex(sbox_diff))
            if sbox_diff == target_diff[i]:
                new_keyspace.append(k)
        r1_keyspace[i]=new_keyspace

    return r1_keyspace

def attack_r2(target_diff,cip, fcip, r1_keyspace,r2_keyspace):
    # giving the group idx for 2nd round
    quotient_idx_list = [i for i in range(8)]

    # making the nibble idx list at round 2 from groups of that round
    for group_idx in quotient_idx_list:
        # making the nibble list of the quotient group from the corresponding group idx
        nibble_idx_list = []
        for bit in range(4):
            nibble_idx_list.append(4*group_idx + bit)
        
        for nibble_idx in nibble_idx_list:
            new_keyspace = []
            for key4 in r2_keyspace[group_idx]:
                # forming the last round key from the group idx
                last_key = [0 for i in range(32)]

                for j in range(4):
                    last_key[group_idx + 8*j] = key4[j]
                
                dec_cip = default_rc_add(cip,7)
                dec_fcip = default_rc_add(fcip,7)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)
                dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                dec_cip = inv_sbox(dec_cip)
                dec_fcip = inv_sbox(dec_fcip)
                dec_cip = default_rc_add(dec_cip,6)
                dec_fcip = default_rc_add(dec_fcip,6)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)

                if ((nibble_idx == 0) or (nibble_idx == 10) or (nibble_idx == 21) or (nibble_idx == 31)):
                    i = last_key[nibble_idx]
                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]
                    # checking whether the input diff is same as the diff in trail or not
                    if(in_diff == target_diff[nibble_idx]):
                        new_keyspace.append(key4)   
                else:
                    for i in r1_keyspace[nibble_idx]:
                        in_diff = inv_sbox_table[dec_cip[nibble_idx]^i] ^ inv_sbox_table[dec_fcip[nibble_idx]^i]
                        # checking whether the input diff is same as the diff in trail or not
                        if(in_diff == target_diff[nibble_idx]):
                            new_keyspace.append(key4)
                            break
            r2_keyspace[group_idx] = new_keyspace
    return r2_keyspace

def attack_r3(target_diff,cip, fcip, r1_keyspace,r2_keyspace,r3_keyspace):
    # making the nibble list from the corresponding group idx
    # nibble_idx_list = [[i for i in range(16)], [i for i in range(16, 32)]]
    nibble_idx_list = [[0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15], [20, 21, 22, 23, 28, 29, 30, 31, 16, 17, 18, 19, 24, 25, 26, 27]] 

    # in the third last group there are only 2 groups, 0 and 1 
    for group_idx_last in [0,1]:
        for nibble_idx in nibble_idx_list[group_idx_last]:
            new_keyspace = []
            # for each key in the key list
            for key in r3_keyspace[group_idx_last]:
                # forming the last round key from the group idx
                last_key = [0 for i in range(32)]
                for group_idx_mid in range(4):
                    for key_0 in range(4):
                        last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_mid][key_0]
                # for qr group 0, 2, 5, 7
                if(nibble_idx in [0, 1, 2, 3, 8, 9, 10, 11, 20, 21, 22, 23, 28, 29, 30, 31]):
                    # last layer
                    dec_cip = default_rc_add(cip,7)
                    dec_fcip = default_rc_add(fcip,7)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    # 2nd last layer                    
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,6)
                    dec_fcip = default_rc_add(dec_fcip,6)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    # 3rd last layer
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,5)
                    dec_fcip = default_rc_add(dec_fcip,5)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    if(group_idx_last == 0):
                        if ((nibble_idx%2) == 0):
                            in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]
                            # for printing purpose
                            if(in_diff == target_diff[nibble_idx]):
                                new_keyspace.append(key)
                        else:
                            for dummy_ele in r1_keyspace[nibble_idx]:
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                if(in_diff == target_diff[nibble_idx]):
                                    new_keyspace.append(key)
                                    break
                    # for nibbles 20, 21, 22, 23, 28, 29, 30, 31
                    else:
                        # for nibbles 21, 23, 29, 31
                        if ((nibble_idx%2) == 1):
                            in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]
                            # for printing purpose
                            if(in_diff == target_diff[nibble_idx]):
                                new_keyspace.append(key)
                        # for nibbles 20, 22, 28, 30
                        else:
                            for dummy_ele in r1_keyspace[nibble_idx]:
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                if(in_diff == target_diff[nibble_idx]):
                                    new_keyspace.append(key)
                                    break
                # for nibble 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27
                if(nibble_idx in [4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19, 24, 25, 26, 27]):
                    eq_key_list = []
                    if(len(r2_keyspace[nibble_idx//4]) > 16):
                        eq_key_list = r2_keyspace[nibble_idx//4].copy()
                    else:
                        eq_key_list.append(r2_keyspace[nibble_idx//4][0])
                    for eq_key in eq_key_list:
                        # last layer
                        dec_cip = default_rc_add(cip,7)
                        dec_fcip = default_rc_add(fcip,7)
                        dec_cip = inv_perm(dec_cip)
                        dec_fcip = inv_perm(dec_fcip)
                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                        dec_cip = inv_sbox(dec_cip)
                        dec_fcip = inv_sbox(dec_fcip)
                        # 2nd last layer
                        dec_cip = default_rc_add(dec_cip,6)
                        dec_fcip = default_rc_add(dec_fcip,6)
                        dec_cip = inv_perm(dec_cip)
                        dec_fcip = inv_perm(dec_fcip)
                        # making mid key from the 0th ele of r2 keyspace
                        mid_key = [0 for i in range(32)]
                        for qr in range(8):
                            for i in range(4):
                                mid_key[qr + 8*i] = r2_keyspace[qr][0][i]
                        for i in range(4):
                            mid_key[nibble_idx//4+8*i] = eq_key[i]
                        dec_cip = [dec_cip^mid_key for dec_cip, mid_key in zip(dec_cip, mid_key)]
                        dec_fcip = [dec_fcip^mid_key for dec_fcip, mid_key in zip(dec_fcip, mid_key)]
                        # 3rd last layer
                        dec_cip = inv_sbox(dec_cip)
                        dec_fcip = inv_sbox(dec_fcip)
                        dec_cip = default_rc_add(dec_cip,5)
                        dec_fcip = default_rc_add(dec_fcip,5)
                        dec_cip = inv_perm(dec_cip)
                        dec_fcip = inv_perm(dec_fcip)
                        flag1 = 1
                        # for the left half nibbles 4, 5, 6, 7, 12, 13, 14, 15, 16,17,18,19,24,25,26,27 
                        if (group_idx_last == 0):
                            # for nibbles 4, 6, 12, 14
                            # flag1 = 0
                            if ((nibble_idx%2) == 0):
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]
                                # for printing purpose
                                if(in_diff == target_diff[nibble_idx]):
                                    new_keyspace.append(key)
                                    flag1 = 0
                                    break
                            # for nibbles 5, 7, 13, 15
                            else:
                                # flag1 is used to break the for loop in r1 dummy list
                                flag1 = 1
                                for dummy_ele in r1_keyspace[nibble_idx]:
                                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                    # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                    if(in_diff == target_diff[nibble_idx]):
                                        new_keyspace.append(key)
                                        flag1 = 0
                                        break
                                if(flag1 == 0):
                                    break
                        else:
                            # for nibbles 17, 19, 25, 27
                            if ((nibble_idx%2) == 1):
                                in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]
                                # for printing purpose
                                if(in_diff == target_diff[nibble_idx]):
                                    new_keyspace.append(key)
                                    flag1 = 0
                                    break
                            else:
                                # for nibbles 16,18,24,26
                                for dummy_ele in r1_keyspace[nibble_idx]:
                                    in_diff = inv_sbox_table[dec_cip[nibble_idx]^dummy_ele] ^ inv_sbox_table[dec_fcip[nibble_idx]^dummy_ele]
                                    # if any of the cls rep satisfies the in diff then the key4 is a possible key
                                    if(in_diff == target_diff[nibble_idx]):
                                        new_keyspace.append(key)
                                        flag1 = 0
                                        break
                                if(flag1 == 0):
                                    break
            r3_keyspace[group_idx_last] = new_keyspace
    return r3_keyspace

def attack_r456(target_diff,cip, fcip, r4_keyspace,round):
    # making the nibble list from the corresponding group idx
    nibble_idx_list = [i for i in range(32)]
    for nibble_idx in nibble_idx_list:        
        # if the diff appears in the nibble idx, then do the following 
        if (target_diff[nibble_idx] != 0):
            new_keyspace = []
            for key in r4_keyspace:
                # forming the last round key from the group idx
                last_key = [0 for i in range(32)]

                for group_idx_last in range(2):
                    for group_idx_mid in range(4):
                        for key_0 in range(4):
                            last_key[group_idx_last + 2*group_idx_mid + 8*key_0] = key[group_idx_last][group_idx_mid][key_0]

                # last layer
                dec_cip = default_rc_add(cip,7)
                dec_fcip = default_rc_add(fcip,7)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)
                dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]
                for r in range(round-2):
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,6-r)
                    dec_fcip = default_rc_add(dec_fcip,6-r)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]
                # 4th last layer
                dec_cip = inv_sbox(dec_cip)
                dec_fcip = inv_sbox(dec_fcip)
                dec_cip = default_rc_add(dec_cip,8-round)
                dec_fcip = default_rc_add(dec_fcip,8-round)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)
                # taking inv sbox table
                in_diff = inv_sbox_table[dec_cip[nibble_idx]^last_key[nibble_idx]] ^ inv_sbox_table[dec_fcip[nibble_idx]^last_key[nibble_idx]]

                # checking whether the input diff is same as the diff in trail or not
                if(in_diff == target_diff[nibble_idx]):
                    new_keyspace.append(key)
            r4_keyspace = new_keyspace
    return r4_keyspace

def to_nibbles(val):
    return [(val >> (4 * i)) & 0xF for i in range(32)]

# ==========================================
# 2. File Parsing & Main Execution
# ==========================================

def parse_deterministic_solutions(filename):
    with open(filename, 'r') as f:
        content = f.read()

    blocks = content.split('==============================')
    tests = {}
    
    # Group by MK (works even without Test Num)
    test_counter = 0

    for block in blocks:
        if not block.strip(): continue

        mk_match = re.search(r"mk:\s*(0x[0-9A-Fa-f]+)", block)
        c1_match = re.search(r"c1:\s*(0x[0-9A-Fa-f]+)", block)
        c2_match = re.search(r"c2:\s*(0x[0-9A-Fa-f]+)", block)
        
        if not (mk_match and c1_match and c2_match): continue
        
        mk_str = mk_match.group(1)
        c1_val = int(c1_match.group(1), 16)
        c2_val = int(c2_match.group(1), 16)
        
        trail = []
        x_lines = re.findall(r"X_\d+\s*=\s*([0-9A-Fa-f]+)", block)
        if len(x_lines) != 9: continue
        for x_str in x_lines: trail.append(int(x_str, 16))

        if mk_str not in tests:
            test_counter += 1
            tests[mk_str] = {'id': test_counter, 'mk': mk_str, 'pairs': []}
            
        tests[mk_str]['pairs'].append({'c1': c1_val, 'c2': c2_val, 'trail': trail})
        
    return tests

def main():
    input_file = "deterministic_solutions.txt"
    output_file = "key_recovery_stats.txt"
    
    print(f"Parsing {input_file}...")
    tests = parse_deterministic_solutions(input_file)
    print(f"Found {len(tests)} unique Master Keys (Tests).")

    with open(output_file, 'w') as f_out:
        sorted_tests = sorted(tests.values(), key=lambda x: x['id'])
        
        for data in sorted_tests:
            test_id = data['id']
            mk_str = data['mk']
            pairs = data['pairs']
            
            # Use all available pairs (up to 4)
            if len(pairs) < 4:
                print(f"Skipping Test #{test_id} (MK: {mk_str}): has only {len(pairs)} pairs.")
                continue
            pairs = pairs[:4]

            print(f"Running Test #{test_id} (MK: {mk_str}) ...")
            f_out.write(f"Test #{test_id} MK: {mk_str}\n")
            
            start_time = time.time()
            
            # --- Prepare Data ---
            mk_val = int(mk_str, 16)
            mk_nibbles = to_nibbles(mk_val)
            mk_nibbles = inv_perm(mk_nibbles)
            for i in range(32): mk_nibbles[i] = [mk_nibbles[i]]

            p1 = pairs[0]; p2 = pairs[1]; p3 = pairs[2]; p4 = pairs[3]
            c1n = to_nibbles(p1['c1']); c2n = to_nibbles(p1['c2'])
            c3n = to_nibbles(p2['c1']); c4n = to_nibbles(p2['c2'])
            c5n = to_nibbles(p3['c1']); c6n = to_nibbles(p3['c2'])
            c7n = to_nibbles(p4['c1']); c8n = to_nibbles(p4['c2'])
            t1n = [to_nibbles(x) for x in p1['trail']]
            t2n = [to_nibbles(x) for x in p2['trail']]
            t3n = [to_nibbles(x) for x in p3['trail']]
            t4n = [to_nibbles(x) for x in p4['trail']]

            # --- R1 Attack ---
            r1_keyspace = [[i for i in range(16)] for _ in range(32)]
            r1_keyspace = attack_r1(t1n[7], c1n, c2n, r1_keyspace)
            r1_keyspace = attack_r1(t2n[7], c3n, c4n, r1_keyspace)
            r1_keyspace = attack_r1(t3n[7], c5n, c6n, r1_keyspace)
            r1_keyspace = attack_r1(t4n[7], c7n, c8n, r1_keyspace)
            f_out.write(f"  Round 1 Candidates (per nibble): {[len(k) for k in r1_keyspace]}\n")
            
            flag = True
            for i in range(32):
                if mk_nibbles[i][0] not in r1_keyspace[i]: flag = False; break
            f_out.write(f"  MK in R1: {flag}\n")

            # --- R2 Attack ---
            r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]
            r2_keyspace = attack_r2(t1n[6], c1n, c2n, r1_keyspace, r2_keyspace)
            r2_keyspace = attack_r2(t2n[6], c3n, c4n, r1_keyspace, r2_keyspace)
            r2_keyspace = attack_r2(t3n[6], c5n, c6n, r1_keyspace, r2_keyspace)
            r2_keyspace = attack_r2(t4n[6], c7n, c8n, r1_keyspace, r2_keyspace)
            f_out.write(f"  Round 2 Candidates (per group): {[len(k) for k in r2_keyspace]}\n")

            mk2_keyspace = [list(product(*[mk_nibbles[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]
            flag = True
            for i in range(8):
                if mk2_keyspace[i][0] not in r2_keyspace[i]: flag = False; break
            f_out.write(f"  MK in R2: {flag}\n")

            # --- R3 Attack ---
            r3_keyspace = [[], []]
            for group_idx_last in range(2):    
                r3_keyspace[group_idx_last] = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))
            r3_keyspace = attack_r3(t1n[5], c1n, c2n, r1_keyspace, r2_keyspace, r3_keyspace)
            r3_keyspace = attack_r3(t2n[5], c3n, c4n, r1_keyspace, r2_keyspace, r3_keyspace)
            r3_keyspace = attack_r3(t3n[5], c5n, c6n, r1_keyspace, r2_keyspace, r3_keyspace)
            r3_keyspace = attack_r3(t4n[5], c7n, c8n, r1_keyspace, r2_keyspace, r3_keyspace)
            f_out.write(f"  Round 3 Candidates (per half): {[len(k) for k in r3_keyspace]}\n")
            
            mk3_keyspace = [[], []]
            for group_idx_last in range(2):    
                mk3_keyspace[group_idx_last] = list(product(*[mk2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))
            flag = True
            for i in range(2):
                if mk3_keyspace[i][0] not in r3_keyspace[i]: flag = False; break
            f_out.write(f"  MK in R3: {flag}\n")

            # --- R4 ~ R8 Attacks ---
            r4_keyspace = list(product(r3_keyspace[0], r3_keyspace[1]))
            mk4_keyspace = list(product(mk3_keyspace[0], mk3_keyspace[1]))
            
            # R4
            r4_keyspace = attack_r456(t1n[4], c1n, c2n, r4_keyspace, 4)
            r4_keyspace = attack_r456(t2n[4], c3n, c4n, r4_keyspace, 4)
            r4_keyspace = attack_r456(t3n[4], c5n, c6n, r4_keyspace, 4)
            r4_keyspace = attack_r456(t4n[4], c7n, c8n, r4_keyspace, 4)
            f_out.write(f"  Round 4 Candidates: {len(r4_keyspace)}\n")
            f_out.write(f"  MK in R4: {mk4_keyspace[0] in r4_keyspace}\n")

            # R5
            r5_keyspace = attack_r456(t1n[3], c1n, c2n, r4_keyspace, 5)
            r5_keyspace = attack_r456(t2n[3], c3n, c4n, r5_keyspace, 5)
            r5_keyspace = attack_r456(t3n[3], c5n, c6n, r5_keyspace, 5)
            r5_keyspace = attack_r456(t4n[3], c7n, c8n, r5_keyspace, 5)
            f_out.write(f"  Round 5 Candidates: {len(r5_keyspace)}\n")
            f_out.write(f"  MK in R5: {mk4_keyspace[0] in r5_keyspace}\n")

            # R6
            r6_keyspace = attack_r456(t1n[2], c1n, c2n, r5_keyspace, 6)
            r6_keyspace = attack_r456(t2n[2], c3n, c4n, r6_keyspace, 6)
            r6_keyspace = attack_r456(t3n[2], c5n, c6n, r6_keyspace, 6)
            r6_keyspace = attack_r456(t4n[2], c7n, c8n, r6_keyspace, 6)
            f_out.write(f"  Round 6 Candidates: {len(r6_keyspace)}\n")
            f_out.write(f"  MK in R6: {mk4_keyspace[0] in r6_keyspace}\n")

            # R7
            r7_keyspace = attack_r456(t1n[1], c1n, c2n, r6_keyspace, 7)
            r7_keyspace = attack_r456(t2n[1], c3n, c4n, r7_keyspace, 7)
            r7_keyspace = attack_r456(t3n[1], c5n, c6n, r7_keyspace, 7)
            r7_keyspace = attack_r456(t4n[1], c7n, c8n, r7_keyspace, 7)
            f_out.write(f"  Round 7 Candidates: {len(r7_keyspace)}\n")
            f_out.write(f"  MK in R7: {mk4_keyspace[0] in r7_keyspace}\n")

            # R8 (Final)
            r8_keyspace = attack_r456(t1n[0], c1n, c2n, r7_keyspace, 8)
            r8_keyspace = attack_r456(t2n[0], c3n, c4n, r8_keyspace, 8)
            r8_keyspace = attack_r456(t3n[0], c5n, c6n, r8_keyspace, 8)
            r8_keyspace = attack_r456(t4n[0], c7n, c8n, r8_keyspace, 8)
            f_out.write(f"  Round 8 Candidates: {len(r8_keyspace)}\n")
            f_out.write(f"  MK in R8: {mk4_keyspace[0] in r8_keyspace}\n")
            
            f_out.write(f"  Time taken: {time.time() - start_time:.4f}s\n")
            f_out.write("-" * 30 + "\n")
            f_out.flush()

    print(f"Done. Stats written to {output_file}")

if __name__ == "__main__":
    main()