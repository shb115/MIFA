from itertools import product
import time
from typing import List

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

inv_sbox_table = [0] * 16

for i in range(16):
    inv_sbox_table[sbox[i]] = i

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
    
    c5 = (rc >> 5) & 1
    c4 = (rc >> 4) & 1
    c3 = (rc >> 3) & 1
    c2 = (rc >> 2) & 1
    c1 = (rc >> 1) & 1
    c0 = rc & 1

    bit_indices = [127, 23, 19, 15, 11, 7, 3]
    values =      [1,   c5, c4, c3, c2, c1, c0]

    for bit_index, val in zip(bit_indices, values):
        nibble_index = bit_index // 4
        bit_pos = bit_index % 4  # 0 = LSB, 3 = MSB
        s[nibble_index] ^= (val << bit_pos)
    
    return s

def attack_r1(target_diff, c1, c2, r1_keyspace):
    dec_c1 = default_rc_add(c1,6)
    dec_c2 = default_rc_add(c2,6)
    dec_c1 = inv_perm(dec_c1)
    dec_c2 = inv_perm(dec_c2)
    
    for i in range(32):  
        new_keyspace=[]
        for k in r1_keyspace[i]:       
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
                
                dec_cip = default_rc_add(cip,6)
                dec_fcip = default_rc_add(fcip,6)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)
                dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                dec_cip = inv_sbox(dec_cip)
                dec_fcip = inv_sbox(dec_fcip)
                dec_cip = default_rc_add(dec_cip,5)
                dec_fcip = default_rc_add(dec_fcip,5)
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
                    dec_cip = default_rc_add(cip,6)
                    dec_fcip = default_rc_add(fcip,6)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    # 2nd last layer                    
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,5)
                    dec_fcip = default_rc_add(dec_fcip,5)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                    dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                    # 3rd last layer
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,4)
                    dec_fcip = default_rc_add(dec_fcip,4)
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
                        dec_cip = default_rc_add(cip,6)
                        dec_fcip = default_rc_add(fcip,6)
                        dec_cip = inv_perm(dec_cip)
                        dec_fcip = inv_perm(dec_fcip)
                        dec_cip = [dec_cip^last_key for dec_cip, last_key in zip(dec_cip, last_key)]
                        dec_fcip = [dec_fcip^last_key for dec_fcip, last_key in zip(dec_fcip, last_key)]
                        dec_cip = inv_sbox(dec_cip)
                        dec_fcip = inv_sbox(dec_fcip)
                        # 2nd last layer
                        dec_cip = default_rc_add(dec_cip,5)
                        dec_fcip = default_rc_add(dec_fcip,5)
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
                        dec_cip = default_rc_add(dec_cip,4)
                        dec_fcip = default_rc_add(dec_fcip,4)
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
                dec_cip = default_rc_add(cip,6)
                dec_fcip = default_rc_add(fcip,6)
                dec_cip = inv_perm(dec_cip)
                dec_fcip = inv_perm(dec_fcip)
                dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]
                for r in range(round-2):
                    dec_cip = inv_sbox(dec_cip)
                    dec_fcip = inv_sbox(dec_fcip)
                    dec_cip = default_rc_add(dec_cip,5-r)
                    dec_fcip = default_rc_add(dec_fcip,5-r)
                    dec_cip = inv_perm(dec_cip)
                    dec_fcip = inv_perm(dec_fcip)
                    dec_cip = [i^j for i, j in zip(dec_cip, last_key)]
                    dec_fcip = [i^j for i, j in zip(dec_fcip, last_key)]
                # 4th last layer
                dec_cip = inv_sbox(dec_cip)
                dec_fcip = inv_sbox(dec_fcip)
                dec_cip = default_rc_add(dec_cip,7-round)
                dec_fcip = default_rc_add(dec_fcip,7-round)
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

start_time = time.time() 

print("### 7-round key-recovery ###")

# 입력값
c1 = 0x2D79F988BBD76F0804D5BCD0080E6781
c2 = 0x36D1BED45C3C1460B2BEDD33EE3DB2CB
c3 = 0xF0AA8B553E31316FFC695451AC29C5C1
c4 = 0x9813B5C9F166AE2AB9EBA980E58A85F4
c5 = 0xA9F6B6B58D6A3736EB5AAE3CC643F085
c6 = 0x4C7A2B0CC5C5543ACC4B11B6771D5711
trail1 = [
0x00000000000000000000000000000002,
0x00000000000000040000000200000001,
0x00080008000404000000020000010101,
0x0082000A444101012200082000140411,
0x007841994091304960789C0831D14635,
0x9F5D9CE64F84E7B60776010D23B38890,
0xCECEB245BB59116A5F52221CE8F82066,
0x1BA8475CE7EB7B68B66B61E3E633D54A,
]
trail2 = [
0x00000000000000000000000000000002,
0x00000008000000040000000000000001,
0x08080000040400000000000200010001,
0x0020080040500400A020002240500111,
0x12421149002104094050565824042381,
0xB9184664DF052E785F6A5E37D1350A5D,
0x3E85CC82DC7EBA79A92B2CEECB44FF02,
0x68B93E9CCF579F454582FDD149A34035,
]
trail3 = [
0x00000000000000000000000000000002,
0x00000008000000040000000000000001,
0x00080000040400000200000200010001,
0x00A02880405014002000000200504111,
0x1440400D0003240B0D5912490E840101,
0x3C84A9281243CF41512B6F68E0043571,
0xEBB9F04775D19F68CD75422AB6C70E15,
0xE58C9DB948AF630C2711BF8AB15EA794,
]

mk = 0x67C6697351FF4AEC29CDBAABF2FBE346
mk_nibbles = to_nibbles(mk)
mk_nibbles = inv_perm(mk_nibbles)
for i in range(32):
    mk_nibbles[i] = [mk_nibbles[i]]

# 변환
c1_nibbles = to_nibbles(c1)
c2_nibbles = to_nibbles(c2)
c3_nibbles = to_nibbles(c3)
c4_nibbles = to_nibbles(c4)
c5_nibbles = to_nibbles(c5)
c6_nibbles = to_nibbles(c6)

trail1_nibbles = [to_nibbles(x) for x in trail1]
trail2_nibbles = [to_nibbles(x) for x in trail2]
trail3_nibbles = [to_nibbles(x) for x in trail3]

r1_keyspace = [[i for i in range(16)] for _ in range(32)]

r1_keyspace = attack_r1(trail1_nibbles[6],c1_nibbles,c2_nibbles,r1_keyspace)
r1_keyspace = attack_r1(trail2_nibbles[6],c3_nibbles,c4_nibbles,r1_keyspace)
r1_keyspace = attack_r1(trail3_nibbles[6],c5_nibbles,c6_nibbles,r1_keyspace)

print("### r1_keyspace ###")
#for i, candidates in enumerate(r1_keyspace):
#    hex_vals = ' '.join(f"{k:X}" for k in candidates)
#    print(f"Nibble {i:2d}: {hex_vals if hex_vals else '(no candidates)'}")

flag = 1
for i in range(32):
    if (mk_nibbles[i][0] not in r1_keyspace[i]):
        flag = 0
        break
if flag:
    print("mk in r1_keyspace")
else:
    print("mk not in r1_keyspace")

print("r1_keyspace length:",end=" ")
for i in r1_keyspace:
    print(len(i),end=" ")
print()

# taking the product space of the corresponding key nibbles
r2_keyspace = [list(product(*[r1_keyspace[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

r2_keyspace = attack_r2(trail1_nibbles[5],c1_nibbles,c2_nibbles,r1_keyspace,r2_keyspace)
r2_keyspace = attack_r2(trail2_nibbles[5],c3_nibbles,c4_nibbles,r1_keyspace,r2_keyspace)
#r2_keyspace = attack_r2(trail3_nibbles[5],c5_nibbles,c6_nibbles,r1_keyspace,r2_keyspace)

mk2_keyspace = [list(product(*[mk_nibbles[(i + 8 * j)%32] for j in range(4)])) for i in range(8)]

flag = 1
for i in range(8):
    if (mk2_keyspace[i][0] not in r2_keyspace[i]):
        flag = 0
        break
if flag:
    print("mk in r2_keyspace")
else:
    print("mk not in r2_keyspace")

print("r2_keyspace length:",end=" ")
for i in r2_keyspace:
    print(len(i),end=" ")
print()

r3_keyspace = [[], []]
# producting the key space of 3rd last round
for group_idx_last in range(2):    
    r3_keyspace[group_idx_last] = list(product(*[r2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

r3_keyspace = attack_r3(trail1_nibbles[4],c1_nibbles,c2_nibbles,r1_keyspace,r2_keyspace,r3_keyspace)
r3_keyspace = attack_r3(trail2_nibbles[4],c3_nibbles,c4_nibbles,r1_keyspace,r2_keyspace,r3_keyspace)
#r3_keyspace = attack_r3(trail3_nibbles[4],c5_nibbles,c6_nibbles,r1_keyspace,r2_keyspace,r3_keyspace)

mk3_keyspace = [[], []]
# producting the key space of 3rd last round
for group_idx_last in range(2):    
    mk3_keyspace[group_idx_last] = list(product(*[mk2_keyspace[(group_idx_last + 2*j)%32] for j in range(4)]))

flag = 1
for i in range(2):
    if (mk3_keyspace[i][0] not in r3_keyspace[i]):
        flag = 0
        break
if flag:
    print("mk in r3_keyspace")
else:
    print("mk not in r3_keyspace")

print("r3_keyspace length:",end=" ")
for i in r3_keyspace:
    print(len(i),end=" ")
print()

r4_keyspace = list(product(r3_keyspace[0], r3_keyspace[1]))

r4_keyspace = attack_r456(trail1_nibbles[3],c1_nibbles,c2_nibbles,r4_keyspace,4)
r4_keyspace = attack_r456(trail2_nibbles[3],c3_nibbles,c4_nibbles,r4_keyspace,4)
#r4_keyspace = attack_r456(trail3_nibbles[3],c5_nibbles,c6_nibbles,r4_keyspace,4)

mk4_keyspace = list(product(mk3_keyspace[0], mk3_keyspace[1]))

if (mk4_keyspace[0] not in r4_keyspace):
    print("mk not in r4_keyspace")
else:
    print("mk in r4_keyspace")
    
print("r4_keyspace length:",len(r4_keyspace))


r5_keyspace = attack_r456(trail1_nibbles[2],c1_nibbles,c2_nibbles,r4_keyspace,5)
r5_keyspace = attack_r456(trail2_nibbles[2],c3_nibbles,c4_nibbles,r5_keyspace,5)
#r5_keyspace = attack_r456(trail3_nibbles[2],c5_nibbles,c6_nibbles,r5_keyspace,5)
#r5_keyspace = attack_r456(trail4_nibbles[1],c7_nibbles,c8_nibbles,r4_keyspace,5)

if (mk4_keyspace[0] not in r5_keyspace):
    print("mk not in r5_keyspace")
else:
    print("mk in r5_keyspace")
    
print("r5_keyspace length:",len(r5_keyspace))

r6_keyspace = attack_r456(trail1_nibbles[1],c1_nibbles,c2_nibbles,r5_keyspace,6)
r6_keyspace = attack_r456(trail2_nibbles[1],c3_nibbles,c4_nibbles,r6_keyspace,6)
#r6_keyspace = attack_r456(trail3_nibbles[1],c5_nibbles,c6_nibbles,r6_keyspace,6)
#r5_keyspace = attack_r456(trail4_nibbles[1],c7_nibbles,c8_nibbles,r4_keyspace,5)

if (mk4_keyspace[0] not in r6_keyspace):
    print("mk not in r6_keyspace")
else:
    print("mk in r6_keyspace")
    
print("r6_keyspace length:",len(r6_keyspace))

r7_keyspace = attack_r456(trail1_nibbles[0],c1_nibbles,c2_nibbles,r6_keyspace,7)
r7_keyspace = attack_r456(trail2_nibbles[0],c3_nibbles,c4_nibbles,r7_keyspace,7)
#r7_keyspace = attack_r456(trail3_nibbles[0],c5_nibbles,c6_nibbles,r7_keyspace,7)
#r5_keyspace = attack_r456(trail4_nibbles[1],c7_nibbles,c8_nibbles,r4_keyspace,5)

if (mk4_keyspace[0] not in r7_keyspace):
    print("mk not in r7_keyspace")
else:
    print("mk in r7_keyspace")
    
print("r7_keyspace length:",len(r7_keyspace))

end_time = time.time()
print(f"time: {end_time - start_time:.4f}s")