"""trail_val_check.py — DDT-level sanity check of hard-coded BAKSHEESH 4/5-round trails.

This is a **standalone demonstration**: the two hard-coded trail
sequences below are example single-solution trails, NOT the specific
trails consumed by the attack driver in
`Codes/key_recovery_attack/` (which loads its trails from
`trails_{4,5}r.txt`) or enumerated by `trail_search_on_baksheesh.py`.
A green "All S-box transitions valid" row here demonstrates that the
DDT-check procedure works on representative trails.

To DDT-validate the EXACT trails the attack driver consumes at runtime,
run the sibling script
    ./trail_val_check_against_committed.py
which parses every entry of `trails_{4,5}r.txt` and reports per-trail
OK/FAIL.  The specific trails the attacks actually use are otherwise
validated end-to-end by the attack's success criterion itself —
`mk in r*_keyspace`."""

# s-box
s_box = [
    0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe, 0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1
]

ddt=[[0 for _ in range(16)] for __ in range(16)]

for i in range(16):
    for j in range(16):
        ddt[i^j][s_box[i]^s_box[j]] += 1

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

inv_bit_perm = [0] * 128
for i, val in enumerate(bit_perm):
    inv_bit_perm[val] = i

print("### 4-round trail validation check ###")

X = [
    0x00000000000000000000000000000001,
    0x00000008000000000000000200000001,
    0x08000808040004000200000201000101,
    0x2A02082A151014048A08000A45444144,
    0xC308E0CF492360939ED1B258D4AC906A,
]

Y = []
for i in range(1, 5):  # X[1] ~ X[6]
    x_bits = format(X[i], '0128b')[::-1]  # LSB-first (bit 0 is the rightmost)
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[inv_bit_perm[j]] = x_bits[j]
    y_str = ''.join(y_bits)[::-1]  # back to MSB-first for integer conversion
    Y.append(int(y_str, 2))

# print results
#for idx, y in enumerate(Y):
#    print(f"Y[{idx}] = 0x{y:032X}")

for i in range(4):
    all_valid = True
    for sbox_idx in range(32):  # 128bit / 4bit
        shift = sbox_idx * 4
        x_nibble = (X[i] >> shift) & 0xF
        y_nibble = (Y[i] >> shift) & 0xF
        if ddt[x_nibble][y_nibble] == 0:
            all_valid = False
            break
    if all_valid:
        print(f"Round {i+1}: [OK]   All S-box transitions valid")
    else:
        print(f"Round {i+1}: [FAIL] Invalid S-box transition exists")

print("### 5-round trail validation check ###")

X = [
    0x00000000000000000000000000000001,
    0x00000000000000000000000200000001,
    0x00000000000000040000020200000100,
    0x000808020000010100000A0000000500,
    0x8A02020045040000280A000815040000,
    0x404068E0216014603880B220D490C140,
]

Y = []
for i in range(1, 6):  # X[1] ~ X[6]
    x_bits = format(X[i], '0128b')[::-1]  # LSB-first (bit 0 is the rightmost)
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[inv_bit_perm[j]] = x_bits[j]
    y_str = ''.join(y_bits)[::-1]  # back to MSB-first for integer conversion
    Y.append(int(y_str, 2))

# print results
#for idx, y in enumerate(Y):
#    print(f"Y[{idx}] = 0x{y:032X}")

for i in range(5):
    all_valid = True
    for sbox_idx in range(32):  # 128bit / 4bit
        shift = sbox_idx * 4
        x_nibble = (X[i] >> shift) & 0xF
        y_nibble = (Y[i] >> shift) & 0xF
        if ddt[x_nibble][y_nibble] == 0:
            all_valid = False
            break
    if all_valid:
        print(f"Round {i+1}: [OK]   All S-box transitions valid")
    else:
        print(f"Round {i+1}: [FAIL] Invalid S-box transition exists")
