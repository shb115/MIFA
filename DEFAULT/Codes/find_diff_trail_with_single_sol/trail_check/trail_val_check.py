# s-box
s_box = [
    0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5
]

ddt=[[0 for _ in range(16)] for __ in range(16)]

for i in range(16):
    for j in range(16):
        ddt[i^j][s_box[i]^s_box[j]] += 1
'''
for i in range(16):
    print(ddt[i])
'''
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

print("### 6-round trail validation check ###")

X = [
    0x00000000000000000000000000000001,
    0x00000008000000000000000000000001,
    0x08000008040000000000000000000001,
    0x20000000041000000280000240400001,
    0x403020502090940010004252004041A1,
    0x44540E1DAA8325895559154922AC0D0B,
    0xC12EE972D85C4E10DADFE712F42D55D0,
]

Y = []
for i in range(1, 7):  # X[1] ~ X[6]
    x_bits = format(X[i], '0128b')[::-1]  # LSB-first (0-th bit is the rightmost)
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[inv_bit_perm[j]] = x_bits[j]
    y_str = ''.join(y_bits)[::-1]  # Convert back to MSB-first and cast to integer
    Y.append(int(y_str, 2))

# Print results
#for idx, y in enumerate(Y):
#    print(f"Y[{idx}] = 0x{y:032X}")

for i in range(6):
    all_valid = True
    for sbox_idx in range(32):  # 128bit / 4bit
        shift = sbox_idx * 4
        x_nibble = (X[i] >> shift) & 0xF
        y_nibble = (Y[i] >> shift) & 0xF
        if ddt[x_nibble][y_nibble] == 0:
            all_valid = False
            break
    if all_valid:
        print(f"Round {i}: ✅ All S-box transitions valid")
    else:
        print(f"Round {i}: ❗ Invalid S-box transition exists")

print("### 7-round trail validation check ###")

X = [
    0x00000000000000000000000000000001,
    0x00000008000000000000000000000001,
    0x08000008040000000000000000000001,
    0x00200008041000008200000040400001,
    0x18104058841030204080805000604021,
    0x1C55440D2E1822809584540562E0202B,
    0x8E744E2D71EB673A713D72450C44FCE0,
    0x5F880B94C83395D9A5DEF745DC29AE10,
]

Y = []
for i in range(1, 8):  # X[1] ~ X[7]
    x_bits = format(X[i], '0128b')[::-1]  # LSB-first (0-th bit is the rightmost)
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[inv_bit_perm[j]] = x_bits[j]
    y_str = ''.join(y_bits)[::-1]  # Convert back to MSB-first and cast to integer
    Y.append(int(y_str, 2))

# Print results
#for idx, y in enumerate(Y):
#    print(f"Y[{idx}] = 0x{y:032X}")

for i in range(7):
    all_valid = True
    for sbox_idx in range(32):  # 128bit / 4bit
        shift = sbox_idx * 4
        x_nibble = (X[i] >> shift) & 0xF
        y_nibble = (Y[i] >> shift) & 0xF
        if ddt[x_nibble][y_nibble] == 0:
            all_valid = False
            break
    if all_valid:
        print(f"Round {i}: ✅ All S-box transitions valid")
    else:
        print(f"Round {i}: ❗ Invalid S-box transition exists")

print("### 8-round trail validation check ###")

X = [
    0x00000000000000000000000000000001,
    0x00000008000000000000000000000001,
    0x00000008040000000200000000000001,
    0x08000000041010000080800200404001,
    0x0010041C009204828081424140402901,
    0x1398C75601CDA9A3004C475B27351D05,
    0xB8B396E2EB9F89D4DF0967716A2E1AA8,
    0x2E5E81996EED5BFD0DC82A41693DD98A,
    0xCD0FB5224F22C1B9DEE407ECC3E82BED,
]

Y = []
for i in range(1, 9):  # X[1] ~ X[8]
    x_bits = format(X[i], '0128b')[::-1]  # LSB-first (0-th bit is the rightmost)
    y_bits = ['0'] * 128
    for j in range(128):
        y_bits[inv_bit_perm[j]] = x_bits[j]
    y_str = ''.join(y_bits)[::-1]  # Convert back to MSB-first and cast to integer
    Y.append(int(y_str, 2))

# Print results
#for idx, y in enumerate(Y):
#    print(f"Y[{idx}] = 0x{y:032X}")

for i in range(8):
    all_valid = True
    for sbox_idx in range(32):  # 128bit / 4bit
        shift = sbox_idx * 4
        x_nibble = (X[i] >> shift) & 0xF
        y_nibble = (Y[i] >> shift) & 0xF
        if ddt[x_nibble][y_nibble] == 0:
            all_valid = False
            break
    if all_valid:
        print(f"Round {i}: ✅ All S-box transitions valid")
    else:
        print(f"Round {i}: ❗ Invalid S-box transition exists")