#include <stdint.h>
#include <stdio.h>
#include <string.h>  // Use memcpy

#define DEFAULT_LAYER_ROUND 28
#define DEFAULT_CORE_ROUND  24

// S-box for Layer rounds
const uint8_t default_layer_sbox[16] = {0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5};
// S-box for Core rounds
const uint8_t default_core_sbox[16] = {0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5};
// Bit Permutation Table
const uint8_t default_bit_perm[128] = {
    0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
    4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
    8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
   12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
   16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
   20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
   24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
   28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
};
// Round Constants
const uint8_t default_rc[28] = {1,3,7,15,31,62,61,59,55,47,30,60,57,51,39,14,29,58,53,43,22,44,24,48,33,2,5,11};

// SubCells operation for Core rounds
void default_core_slayer(uint8_t s[16])
{
    int i;
    // Apply Core S-box to each nibble
    for (i=0;i<16;i++) s[i]=(default_core_sbox[s[i]&0xf])|((default_core_sbox[(s[i]>>4)&0xf])<<4);
}

// SubCells operation for Layer rounds
void default_layer_slayer(uint8_t s[16])
{
    int i;
    // Apply Layer S-box to each nibble
    for (i=0;i<16;i++) s[i]=(default_layer_sbox[s[i]&0xf])|((default_layer_sbox[(s[i]>>4)&0xf])<<4);
}

// PermBits operation (Bit Permutation)
void default_player(uint8_t s[16])
{
    int i;

    uint8_t tmp[16] ={0,};

    for (i=0;i<128;i++)
    {
        int src_byte = i / 8;   // Source byte position
        int src_bit = i % 8;    // Source bit position

        int dest_byte = default_bit_perm[i] / 8;  // Destination byte position
        int dest_bit = default_bit_perm[i] % 8;   // Destination bit position

        // Read bit from source array
        uint8_t bit = (s[src_byte] >> src_bit) & 1;

        // Write bit to new position
        tmp[dest_byte] |= (bit << dest_bit);
    }

    // Copy result back to state
    memcpy(s, tmp, 16);
}

// AddRoundConstant operation
void default_rc_add(uint8_t s[16], int r)
{
    uint8_t c5,c4,c3,c2,c1,c0;
    
    // Extract bits from round constant
    c5=default_rc[r]>>5;
    c4=(default_rc[r]>>4)&0x1;
    c3=(default_rc[r]>>3)&0x1;
    c2=(default_rc[r]>>2)&0x1;
    c1=(default_rc[r]>>1)&0x1;
    c0=default_rc[r]&0x1;

    // XOR round constant to state
    s[15]^=(1<<7); // Constant 1 addition
    s[2]^=c5<<7;
    s[2]^=c4<<3;
    s[1]^=c3<<7;
    s[1]^=c2<<3;
    s[0]^=c1<<7;
    s[0]^=c0<<3;
}

// AddRoundKey operation
void default_key_add(uint8_t s[16], const uint8_t k[16])
{
    int i;

    for (i=0;i<16;i++) s[i]^=k[i];
}

// Core Round function
void default_core_round(uint8_t s[16], const uint8_t rk[4][16], int r)
{
    default_core_slayer(s);
    default_player(s);
    default_rc_add(s,r);
    default_key_add(s,rk[r%4]);
}

// Layer Round function
void default_layer_round(uint8_t s[16], const uint8_t rk[4][16],int r)
{
    default_layer_slayer(s);
    default_player(s);
    default_rc_add(s,r);
    default_key_add(s,rk[r%4]);
}

// Encryption function
void default_enc(uint8_t c[16], const uint8_t p[16], const uint8_t rk[4][16])
{
    int i;
    
    uint8_t s[16];

    // Load plaintext (reversing byte order)
    for(i=0;i<16;i++) s[i]=p[15-i];

    // 28 Layer Rounds
    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    // 24 Core Rounds
    for (i=0;i<24;i++) default_core_round(s,rk,i);

    // 28 Layer Rounds
    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    // Copy ciphertext
    memcpy(c,s,16);
}

// Simplified AddRoundConstant for Key Schedule
void default_rc_add_prime(uint8_t s[16])
{
    s[15]^=(1<<7);
}

// Simplified Layer Round for Key Schedule
void default_layer_round_prime(uint8_t s[16])
{
    default_layer_slayer(s);
    default_player(s);
    default_rc_add_prime(s);
}

// Key Schedule
void default_key_schedule(uint8_t rk[4][16], const uint8_t mk[16])
{
    int i;
    
    uint8_t mk_t[16]={0,};
    
    // Load Master Key (reversing byte order)
    for(i=0;i<16;i++) mk_t[i]=mk[15-i];

    memcpy(rk[0],mk_t,16);    
    memcpy(rk[1],mk_t,16);    
    for(int i=0;i<4;i++) default_layer_round_prime(rk[1]);    
    memcpy(rk[2],rk[1],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[2]);
    memcpy(rk[3],rk[2],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[3]);
}

int main()
{
    int i,t,f;

    uint8_t c[16]={0,};
    uint8_t rk[4][16]={0,};

    // Four shipped test vectors: (plaintext, master key, expected ciphertext).
    // Layout matches BAKSHEESH/reference_code/baksheesh.c — c_test[t][k] stores
    // the byte printed FIRST (i.e. c[15] → c_test[t][0]); see the compare
    // loop below.
    uint8_t p[4][16]={
        {0,},
        {0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33},
        {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55},
        {0xe1,0xe5,0x1e,0x2e,0x08,0xf8,0x58,0x8d,0x6f,0xb8,0x59,0x11,0xb2,0x5a,0x18,0x29}
    };
    uint8_t mk[4][16]={
        {0,},
        {0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33},
        {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa},
        {0x97,0x4c,0x0a,0xda,0xa3,0x39,0x00,0x49,0x59,0x09,0xbe,0xa9,0x63,0xdf,0x0a,0x19}
    };
    uint8_t c_test[4][16]={
        {0x93,0xfa,0xff,0x13,0x8c,0x52,0x7a,0x05,0x2e,0x5c,0x99,0x62,0x78,0x28,0x02,0x44},
        {0x68,0x90,0x2d,0x38,0xbe,0xd0,0xd8,0xa1,0x9c,0x42,0x0c,0xfc,0x3c,0x0d,0x3d,0x9a},
        {0xb6,0x01,0x61,0x05,0x42,0xb8,0x2a,0xe8,0x43,0x2c,0x11,0x17,0x87,0x5b,0x16,0xbe},
        {0xf9,0x19,0x4b,0x99,0x28,0xff,0x08,0xc7,0x68,0x39,0x8a,0xfa,0xa5,0x9b,0xd0,0xf3}
    };

    int any_fail = 0;
    for(t=0;t<4;t++)
    {
        f=1;

        default_key_schedule(rk,mk[t]);
        default_enc(c,p[t],rk);

        for(i=15;i>=0;i--) printf("%02X ",c[i]);
        printf("\n");

        // Verify against the shipped expected ciphertext.
        for(i=15;i>=0;i--)
        {
            if(c[i]!=c_test[t][15-i])
            {
                printf("test vector fail\n");
                f=0;
                any_fail = 1;
                break;
            }
        }
        if(f==1) printf("test vector succ\n");
    }
    /* Return non-zero if any of the four shipped test vectors
     * disagreed — `make && ./default && echo OK` should not print
     * OK when the cipher is broken. */
    return any_fail ? 1 : 0;
}
