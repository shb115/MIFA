#include <stdint.h>
#include <stdio.h>
#include <string.h>  // Use memcpy
#include <stdlib.h>
#include <time.h>

// Define number of rounds
#define DEFAULT_LAYER_ROUND 28
#define DEFAULT_CORE_ROUND  24

// S-box for the Layer stages (4-bit based)
const uint8_t default_layer_sbox[16] = {0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5};
// S-box for the Core stages (4-bit based)
const uint8_t default_core_sbox[16] = {0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5};
// Bit Permutation table (mapping for 128-bit positions)
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

// SubCells layer for the Core stage
void default_core_slayer(uint8_t s[16])
{
    int i;
    // Apply S-box to each nibble (upper 4 bits, lower 4 bits)
    for (i=0;i<16;i++) s[i]=(default_core_sbox[s[i]&0xf])|((default_core_sbox[(s[i]>>4)&0xf])<<4);
}

// SubCells layer for the Layer stage
void default_layer_slayer(uint8_t s[16])
{
    int i;
    // Apply S-box to each nibble (upper 4 bits, lower 4 bits)
    for (i=0;i<16;i++) s[i]=(default_layer_sbox[s[i]&0xf])|((default_layer_sbox[(s[i]>>4)&0xf])<<4);
}

// PermBits layer (Bit Permutation)
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

// AddRoundConstant layer
void default_rc_add(uint8_t s[16], int r)
{
    uint8_t c5,c4,c3,c2,c1,c0;
    
    // Extract round constant bits
    c5=default_rc[r]>>5;
    c4=(default_rc[r]>>4)&0x1;
    c3=(default_rc[r]>>3)&0x1;
    c2=(default_rc[r]>>2)&0x1;
    c1=(default_rc[r]>>1)&0x1;
    c0=default_rc[r]&0x1;

    // XOR round constant to specific state bytes
    s[15]^=(1<<7); // Always add 1 to this bit
    s[2]^=c5<<7;
    s[2]^=c4<<3;
    s[1]^=c3<<7;
    s[1]^=c2<<3;
    s[0]^=c1<<7;
    s[0]^=c0<<3;
}

// AddRoundKey layer
void default_key_add(uint8_t s[16], const uint8_t k[16])
{
    int i;
    // XOR state array with round key
    for (i=0;i<16;i++) s[i]^=k[i];
}

// Core Round function
void default_core_round(uint8_t s[16], const uint8_t rk[4][16], int r)
{
    default_core_slayer(s); // S-box
    default_player(s);      // Permutation
    default_rc_add(s,r);    // Round Constant
    default_key_add(s,rk[r%4]); // Round Key (Use 4 keys cyclically)
}

// Layer Round function
void default_layer_round(uint8_t s[16], const uint8_t rk[4][16],int r)
{
    default_layer_slayer(s); // S-box
    default_player(s);       // Permutation
    default_rc_add(s,r);     // Round Constant
    default_key_add(s,rk[r%4]); // Round Key
}

// Full Encryption function
void default_enc(uint8_t c[16], const uint8_t p[16], const uint8_t rk[4][16])
{
    int i;
    
    uint8_t s[16];

    // Load plaintext (Handle byte order reversal)
    for(i=0;i<16;i++) s[i]=p[15-i];

    // Step 1: Layer rounds (28 rounds)
    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    // Step 2: Core rounds (24 rounds)
    for (i=0;i<24;i++) default_core_round(s,rk,i);

    // Step 3: Layer rounds (28 rounds)
    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    // Copy ciphertext (Copy state array as is)
    memcpy(c,s,16);
}

// Simplified Round Constant addition for Key Schedule
void default_rc_add_prime(uint8_t s[16])
{
    s[15]^=(1<<7);
}

// Simplified Layer Round function for Key Update
void default_layer_round_prime(uint8_t s[16])
{
    default_layer_slayer(s);
    default_player(s);
    default_rc_add_prime(s);
}

// Key Schedule function (Generates 4 round keys)
void default_key_schedule(uint8_t rk[4][16], const uint8_t mk[16])
{
    int i;
    
    uint8_t mk_t[16]={0,};
    
    // Load master key (Handle byte order reversal)
    for(i=0;i<16;i++) mk_t[i]=mk[15-i];

    // RK0: Use master key as is
    memcpy(rk[0],mk_t,16);    
    // RK1: Initialized same as RK0
    memcpy(rk[1],mk_t,16);    
    // Generate RK1: Perform 4 simplified rounds
    for(int i=0;i<4;i++) default_layer_round_prime(rk[1]);    
    // RK2: Generated based on RK1
    memcpy(rk[2],rk[1],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[2]);
    // RK3: Generated based on RK2
    memcpy(rk[3],rk[2],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[3]);
}

// Simple Key Schedule (Used in test)
void default_key_schedule_simple(uint8_t rk[4][16], const uint8_t mk[16])
{
    int i;
    
    uint8_t mk_t[16]={0,};
    
    // Load master key (Handle byte order reversal)
    for(i=0;i<16;i++) mk_t[i]=mk[15-i];

    // Use same master key for all round keys (Simplified logic)
    memcpy(rk[0],mk_t,16);    
    memcpy(rk[1],mk_t,16);    
    memcpy(rk[2],mk_t,16);
    memcpy(rk[3],mk_t,16);
}

// Reduced Layer Function (Encrypts for 'r' rounds only)
void default_layer_reduced(uint8_t c[16], const uint8_t p[16], const uint8_t rk[4][16], const int r)
{
    int i;

    uint8_t s[16];

    // Load plaintext (Handle byte order reversal)
    for(i=0;i<16;i++) s[i]=p[15-i];

    // Run Layer function for 'r' rounds
    for (i=0;i<r;i++) default_layer_round(s,rk,i);

    // Copy result
    memcpy(c,s,16);
}

// Generate random bytes for test
void generate_random_bytes(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() % 256; // Value between 0 and 255
    }
}

int main(int argc, char **argv)
{
    int i,j,test_num;

    uint8_t c1[16]={0,};
    uint8_t c2[16]={0,};
    uint8_t rk[4][16]={0,};

    uint8_t p1[16]={0,};
    uint8_t p2[16]={0,};
    uint8_t mk1[16]={0,};

    // Initialize random seed
    srand(time(NULL));

    // Run 1 test case
    for (test_num=0; test_num<1; test_num++)
    {
        // Generate random master key
        generate_random_bytes(mk1,16);

        printf("===== TEST NUM %d =====\n", test_num);
        printf("\n"); 

        // Run twice for each test (using same key but different plaintexts)
        for (j=0;j<2;j++)
        {        
            // Generate random plaintext p1
            generate_random_bytes(p1,16);
            
            // Create p2 by flipping the last bit of p1 (LSB of last byte)
            memcpy(p2,p1,16);
            p2[15]^=0x1;

            // Generate simple key schedule
            default_key_schedule_simple(rk,mk1);
            
            // Encrypt p1 and p2 using reduced rounds (Number of rounds from argv[1])
            default_layer_reduced(c1,p1,rk,atoi(argv[1]));
            default_layer_reduced(c2,p2,rk,atoi(argv[1]));
                    
            // Print Master Key
            printf("mk:0x");
            for(i=0;i<=15;i++) 
            {
                printf("%02X",mk1[i]);
            }              
            printf("\n"); 

            // Print Ciphertext 1
            printf("c1:0x");
            for(i=15;i>=0;i--) 
            {
                printf("%02X",c1[i]);
            }              
            printf("\n"); 

            // Print Ciphertext 2
            printf("c2:0x");
            for(i=15;i>=0;i--) 
            {
                printf("%02X",c2[i]);
            }              
            printf("\n"); 
            
            // Print XOR Difference (c1 ^ c2)
            printf("c1^c2:0x");
            for(i=15;i>=0;i--) 
            {
                printf("%02X",c1[i]^c2[i]);
            }              
            printf(",");
            printf("\n"); 
            printf("\n"); 
        }    
        printf("\n"); 
    }
}