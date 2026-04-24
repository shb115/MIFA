#include <stdint.h>
#include <stdio.h>
#include <string.h>  // for memcpy
#include <stdlib.h>
#include <time.h>

#define BAKSHEESH_ROUND 35

const uint8_t baksheesh_sbox[16] = {0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe, 0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1};
const uint8_t baksheesh_bit_perm[128] = {
    0, 33, 66, 99, 96,  1, 34, 67, 64, 97,  2, 35, 32, 65, 98,  3,
    4, 37, 70,103,100,  5, 38, 71, 68,101,  6, 39, 36, 69,102,  7,
    8, 41, 74,107,104,  9, 42, 75, 72,105, 10, 43, 40, 73,106, 11,
   12, 45, 78,111,108, 13, 46, 79, 76,109, 14, 47, 44, 77,110, 15,
   16, 49, 82,115,112, 17, 50, 83, 80,113, 18, 51, 48, 81,114, 19,
   20, 53, 86,119,116, 21, 54, 87, 84,117, 22, 55, 52, 85,118, 23,
   24, 57, 90,123,120, 25, 58, 91, 88,121, 26, 59, 56, 89,122, 27,
   28, 61, 94,127,124, 29, 62, 95, 92,125, 30, 63, 60, 93,126, 31
};
const uint8_t baksheesh_rc[35] = {2, 33, 16, 9, 36, 19, 40, 53, 26, 13, 38, 51, 56, 61, 62, 31, 14, 7, 34, 49, 24, 45, 54, 59, 28, 47, 22, 43, 20, 11, 4, 3, 32, 17, 8};

void baksheesh_slayer(uint8_t s[16])
{
    int i;

    for (i=0;i<16;i++) s[i]=(baksheesh_sbox[s[i]&0xf])|((baksheesh_sbox[(s[i]>>4)&0xf])<<4);
}

void baksheesh_player(uint8_t s[16])
{
    int i;

    uint8_t tmp[16] ={0,};

    for (i=0;i<128;i++)
    {
        int src_byte = i / 8;   // source byte index
        int src_bit = i % 8;    // source bit index

        int dest_byte = baksheesh_bit_perm[i] / 8;  // destination byte index
        int dest_bit = baksheesh_bit_perm[i] % 8;   // destination bit index

        // read bit from the source array
        uint8_t bit = (s[src_byte] >> src_bit) & 1;

        // write bit at the new position
        tmp[dest_byte] |= (bit << dest_bit);
    }

    // copy the result back
    memcpy(s, tmp, 16);
}

void baksheesh_rc_add(uint8_t s[16], int r)
{
    uint8_t c5, c4, c3, c2, c1, c0;
    
    c5 = baksheesh_rc[r] >> 5;
    c4 = (baksheesh_rc[r] >> 4) & 0x1;
    c3 = (baksheesh_rc[r] >> 3) & 0x1;
    c2 = (baksheesh_rc[r] >> 2) & 0x1;
    c1 = (baksheesh_rc[r] >> 1) & 0x1;
    c0 = baksheesh_rc[r] & 0x1;

    // bit positions: 8, 13, 19, 35, 67, 106
    // which are in:
    // bit 8  → s[1], bit 0
    // bit 13 → s[1], bit 5
    // bit 19 → s[2], bit 3
    // bit 35 → s[4], bit 3
    // bit 67 → s[8], bit 3
    // bit 106 → s[13], bit 2

    s[1] ^= (c0 << 0);  // bit 8
    s[1] ^= (c1 << 5);  // bit 13
    s[2] ^= (c2 << 3);  // bit 19
    s[4] ^= (c3 << 3);  // bit 35
    s[8] ^= (c4 << 3);  // bit 67
    s[13] ^= (c5 << 2); // bit 106
}

void baksheesh_key_add(uint8_t s[16], const uint8_t k[16])
{
    int i;

    for (i=0;i<16;i++) s[i]^=k[i];
}

void baksheesh_round(uint8_t s[16], const uint8_t rk[36][16], int r)
{
    baksheesh_slayer(s);
    baksheesh_player(s);
    baksheesh_rc_add(s,r-1);
    baksheesh_key_add(s,rk[r]);
}

void baksheesh_enc(uint8_t c[16], const uint8_t p[16], const uint8_t rk[36][16])
{
    int i;
    
    uint8_t s[16];

    for(i=0;i<16;i++) s[i]=p[15-i];

    baksheesh_key_add(s,rk[0]);

    for (i=1;i<36;i++) baksheesh_round(s,rk,i);

    memcpy(c,s,16);
}

void baksheesh_enc_reduced(uint8_t c[16], const uint8_t p[16], const uint8_t rk[36][16], const int round)
{
    int i;
    
    uint8_t s[16];

    for(i=0;i<16;i++) s[i]=p[15-i];

    for(i=36-round;i<36;i++) baksheesh_round(s,rk,i);

    memcpy(c,s,16);
}

void baksheesh_key_schedule(uint8_t rk[36][16], const uint8_t mk[16]) {
    int i, j;

    // 1) reverse the master-key byte order so bit 0 of rk[0] is the global LSB
    uint8_t mk_t[16];
    for (i = 0; i < 16; i++) {
        mk_t[i] = mk[15 - i];
    }

    // rk[0] <- reversed master key
    memcpy(rk[0], mk_t, 16);

    // 2) derive rk[1] .. rk[35]: right-rotate the full 128-bit state by 1 bit
    for (i = 1; i < 36; i++) {
        for (j = 0; j < 16; j++) {
            uint8_t curr     = rk[i - 1][j];
            uint8_t next_b   = rk[i - 1][(j + 1) % 16];   // take LSB of the next byte
            uint8_t shifted  =  curr >> 1;                // shift current byte right by 1 bit
            uint8_t carry_in = (next_b & 0x01) << 7;      // next byte LSB becomes this byte MSB

            rk[i][j] = shifted | carry_in;
        }
    }
}

void generate_random_bytes(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() % 256; // value between 0 and 255
    }
}

int main(int argc, char **argv)
{
    int i,j;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <round-count> <sample-count> [<fault-byte>] [<seed>]\n", argv[0]);
        fprintf(stderr, "       e.g. %s 4 1000              (fault=0x8, random seed)\n", argv[0]);
        fprintf(stderr, "            %s 4 1000 0x4          (fault=0x4, random seed)\n", argv[0]);
        fprintf(stderr, "            %s 4 1000 0x8 42       (deterministic seed)\n", argv[0]);
        fprintf(stderr, "NOTE: the committed 0x4_*r_1000.txt samples were generated\n");
        fprintf(stderr, "      with fault-byte 0x4; 0x8_*r_1000.txt with 0x8.\n");
        return 1;
    }

    uint8_t c1[16]={0,};
    uint8_t c2[16]={0,};
    uint8_t rk[36][16]={0,};

    uint8_t p1[16]={0,};
    uint8_t p2[16]={0,};
    uint8_t mk1[16]={0x04, 0x23, 0xC5, 0x19, 0x24, 0x04, 0xF8, 0xAB, 0xD7, 0x10 ,0xC5, 0x72, 0x3A, 0x3B, 0x7D, 0xF0};

    // Fault byte to XOR into p2[15]: argv[3] if present (hex accepted),
    // else the historical default of 0x8.
    uint8_t fault_byte = (argc >= 4) ? (uint8_t)strtoul(argv[3], NULL, 0) : 0x8;

    // random seed: argv[4] wins if given, else time(NULL)
    unsigned int seed = (argc >= 5) ? (unsigned int)strtoul(argv[4], NULL, 10) : (unsigned int)time(NULL);
    srand(seed);

    //generate_random_bytes(mk1,16);

    printf("mk1  : 0x");
    for(i=0;i<=15;i++) 
    {
        printf("%02X",mk1[i]);
    }              
    printf("\n"); 

    printf("\n"); 

    for (j=0;j<atoi(argv[2]);j++)
    {        
        generate_random_bytes(p1,16);
        //generate_random_bytes(mk1,16);
        memcpy(p2,p1,16);
        p2[15]^=fault_byte;

        baksheesh_key_schedule(rk,mk1);
        baksheesh_enc_reduced(c1,p1,rk,atoi(argv[1]));
        baksheesh_enc_reduced(c2,p2,rk,atoi(argv[1]));
        
        /*
        printf("p1^p2: 0x");
        for(i=0;i<=15;i++) 
        {
            printf("%02X",p1[i]^p2[i]);
        }              
        printf("\n");

        printf("c1   : 0x");
        for(i=15;i>=0;i--) 
        {
            printf("%02X",c1[i]);
        }              
        printf("\n"); 

        printf("c2   : 0x");
        for(i=15;i>=0;i--) 
        {
            printf("%02X",c2[i]);
        }              
        printf("\n"); 
        */
        printf("0x");
        for(i=15;i>=0;i--) 
        {
            printf("%02X",c1[i]^c2[i]);
        }       
        printf(",");
        printf("\n");
    }
    return 0;
}
