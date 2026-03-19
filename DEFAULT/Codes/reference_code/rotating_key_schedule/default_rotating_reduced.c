#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define DEFAULT_LAYER_ROUND 28
#define DEFAULT_CORE_ROUND  24

const uint8_t default_layer_sbox[16] = {0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5};
const uint8_t default_core_sbox[16] = {0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5};
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
const uint8_t default_rc[28] = {1,3,7,15,31,62,61,59,55,47,30,60,57,51,39,14,29,58,53,43,22,44,24,48,33,2,5,11};

void default_core_slayer(uint8_t s[16])
{
    int i;

    for (i=0;i<16;i++) s[i]=(default_core_sbox[s[i]&0xf])|((default_core_sbox[(s[i]>>4)&0xf])<<4);
}

void default_layer_slayer(uint8_t s[16])
{
    int i;

    for (i=0;i<16;i++) s[i]=(default_layer_sbox[s[i]&0xf])|((default_layer_sbox[(s[i]>>4)&0xf])<<4);
}

void default_player(uint8_t s[16])
{
    int i;

    uint8_t tmp[16] ={0,};

    for (i=0;i<128;i++)
    {
        int src_byte = i / 8; 
        int src_bit = i % 8;  

        int dest_byte = default_bit_perm[i] / 8;  
        int dest_bit = default_bit_perm[i] % 8;   

        uint8_t bit = (s[src_byte] >> src_bit) & 1;

        tmp[dest_byte] |= (bit << dest_bit);
    }

    memcpy(s, tmp, 16);
}

void default_rc_add(uint8_t s[16], int r)
{
    uint8_t c5,c4,c3,c2,c1,c0;
    
    c5=default_rc[r]>>5;
    c4=(default_rc[r]>>4)&0x1;
    c3=(default_rc[r]>>3)&0x1;
    c2=(default_rc[r]>>2)&0x1;
    c1=(default_rc[r]>>1)&0x1;
    c0=default_rc[r]&0x1;

    s[15]^=(1<<7);
    s[2]^=c5<<7;
    s[2]^=c4<<3;
    s[1]^=c3<<7;
    s[1]^=c2<<3;
    s[0]^=c1<<7;
    s[0]^=c0<<3;
}

void default_key_add(uint8_t s[16], const uint8_t k[16])
{
    int i;

    for (i=0;i<16;i++) s[i]^=k[i];
}

void default_core_round(uint8_t s[16], const uint8_t rk[4][16], int r)
{
    default_core_slayer(s);
    default_player(s);
    default_rc_add(s,r);
    default_key_add(s,rk[r%4]);
}

void default_layer_round(uint8_t s[16], const uint8_t rk[4][16],int r)
{
    default_layer_slayer(s);
    default_player(s);
    default_rc_add(s,r);
    default_key_add(s,rk[r%4]);
}

void default_enc(uint8_t c[16], const uint8_t p[16], const uint8_t rk[4][16])
{
    int i;
    
    uint8_t s[16];

    for(i=0;i<16;i++) s[i]=p[15-i];

    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    for (i=0;i<24;i++) default_core_round(s,rk,i);

    for (i=0;i<28;i++) default_layer_round(s,rk,i);

    memcpy(c,s,16);
}

void default_rc_add_prime(uint8_t s[16])
{
    s[15]^=(1<<7);
}

void default_layer_round_prime(uint8_t s[16])
{
    default_layer_slayer(s);
    default_player(s);
    default_rc_add_prime(s);
}

void default_key_schedule(uint8_t rk[4][16], const uint8_t mk[16])
{
    int i;
    
    uint8_t mk_t[16]={0,};
    
    for(i=0;i<16;i++) mk_t[i]=mk[15-i];

    memcpy(rk[0],mk_t,16);    
    memcpy(rk[1],mk_t,16);    
    for(int i=0;i<4;i++) default_layer_round_prime(rk[1]);    
    memcpy(rk[2],rk[1],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[2]);
    memcpy(rk[3],rk[2],16);
    for(int i=0;i<4;i++) default_layer_round_prime(rk[3]);
}

void default_key_schedule_simple(uint8_t rk[4][16], const uint8_t mk[16])
{
    int i;
    
    uint8_t mk_t[16]={0,};
    
    for(i=0;i<16;i++) mk_t[i]=mk[15-i];

    memcpy(rk[0],mk_t,16);    
    memcpy(rk[1],mk_t,16);    
    memcpy(rk[2],mk_t,16);
    memcpy(rk[3],mk_t,16);
}

void default_layer_reduced(uint8_t c[16], const uint8_t p[16], const uint8_t rk[4][16], const int r)
{
    int i;

    uint8_t s[16];

    for(i=0;i<16;i++) s[i]=p[15-i];

    for (i=28-r;i<28;i++) default_layer_round(s,rk,i);

    memcpy(c,s,16);
}

void generate_random_bytes(uint8_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buffer[i] = rand() % 256; // 0~255 사이 값
    }
}

int main()
{
    int i,j;

    uint8_t c1[16]={0,};
    uint8_t c2[16]={0,};
    uint8_t rk[4][16]={{0,},};
    uint8_t p1[16]={0,};
    uint8_t p2[16]={0,};
    uint8_t mk[16]={0x82, 0x9B, 0x94, 0xB6, 0xF9, 0xB8, 0x9B ,0x94 ,0x39, 0x86, 0xB2, 0xCB, 0x7D, 0xD8, 0x31, 0x5F};
    srand(time(NULL));

    
    //generate_random_bytes(mk,16);
    default_key_schedule(rk,mk);

    printf("rk0  : 0x");
    for(i=15;i>=0;i--) 
    {
        printf("%02X",rk[0][i]);
    }              
    printf("\n"); 

    printf("rk1  : 0x");
    for(i=15;i>=0;i--) 
        {
    printf("%02X",rk[1][i]);
    }              
    printf("\n"); 

    printf("rk2  : 0x");
    for(i=15;i>=0;i--) 
    {
        printf("%02X",rk[2][i]);
    }              
    printf("\n"); 

    printf("rk3  : 0x");
    for(i=15;i>=0;i--) 
    {
        printf("%02X",rk[3][i]);
    }              
    printf("\n"); 
    printf("\n"); 
    printf("\n"); 

    for (j=15;j>=0;j--)
    {        
        generate_random_bytes(p1,16);
        memcpy(p2,p1,16);
        p2[j]^=0x1;
        
        default_layer_reduced(c1,p1,rk,6);
        default_layer_reduced(c2,p2,rk,6);
        
        printf("p1^p2: 0x");
        for(i=0;i<=15;i++) 
        {
            printf("%02X",p1[i]^p2[i]);
        }              
        printf("\n");        
        
        printf("c1^c2: 0x");
        for(i=15;i>=0;i--) 
        {
            printf("%02X",c1[i]^c2[i]);
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
        printf("\n"); 
    }    
}