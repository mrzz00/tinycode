#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>
#include "fealclient.h"


#define MAXENCRYPT 25 /* Max plain-cipher pair*/
#define SAMPLES 25
#define SUB_SPACE 1 << 16


struct block
{
  ByteType l[4];
  ByteType r[4];
};

struct block plain[SAMPLES], cipher[SAMPLES];

ByteType l0[4], r0[4], 
         l1[4], r1[4], 
         l2[4], r2[4], 
         l3[4], r3[4],
         f0[4], f1[4], f2[4], f3[4], 
         k0[2], k1[2], k2[2], k3[2];

ByteType Rot2Results[256];


ByteType key [12][2];
ByteType key_real [12][2];
ByteType key_ges [4];
ByteType k3_candidate[SAMPLES][2];
ByteType k0_candidate[SAMPLES][2];


uint8_t n_k0 = 0, n_k1 = 0, n_k2 = 0, n_k3 = 0;

void initRot2(void)
{
  int i;
  for (i = 0; i < 256; i++) {
    Rot2Results[i] = (ByteType) (i<<2 | ((i>>6)&3));
  }
}
  
#define Rot2(x) Rot2Results[(x)]
#define S0(a,b) Rot2((a+b)&255)
#define S1(a,b) Rot2((a+b+1)&255)


void F (ByteType x[4], ByteType k[2], ByteType y[4])
{
  ByteType a, b, c, d;
  a = x[0];
  b = x[0] ^ x[1];
  c = x[2] ^ x[3];
  d = x[3];
  b ^= k[0];
  c ^= k[1];
  b = S1(b,c);
  c = S0(b,c);
  a = S0(a,b);
  d = S1(c,d);
  y[0] = a; y[1] = b; y[2] = c; y[3] = d;

}

#define BIT(a,b) (((a)>>(b))&1)   // return b-th bit of a

int getBIT(ByteType a[4], uint8_t b){
    return BIT(a[b/8], b%8);
}

void generate_m_c(){

  srand(time(NULL));
  for (size_t i = 0; i < SAMPLES; i++)
  {

    for (size_t j = 0; j < 4; j++)
    {
     plain[i].l[j] = rand() & 255;
     plain[i].r[j] = rand() & 255;
    }
    feal_encrypt(&plain[i], &cipher[i]);
  }
  return;
}

void attack3(){

  for (int k = 0; k < SUB_SPACE; k++)
  { 
 
    k3[0] = k & 255;
    k3[1] = k >> 8;
   
    bool t1, t2;
    uint8_t count = 0;
    for (size_t i = 0; i < SAMPLES; i++)
    {
     
      r3[0] = cipher[i].l[0] ^ cipher[i].r[0];
      r3[1] = cipher[i].l[1] ^ cipher[i].r[1];
      r3[2] = cipher[i].l[2] ^ cipher[i].r[2];
      r3[3] = cipher[i].l[3] ^ cipher[i].r[3];
      
      F(r3, k3, f3);

      l3[0] = cipher[i].l[0] ^ f3[0];
      l3[1] = cipher[i].l[1] ^ f3[1];
      l3[2] = cipher[i].l[2] ^ f3[2];
      l3[3] = cipher[i].l[3] ^ f3[3];

      bool flag0, flag1, flag2, flag3;

      flag0 = getBIT(plain[i].l, 0) ^
              getBIT(plain[i].l, 2) ^
              getBIT(plain[i].l, 8) ^
              getBIT(plain[i].r, 0) ^
              getBIT(l3, 0) ^
              getBIT(r3, 2) ^
              getBIT(r3, 8);
     
     flag1 = getBIT(plain[i].l,  0) ^
             getBIT(plain[i].l,  8) ^
             getBIT(plain[i].l, 10) ^
             getBIT(plain[i].l, 16) ^
             getBIT(plain[i].l, 24) ^
             getBIT(plain[i].r,  0) ^
             getBIT(plain[i].r,  8) ^
             getBIT(plain[i].r, 16) ^
             getBIT(plain[i].r, 24) ^
             getBIT(l3,  0) ^
             getBIT(l3,  8) ^
             getBIT(l3, 16) ^
             getBIT(l3, 24) ^
             getBIT(r3, 10);

    flag2 = getBIT(plain[i].l,  8) ^
            getBIT(plain[i].l, 16) ^
            getBIT(plain[i].l, 18) ^
            getBIT(plain[i].l, 24) ^
            getBIT(plain[i].r, 16) ^
            getBIT(plain[i].r, 24) ^
            getBIT(l3, 16) ^
            getBIT(l3, 24) ^
            getBIT(r3,  8) ^
            getBIT(r3, 18);

    flag3 = getBIT(plain[i].l, 16) ^
            getBIT(plain[i].l, 24) ^
            getBIT(plain[i].l, 26) ^
            getBIT(plain[i].r, 24) ^
            getBIT(l3, 24) ^
            getBIT(r3, 16) ^
            getBIT(r3, 26);

    if(i == 0){
      t1 = flag1;
      t2 = flag2;
    }
    if (flag0 == 0 && flag1 == t1 && flag2 == t2 && flag3 == 0)
    {
      count ++;
    }
    }
    
    if(count == SAMPLES && n_k3 < SAMPLES){

     
      

      k3_candidate[n_k3][0] = k3[0];
      k3_candidate[n_k3][1] = k3[1];
      printf("k3 candidate found: %02x%02x\n", k3_candidate[n_k3][0], k3_candidate[n_k3][1]);
      n_k3++;
    }
  }

  printf("%d k3 candidate found\n", n_k3);
  return;
}

void attack0(){

for (int k = 0; k < SUB_SPACE; k++)
  { 
    k0[0] = k & 255;
    k0[1] = k >> 8;
   
    bool t1, t2;
    uint8_t count = 0;
    for (size_t i = 0; i < SAMPLES; i++)
    {
     
      r0[0] = plain[i].l[0] ^ plain[i].r[0];
      r0[1] = plain[i].l[1] ^ plain[i].r[1];
      r0[2] = plain[i].l[2] ^ plain[i].r[2];
      r0[3] = plain[i].l[3] ^ plain[i].r[3];
      
      F(r0, k0, f0);

      r1[0] = plain[i].l[0] ^ f0[0];
      r1[1] = plain[i].l[1] ^ f0[1];
      r1[2] = plain[i].l[2] ^ f0[2];
      r1[3] = plain[i].l[3] ^ f0[3];

      bool flag0, flag1, flag2, flag3;

      flag0 = getBIT(plain[i].l, 2) ^
              getBIT(plain[i].l, 8) ^
              getBIT(plain[i].r, 2) ^
              getBIT(plain[i].r, 8) ^
              getBIT(cipher[i].l, 0) ^
              getBIT(cipher[i].l, 2) ^
              getBIT(cipher[i].l, 8) ^
              getBIT(cipher[i].r, 0) ^
              getBIT(r1, 0);
     
     flag1 = getBIT(plain[i].l, 10) ^
             getBIT(plain[i].r, 10) ^
             getBIT(cipher[i].l,  0) ^
             getBIT(cipher[i].l,  8) ^
             getBIT(cipher[i].l, 10) ^
             getBIT(cipher[i].l, 16) ^
             getBIT(cipher[i].l, 24) ^
             getBIT(cipher[i].r,  0) ^
             getBIT(cipher[i].r,  8) ^
             getBIT(cipher[i].r, 16) ^
             getBIT(cipher[i].r, 24) ^
             getBIT(r1,  0) ^
             getBIT(r1,  8) ^
             getBIT(r1, 16) ^
             getBIT(r1, 24) ;

    flag2 = getBIT(plain[i].l,  8) ^
            getBIT(plain[i].l, 18) ^
            getBIT(plain[i].r,  8) ^
            getBIT(plain[i].r, 18) ^
            getBIT(cipher[i].l,  8) ^
            getBIT(cipher[i].l, 16) ^
            getBIT(cipher[i].l, 18) ^
            getBIT(cipher[i].l, 24) ^
            getBIT(cipher[i].r, 16) ^
            getBIT(cipher[i].r, 24) ^
            getBIT(r1, 16) ^
            getBIT(r1, 24) ;

    flag3 = getBIT(plain[i].l, 16) ^
            getBIT(plain[i].l, 26) ^
            getBIT(plain[i].r, 16) ^
            getBIT(plain[i].r, 26) ^
            getBIT(cipher[i].l, 16) ^
            getBIT(cipher[i].l, 24) ^
            getBIT(cipher[i].l, 26) ^
            getBIT(cipher[i].r, 24) ^
            getBIT(r1, 24) ;

    if(i == 0){
      t1 = flag1;
      t2 = flag2;
    }
    if (flag0 == 0 && flag1 == t1 && flag2 == t2 && flag3 == 0)
    {
      count ++;
    }
    }
    
    if(count == SAMPLES && n_k0 < SAMPLES){

      k0_candidate[n_k0][0] = k0[0];
      k0_candidate[n_k0][1] = k0[1];
      printf("k0 candidate found: %02x%02x\n", k0_candidate[n_k0][0] ,  k0_candidate[n_k0][1]);
    
      n_k0++;
    }
  }
  printf("%d k0 candidate found\n", n_k0);
  return;
}

void attack1_2(){

  bool k1_found = 0, k2_found = 0;
  printf("Attack start:\n");

  for (size_t k3_try = 0; k3_try < n_k3; k3_try++)
  {
    for (size_t k0_try = 0; k0_try < n_k0; k0_try++){


      printf(" k3 = %02x%02x", k3_candidate[k3_try][0], k3_candidate[k3_try][1]);
      printf(" k0 = %02x%02x\n", k0_candidate[k0_try][0], k0_candidate[k0_try][1]);

      for (size_t k = 0; k < SUB_SPACE; k++)
      {
        k1[0] = k & 255;
        k1[1] = k >> 8;
        k2[0] = k & 255;
        k2[1] = k >> 8;
        uint8_t count1 = 0, count2 = 0;
        for (size_t i = 0; i < SAMPLES; i++)
        {
            l0[0] = plain[i].l[0];
            l0[1] = plain[i].l[1];
            l0[2] = plain[i].l[2];
            l0[3] = plain[i].l[3];

            r0[0] = plain[i].l[0] ^ plain[i].r[0];
            r0[1] = plain[i].l[1] ^ plain[i].r[1];
            r0[2] = plain[i].l[2] ^ plain[i].r[2];
            r0[3] = plain[i].l[3] ^ plain[i].r[3];

            F(r0, k0_candidate[k0_try], f0);

            r1[0] = l0[0] ^ f0[0];
            r1[1] = l0[1] ^ f0[1];
            r1[2] = l0[2] ^ f0[2];
            r1[3] = l0[3] ^ f0[3];

            l1[0] = r0[0];
            l1[1] = r0[1];
            l1[2] = r0[2];
            l1[3] = r0[3];

            l2[0] = r1[0];
            l2[1] = r1[1];
            l2[2] = r1[2];
            l2[3] = r1[3];

            r3[0] = cipher[i].l[0] ^ cipher[i].r[0];
            r3[1] = cipher[i].l[1] ^ cipher[i].r[1];
            r3[2] = cipher[i].l[2] ^ cipher[i].r[2];
            r3[3] = cipher[i].l[3] ^ cipher[i].r[3];
            
            F(r3, k3_candidate[k3_try], f3);

            

            l3[0] = cipher[i].l[0] ^ f3[0];
            l3[1] = cipher[i].l[1] ^ f3[1];
            l3[2] = cipher[i].l[2] ^ f3[2];
            l3[3] = cipher[i].l[3] ^ f3[3];

            r2[0] = l3[0];
            r2[1] = l3[1];
            r2[2] = l3[2];
            r2[3] = l3[3];
            
            
            F(r1,k1,f1);

            if(
              (f1[0] == (l1[0] ^ r2[0])) &&
              (f1[1] == (l1[1] ^ r2[1])) &&
              (f1[2] == (l1[2] ^ r2[2])) &&
              (f1[3] == (l1[3] ^ r2[3])) 
            ){
              count1++;
            }

            if (count1 == SAMPLES)
            {
              
              key[1][0] = k1[0];
              key[1][1] = k1[1];
              key[0][0] = k0_candidate[k0_try][0];
              key[0][1] = k0_candidate[k0_try][1];
              key[3][0] = k3_candidate[k3_try][0];
              key[3][1] = k3_candidate[k3_try][1];
              printf("k0 found: %02x%02x\n", key[0][0],key[0][1]);
              printf("k3 found: %02x%02x\n", key[3][0],key[3][1]);
              printf("k1 found: %02x%02x\n", key[1][0],key[1][1]);
              k1_found = 1;
              if (k2_found == 1)
              {
                return;
              }
              
            }

            F(r2,k2,f2);
              if(
                (f2[0] == (l2[0] ^ r3[0])) &&
                (f2[1] == (l2[1] ^ r3[1])) &&
                (f2[2] == (l2[2] ^ r3[2])) &&
                (f2[3] == (l2[3] ^ r3[3])) 
              ){
                count2++;
              }
              
              if (count2 == SAMPLES)
              {
                key[2][0] = k2[0];
                key[2][1] = k2[1];
                printf("k2 found: %02x%02x\n", k2[0], k2[1]);
                k2_found = 1;
                if (k1_found == 1)
                {
                  return;
                }
                
                
              }

            

        }
        
      }
  
  }
  }
  
 
 
}


void attacke (void)
{
   generate_m_c();
   attack3();
   attack0();
   attack1_2();
  
}

int main (void)
{
  int t; /* temporaere Variable */

  initRot2 ();
  feal_connect();
  if ((t=feal_new_key ()) < 0) {
    fprintf (stderr, "Fehler in feal_new_key: %d\n", t);
    exit (1);
  }
  attacke ();
  memset (key[4], 0, 8*2);
  memset (key_real, 0, 12*2);
  t = feal_check_sub (key, key_real, key_ges);
  if (t > 0) {
    printf ("Der Schluessel war richtig: %02x%02x %02x%02x %02x%02x %02x%02x\n",
      key[0][0], key[0][1], key[1][0], key[1][1], key[2][0], key[2][1],
      key[3][0], key[3][1]);
    printf ("Der Gesamtschluessel, aus dem diese Rundenschluessel entstanden,\n");
    printf ("war: %02x%02x%02x%02x%02x%02x%02x%02x\n", key_ges[0], key_ges[1],
      key_ges[2], key_ges[3], key_ges[4], key_ges[5], key_ges[6], key_ges[7]);
  } else if (t < 0) {
    fprintf (stderr, "Fehler in feal_check_sub: %d\n", t);
    exit (1);
  } else {
    printf ("Der Schluessel war falsch.\n\n");
    printf ("Berechneter Schluessel:    %02x%02x %02x%02x %02x%02x %02x%02x\n",
      key[0][0], key[0][1], key[1][0], key[1][1], key[2][0], key[2][1],
      key[3][0], key[3][1]);
    printf ("Tatsaechlicher Schluessel: %02x%02x %02x%02x %02x%02x %02x%02x\n",
      key_real[0][0], key_real[0][1], key_real[1][0], key_real[1][1],
      key_real[2][0], key_real[2][1], key_real[3][0], key_real[3][1]);
    printf ("Der Gesamtschluessel, aus dem diese Rundenschluessel entstanden,\n");
    printf ("war: %02x%02x%02x%02x%02x%02x%02x%02x\n", key_ges[0], key_ges[1],
      key_ges[2], key_ges[3], key_ges[4], key_ges[5], key_ges[6], key_ges[7]);
  }


  exit (0);
}


