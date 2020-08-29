
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

int power(int base, int exp){
  int result = 1;
  for (size_t i = 0; i < exp; i++)
  {
    result = result*base;
  }
  return result;
}

void doexp(mpz_t x, mpz_t y, mpz_t z, mpz_t p)
{

// max. k-ary sliding window Exponentiation with reduced precomputation 
int k = 18;                           // when k >= 19, Segmentation fault
int base = 2;
int long b = power(base, k);

mpz_t Reduced_LUT[b];
mpz_t temp;
mpz_init(temp);

// Initialasition and precomputaion for reduced lookup table
for (size_t i = 0; i < b; i++)
{

  mpz_init(Reduced_LUT[i]);
  if(i == 0)
  {
    mpz_set_si(temp,1);
    mpz_set(Reduced_LUT[i], temp);                                  // x[0] <-- 1 mod p
  }
  if(i == 1)
  {
    mpz_set(Reduced_LUT[i], x);                                     // x[1] <-- x mod p
    mpz_mod(Reduced_LUT[i],Reduced_LUT[i], p);
  }
  if(i == 2)
  {
    mpz_mul (Reduced_LUT[i], x, x);                                 // x[2] <-- x^2 mod p
    mpz_mod(Reduced_LUT[i], Reduced_LUT[i],p);
  }
  
}

for (size_t i = 1; i < b/2; i++)
{
  mpz_mul(Reduced_LUT[2*i+1],Reduced_LUT[2*i-1],Reduced_LUT[2]);    // x[2i+1] <-- x[2i-1]*x[2] mod p
  mpz_mod(Reduced_LUT[2*i+1],Reduced_LUT[2*i+1],p);
}


// modular exponentiation

mpz_set_ui(z,1);

int bitptr = mpz_sizeinbase(y, 2)-1;                                // pointer to start of current window


while (bitptr >= 0)
{

  if(bitptr < k)                                                    // the max length of last window
  {
    k = bitptr+1;
  }


  if(mpz_tstbit(y,bitptr) == 0)                                     // skip zero bits between windows
  {   

      mpz_mul(z,z,z);
      mpz_mod(z,z,p);
      bitptr--;
  }

  else
  { 
    
    int index = 0;                                                  
    int window = k;

    while (window > 1 && mpz_tstbit(y,bitptr-window+1)!=1)          // find the max length of window
    {
      window--;
    }
    
    for (size_t i = 0; i < window; i++)                             
    {
      mpz_mul(z,z,z);                                               // z <-- z^2^window mod p
      mpz_mod(z,z,p);
      index = index + power(base,window-i-1)*mpz_tstbit(y,bitptr-i);//find the index for lookup table
    }
    
    mpz_mul(z,z, Reduced_LUT[index]);                                // z <-- z*(x[2i+1])           
    mpz_mod(z,z,p);

    bitptr = bitptr-window;                                           
  }
  
}
mpz_clear(Reduced_LUT);
return;
}



