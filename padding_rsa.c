#include <praktikum.h>
#include <network.h>
#include <stdbool.h>
#include <protocol.h>

Connection con;

const int local = 1;
struct rsa_key k;

void getCi(mpz_t ci, mpz_t c, mpz_t s, mpz_t e, mpz_t N){

  mpz_t cs;
  mpz_init(cs);
  mpz_powm(cs,s,e,N);     // cs = s^e mod N      
  mpz_mul(ci,c,cs);       // E(m*s) = E(m)*cs mod N
  mpz_mod(ci,ci,N);
  mpz_clear(cs);
  return;
}

void getB(mpz_t _B,  mpz_t _2B, mpz_t _3B,int base, int exp){

  mpz_ui_pow_ui(_B,base,exp);
  mpz_mul_ui(_2B,_B,2);
  mpz_mul_ui(_3B,_B,3);
  mpz_sub_ui(_3B,_3B,1);   // _3b = 3B-1
  return;
}

void getRa_Rb(mpz_t ra, mpz_t rb, mpz_t _2B, mpz_t _3B, mpz_t si, mpz_t N ){
  mpz_mul(ra,_2B, si);                    // ra = (2B*si-3B+1)/N
  mpz_sub(ra, ra, _3B);
  mpz_cdiv_q(ra,ra,N);
  mpz_mul(rb, _3B, si);                   // rb = ((3B-1)*si-2B)/N
  mpz_sub(rb, rb, _2B);
  mpz_fdiv_q(rb,rb,N);
  return;
}

void getMa_Mb(mpz_t ma, mpz_t mb, mpz_t _2B,mpz_t _3B, mpz_t N, mpz_t ri, mpz_t si){

    mpz_mul(ma,ri,N);             // ma = (2B+rN)/s
    mpz_add(ma,ma,_2B);
    mpz_cdiv_q(ma,ma,si);
    mpz_mul(mb,ri,N);             // mb = (3B-1+rN)/s
    mpz_add(mb,mb,_3B);
    mpz_fdiv_q(mb,mb,si);
    return;
}

void getSa_Sb(mpz_t sa, mpz_t sb, mpz_t ma, mpz_t mb, mpz_t _2B, mpz_t _3B, mpz_t N, mpz_t ri){

  mpz_mul(sa,ri,N);             // sa = (2B+rN)/mb
  mpz_add(sa,sa,_2B);
  mpz_cdiv_q(sa,sa,mb);
  mpz_mul(sb,ri,N);             // sa = (3B-1+rN)/ma
  mpz_add(sb,sb,_3B);
  mpz_fdiv_q(sb,sb,ma);
  return;
}

void getRi(mpz_t ri, mpz_t si, mpz_t mb,mpz_t _2B, mpz_t N){

    mpz_mul(ri,mb,si);          // r >= 2(mb*si-2B)/N 
    mpz_sub(ri,ri,_2B);         // it works with B
    mpz_mul_ui(ri,ri,2);
    mpz_cdiv_q(ri,ri,N);
    return;
}
// returns 1 if the padding is valid and 0 otherwise
int padding_oracle(mpz_t c){
  if(local) {
    mpz_t m;
    mpz_init(m);
    mpz_powm(m, c, k.d, k.N);
    int ret = calc_padding_oracle(m, NULL) != NULL;
    mpz_clear(m);
    return ret;
  }
  oracle_req req;
  enum message_type type = ORACLE_REQ;
  store_mpz(req.c, sizeof(req.c), c);
  Transmit(con, &type, sizeof(type));
  Transmit(con, &req, sizeof(req));
  oracle_rep m;
  ReceiveAll(con, &m, sizeof(m));
  return m.rep;

}

void submit_solution( mpz_t m){
  if(local){
    printf("Skipping submition, because running in offline mode.\n");
    return;
  } else {
    solution sol;
    store_mpz(sol.m, sizeof(sol.m), m);
    enum message_type type = SOLUTION;
    Transmit(con, &type, sizeof(type));
    Transmit(con, &sol, sizeof(sol));
    solution_rep m;
    ReceiveAll(con, &m, sizeof(m));
    if(m.state == 0){
      printf("Solution was accepted\n");
      const char *now = Now();
      printf("Solution submitted at %s\n", now);
    }else{
      printf("Solution was rejected\n");
    }
  }
}

int main (int argc, char *argv[]){

  mpz_t N, e, c;
  mpz_init(N); mpz_init(e); mpz_init(c);

  if(local){
    genkey(&k);

    mpz_t m;
    mpz_init(m);
    pad_and_import(m, "This is the secret test message");
    mpz_set(N, k.N);
    mpz_set(e, k.e);
    mpz_powm(c, m, k.e, k.N);
    mpz_clear(m);
  } 
  else {
    con = ConnectTo(MakeNetName(NULL), "RSA_Padding_Daemon");
    challenge chall;
    ReceiveAll(con, &chall, sizeof(chall));   // data(N, e, c) received from Daemon
    mpz_import(N, sizeof(chall.N), 1,1,1,0, chall.N);
    mpz_import(e, sizeof(chall.e), 1,1,1,0, chall.e);
    mpz_import(c, sizeof(chall.c), 1,1,1,0, chall.c);
  }
  
  fprintf(stderr, "N: %s\n",  mpz_get_str(NULL, 16, N));
  fprintf(stderr, "e: %s\n",  mpz_get_str(NULL, 16, e));
  fprintf(stderr, "c: %s\n",  mpz_get_str(NULL, 16, c));


  // Task: Obtain the plaintext of c
  // Use padding_oracle(c_2);
  //   to check (returns 1) if the decryption of c_2 has valid padding
	

  mpz_t _B, _2B, _3B,  ci,  ra, rb, ri,  ma, mb, cm, m,  sa,sb,si, qct, iteration;


  
  mpz_init(_B);
  mpz_init(_2B);
  mpz_init(_3B);

  mpz_init(ci);

  mpz_init(ra);
  mpz_init(rb);         
  mpz_init(ri);            // ra <= ri <= rb
  
  mpz_init(ma);
  mpz_init(mb);         
  mpz_init(cm);
  mpz_init(m);              // ma <= m <= mb
  
  mpz_init(sa);
  mpz_init(sb);
  mpz_init(si);             // sa <= si <= sb
  
  mpz_init(qct);
  mpz_init(iteration);

  bool siFound = false;

  int base = 2;
  int exp = RSA_BITS - 16;
  getB(_B,_2B,_3B,base,exp);

  mpz_cdiv_q(si,N,_3B);
  mpz_set_ui(qct,0);

  while (true)
  {
      mpz_add_ui(qct,qct,1);
      getCi(ci,c,si,e,N);
      gmp_printf("search for s1, query oracle: %Zd\n", qct);
      if (padding_oracle(ci)) 
      {
          gmp_printf("padding correct c1 \n");
          gmp_printf("here is s1 = %Zd found within %Zd query\n", si, qct);
          break;
      }
      mpz_add_ui(si,si,1);  
  }

    getRa_Rb(ra,rb, _2B, _3B, si, N);

    unsigned long _ra, _rb;
    _ra = mpz_get_ui(ra);
    _rb = mpz_get_ui(rb);

    if (mpz_cmp(rb,ra) )     // rb > ra ---> positive
    {
      printf("there are %ld intervals for m\n", _rb-_ra+1);
      return 0;
    }

    mpz_set(ri,ra);
    getMa_Mb(ma,mb,_2B,_3B,N,ri,si);  
    getRi(ri,si,mb,_2B,N);
    mpz_set_ui(iteration,0);

    while (mpz_cmp(mb,ma))
    {
      mpz_set_ui(qct,0);
      mpz_add_ui(iteration,iteration,1);
      getSa_Sb(sa,sb,ma,mb,_2B,_3B,N,ri);
      mpz_set(si,sa);
      siFound = false;

      while (!siFound && mpz_cmp(sb,si) >= 0)
        {
            getCi(ci,c,si,e,N);
            mpz_add_ui(qct,qct,1);
            gmp_printf("search for m wirh ri= %Zx, iteraion %Zd query oracle: %Zd\n",ri, iteration, qct);
            
            if (padding_oracle(ci)) 
            {
                siFound = true;
                mpz_add_ui(qct,qct,1);
                getMa_Mb(ma,mb,_2B,_3B,N,ri,si);	
                getRi(ri,si,mb,_2B,N);
                getSa_Sb(sa,sb,ma,mb,_2B,_3B,N,ri);
                break ;
            }
            mpz_add_ui(si,si,1);  
        }

    if(!siFound){
        mpz_add_ui(ri,ri,1);
        }
    }
  
  printf("found!!!!\n"); 
  mpz_set(m,ma);
  mpz_powm(cm,m,e,N);
  gmp_printf("ri: %Zx\n", ri);
  gmp_printf("si: %Zx\n", si);
  gmp_printf("c:  %Zx\n",c);
  gmp_printf("cm: %Zx\n",cm);
  submit_solution(m);

  if(!local) {
    DisConnect (con);
  }
  exit(0);
  mpz_clears(_B, _2B, _3B,  ci,  ra, rb, ri,  ma, mb, cm, m,  sa,sb,si, qct, iteration, N, e, c);
  return 0;
}
