#include <praktikum.h>
#include <network.h>

#include <protocol.h>

Connection con;

// returns 1 if the padding is valid and 0 otherwise
int padding_oracle(unsigned char *buf, char blocks){

  if(blocks > 2 || blocks < 1){
    printf("Invalid block count: %d\n", blocks);
    exit(1);
  }
  message req;
  memset(&req, 0, sizeof(req));
  req.type = ORACLE_REQ;
  req.oracle_req.blocks = blocks;
  memcpy(req.oracle_req.ch, buf, sizeof(req.oracle_req.ch));
  Transmit(con, &req, sizeof(req));
  message m;
  ReceiveAll(con, &m, sizeof(m));
  if(m.type != ORACLE_REP){
    printf("Invalid message type from daemon\n");
    exit(1);
  }
  return m.oracle_rep.rep;
}

char padding_attack(unsigned char *challenge, unsigned char *plaintext){
  
  char oracle_rep;
  char blocks = 2;
  int  attampts = 0;
  char plaintxt_len = 0;

  unsigned char padding_len = 1;

  unsigned char deCipher[2*BLOCK_LENGTH];

  unsigned char copy[3*BLOCK_LENGTH];
  for (size_t i = 0; i < 3*BLOCK_LENGTH; i++)
  {
      copy[i] = challenge[i];
  }
  
  
  while (1)
  { 
    attampts++;
    challenge[2*BLOCK_LENGTH-padding_len] = challenge[2*BLOCK_LENGTH-padding_len] ^ padding_len;
    oracle_rep = padding_oracle(challenge,blocks);
    printf("respone from oracle: %d\n",oracle_rep);
    challenge[2*BLOCK_LENGTH-padding_len] = copy[2*BLOCK_LENGTH-padding_len];
    if (oracle_rep == 1){
      padding_len--;
      plaintxt_len = 2*BLOCK_LENGTH - padding_len;
      
      break;
    } 
    padding_len++;
  }


  printf("padding length: %d\n", padding_len);

  for (size_t i = 1; i <= padding_len; i++)       // initialize the first padding_len deCipher
  {

    deCipher[2*BLOCK_LENGTH -i] = copy[2*BLOCK_LENGTH-i] ^ padding_len;        // dc2 = m ^ c1'  
    challenge[2*BLOCK_LENGTH -i] = deCipher[2*BLOCK_LENGTH-i] ^ (padding_len+1);    // change c1'
    
   // printf("%d\n", deCipher[3*BLOCK_LENGTH-i]);
   // printf("%d\n", deCipher[3*BLOCK_LENGTH-i] ^ copy[2*BLOCK_LENGTH-i]);
  }



  padding_len++; 

  unsigned char xor;
  blocks = 2;
  while (padding_len <= BLOCK_LENGTH)
  { 
    
    xor = 0;
    while (xor < 256)
    { 
     
      challenge[2*BLOCK_LENGTH - padding_len] = xor ;             
      oracle_rep = padding_oracle(challenge,blocks);
      printf("blocks=%d, padding_len=%2d, xor=%3d, response from oracle: %d\n", blocks,padding_len,xor,oracle_rep);
      if (oracle_rep == 1)
      {   
          
          deCipher[2*BLOCK_LENGTH - padding_len] = xor ^ padding_len;
          padding_len++;
          attampts = attampts + xor;
          if(padding_len > BLOCK_LENGTH) break;
//          printf("padding: ");
          for (size_t i = 1; i < padding_len; i++)
          {
              challenge[2*BLOCK_LENGTH -i] = deCipher[2*BLOCK_LENGTH-i] ^ padding_len;
//              printf("%d ", deCipher[2*BLOCK_LENGTH-i] ^ challenge[2*BLOCK_LENGTH-i]);
          }
          break;
      }
      xor++;
      
    }

  
  }


  blocks = 1;
  padding_len = 1;

  for (size_t i = BLOCK_LENGTH; i < 2*BLOCK_LENGTH; i++)    //retore ciphertext from copy
  {
    challenge[i] = copy[i];
  }
  

  while (padding_len <= BLOCK_LENGTH)
  {
    
    xor = 0;
    while (xor < 256)
    {
      
      challenge[BLOCK_LENGTH-padding_len] = xor;
      oracle_rep = padding_oracle(challenge,blocks);
      printf("blocks=%d, padding_len=%2d, xor=%3d, response from oracle: %d\n", blocks, padding_len,xor,oracle_rep);
      if (oracle_rep == 1)
      {
        deCipher[BLOCK_LENGTH-padding_len] = xor ^ padding_len;
        padding_len++;
        attampts = attampts + xor;
        if (padding_len > BLOCK_LENGTH) break;
        for (size_t i = 1; i < padding_len; i++)
        {
          challenge[BLOCK_LENGTH-i] = deCipher[BLOCK_LENGTH-i] ^ padding_len;
//          printf("%d ", deCipher[BLOCK_LENGTH-i] ^ challenge[BLOCK_LENGTH-i]);
        }
        
        break;
      }
      
      xor++;
    }
    
  }

  for (size_t i = 0; i < 3*BLOCK_LENGTH; i++)     // restore ciphertext from copy
  {
    challenge[i] = copy[i];
  }

 /*  for (size_t i = 0; i < 2*BLOCK_LENGTH; i++)
  { 
    plaintext[i]=challenge[i] ^ deCipher[i];
  } 
   */
  xor_block(&challenge[0], &deCipher[0], &plaintext[0], 2*BLOCK_LENGTH);     // mi =  ci-1 ^ d(ci) 
  printf("Decypted with  %d attempts:\n %s<- Here is the end \n",attampts, plaintext);
  return plaintxt_len;
}


void solution(unsigned char *buf){
  message req;
  memset(&req, 0, sizeof(req));
  req.type = SOLUTION;
  memcpy(req.solution.ch, buf, sizeof(req.solution.ch));
  Transmit(con, &req, sizeof(req));
  message m;
  ReceiveAll(con, &m, sizeof(m));
  if(m.type != SOLUTION_REP){
    printf("Invalid message type from daemon\n");
    exit(1);
  }
  if(m.solution_rep.state == 1){
    printf("AES decryption in daemon failed.\n");
    return;
  }
  if(m.solution_rep.state == 0){
    printf("Solution submitted at %s is correct.\n", Now());
    return;
  }

  printf("Daemon reports decrypted string: ");
  printstring_escaped_unsigned(stdout, m.solution_rep.ch, 2*BLOCK_LENGTH);
  printf("\n");
  if(m.solution_rep.state == 2){
    printf("Padding is invalid.\n");
  }
  if(m.solution_rep.state == 3){
    printf("String has invalid contents.\n");
  }
}

int main (int argc, char *argv[]){
  con = ConnectTo(MakeNetName(NULL), "Padding_Daemon");
  message m;
  ReceiveAll(con, &m, sizeof(m));
  if(m.type != CHALLENGE){
    printf("Invalid message type from daemon");
    exit(1);
  }
  unsigned char plaintext[2*BLOCK_LENGTH];
  unsigned char msg[2*BLOCK_LENGTH];
  unsigned char *challenge = m.challenge.ch;      // challenge is a pointer to m.challenge.ch
  // Task 1: Obtain the plaintext of challenge
  // Use padding_oracle(data, i);
  //   to send the first BLOCK_LENGTH * i bytes of data to the padding oracle
  //  not "the first BLOCK_LENGTH * i bytes of data", but "second BLOCK or third BLOCK"


  
  char plaintext_len = 0;
  
  plaintext_len = padding_attack(challenge, plaintext);
  printf("Press enter to continue: \n");

  scanf("");
  
  // Task 2: Create a valid ciphertext for the string sol_str.
  // Use  solution(ciphertext); to send the ciphertext for checking.
	
  // padding message
  char msg_len = strlen(sol_str);
  for (size_t i = 0; i < 2*BLOCK_LENGTH; i++)
  { 

    if (i >= msg_len)
    {
      msg[i] = 2*BLOCK_LENGTH-msg_len;
      
    }
    else
    {
      msg[i] = sol_str[i];
    }
  } 


  unsigned char chiff[3*BLOCK_LENGTH];

  for (size_t i = 0; i < BLOCK_LENGTH; i++)
  { 
    chiff[i] = 0;
    chiff[BLOCK_LENGTH+i] = challenge[BLOCK_LENGTH+i] ^ plaintext[BLOCK_LENGTH+i] ^ msg[BLOCK_LENGTH+i];
    chiff[2*BLOCK_LENGTH+i] = challenge[2*BLOCK_LENGTH+i];
  }

  char oracle_rep;
  unsigned char padding_len = 1;
  unsigned char xor;
  unsigned char deCipher[BLOCK_LENGTH];
  while (padding_len <= BLOCK_LENGTH)
  {
    xor = 0;
    while (xor < 256)
    {
      chiff[BLOCK_LENGTH - padding_len] = xor;
      oracle_rep = padding_oracle(chiff, 1);
      printf("finding iv[%2d]: %3d with response from oracle %d\n", BLOCK_LENGTH-padding_len, xor, oracle_rep);
      if (oracle_rep == 1)
      {
        deCipher[BLOCK_LENGTH-padding_len] = xor ^ padding_len;
        padding_len++;
        if (padding_len > BLOCK_LENGTH) break;

        for (size_t i = 1; i < padding_len; i++)
        {
          chiff[BLOCK_LENGTH-i] = deCipher[BLOCK_LENGTH - i] ^ padding_len; 
        }
        
        break;
        
      }
      xor++;
      
    }
    
  }
  
  for (size_t i = 0; i < BLOCK_LENGTH; i++)
  {
    chiff[i] = deCipher[i] ^ msg[i];
  }

  solution(chiff);
  DisConnect (con);
  exit(0);

  return 0;
}
