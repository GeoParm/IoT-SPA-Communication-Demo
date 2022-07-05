#include "utilfunctions.h"

#include <stdio.h>
#include <string.h>

#include "dtls-ccm.h"

uint64_t next_counter(uint64_t current)
{
    if(current>0xFFFFFFFF)
        current = 0x00000000;
    else
        current++;
    return current;
}

void dump(unsigned char *buf, uint8_t len) {
  uint8_t i = 0;
  while (i < len) {
    printf("%02x ", buf[i++]);
    if (i % 4 == 0)
      printf(" ");
    if (i % 16 == 0)
      printf("\t");
  }
  printf("\n");
}

int prepare_additional(unsigned char * p, Spa_data h, unsigned char * n, uint8_t n_len){
  /*
  *P : Pointer to a buffer of size LA
  h : Struct of type Spa_data with the included additional data
  n : Nonce buffer
  n_len: Length of Nonce buffer
  */
  int pos_idx=0;  // position index of the target buffer
  memcpy(p, &h.id_mote, sizeof(h.id_mote));
  pos_idx += (int)sizeof(h.id_mote);
  memcpy(p + pos_idx, &h.crypto_suite, sizeof(h.crypto_suite));
  pos_idx += (int)sizeof(h.crypto_suite);
  memcpy(p + pos_idx, n, n_len);
  pos_idx += (int)n_len;
  // printf("POS IDX : %d\n", pos_idx);
  return pos_idx;
}

long int
ccm_encrypt(unsigned char *buf, unsigned char *key,
			 unsigned char *nonce,
			 const unsigned char *aad)
{
  /*
  buf: buffer to write the final payload. It already contains the
        data to encrypt
  key: The key to use to encypt the data
  nonce: The nonce buffer
  aad: The additional buffer
  */
  rijndael_ctx ctx;

   // encrypt with key
    if (rijndael_set_key_enc_only(&ctx, key, 8*DTLS_CCM_BLOCKSIZE) < 0) {
      printf("cannot set key\n");
      return -1;
    }

    long int len;
    len = dtls_ccm_encrypt_message(&ctx, L_MAC, L_L,
      nonce,
		  buf+LA, L_ENC,
			aad, LA);
    if (len > 0){
      len = len + LA;
      printf("MSG encrypted succesfully with length %ld\n", len);
      dump(buf, len);
    }
    else{
      return -1;
    }
    return len;

}


long int
ccm_decrypt(unsigned char *buf, unsigned char *key,
			 unsigned char *nonce,
			uint16_t datalen)
{
  rijndael_ctx ctx;

   // encrypt with key
    if (rijndael_set_key_enc_only(&ctx, key, 8*DTLS_CCM_BLOCKSIZE) < 0) {
      printf("cannot set key\n");
      return -1;
    }

    long int len;
    len = dtls_ccm_decrypt_message(&ctx, L_MAC, L_L,
      nonce,
		  buf + LA, datalen - LA,
			buf, LA);
    if (len >= 0){
      printf("MSG decrypted succesfully with length %ld\n", len);
      dump(buf + LA, len);
    }
    else{
      printf("Failed to decrypt mesage\n");
      return -1;
    }
    return len;

}
