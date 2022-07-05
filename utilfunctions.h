#ifndef UTILFUNCTIONS_H
#define UTILFUNCTIONS_H

#include "contiki.h"

#define L_MAC   8
#define L_L  2
#define LA        16  // Length of additional
#define L_ENC     2  //
#define L_HEADER  LA+L_ENC+L_MAC  /**< length of message payload> **/

typedef struct {
    unsigned char random[4];
    uint64_t  * counter;
}Nonce;

typedef struct {
  uint8_t id_mote[2];  // 2 bytes (last bytes of physical MAC addr)
	uint8_t crypto_suite;
	Nonce nonce;
	uint16_t service;
  // uint8_t mac[8];
}Spa_data;


int prepare_additional(unsigned char *, Spa_data, unsigned char *, uint8_t);

long int
ccm_encrypt(unsigned char *buf, unsigned char *key,
			 unsigned char *nonce,
			 const unsigned char *aad);

long int
ccm_decrypt(unsigned char *buf, unsigned char *key,
			 unsigned char *nonce,
			uint16_t datalen);


uint64_t next_counter(uint64_t current);
void dump(unsigned char *buf, uint8_t len);

#endif
