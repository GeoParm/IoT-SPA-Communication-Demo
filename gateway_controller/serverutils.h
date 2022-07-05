#ifndef SERVERUTILS_H
#define SERVERUTILS_H

#include <stdlib.h>
#include <string.h>

#include "dtls-ccm.h"

//size of IoT payload approximately
#define MAXBUF 60
#define DEVICEID_BYTES  2

#define KEY_LEN DTLS_CCM_BLOCKSIZE
#define N_DEVICES 1

#define RULES_TIMEOUT 2

#define AUTH_DB "./auth_devices.db"  // location of the sqlite db

static int rows_counter = 0;

int device_authentication(char *, unsigned char *);
int callback(void *, int, char **, char **);

void ufw_allow_ip_port(char *device_ip, short int port, int mode, int delay);

#endif /* #endif SERVERUTILS_H */
