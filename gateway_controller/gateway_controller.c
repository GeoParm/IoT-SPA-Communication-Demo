#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <time.h>

#include <string.h>


#include "utilfunctions.h"
#include "serverutils.h"

#include "dtls-ccm.h"


int main(int argc, char *argv[])
{
   int sock;
   int status;
   int inbuf_size;
   struct sockaddr_in6 sin6;
   int sin6len;
   int gateway_controller_port;

   unsigned char key[DTLS_CCM_BLOCKSIZE];  // array to store the encrypton key that is downloaded from database
   unsigned char nonce_payload[DTLS_CCM_NONCE_SIZE + 1];
   unsigned char buffer[MAXBUF];  // array to store incoming data from recvfrom function
   char in_addr_str[INET6_ADDRSTRLEN];  // character array to store the sender's ip address in human readable format.
   short int service_port;  // variable to store the required port according to the SPA incoming message.
   char device_id[2*DEVICEID_BYTES];  // variable to store the device ID of the SPA message sender device.

   //open the socket
   sock = socket(PF_INET6, SOCK_DGRAM,0);

   sin6len = sizeof(struct sockaddr_in6);

   memset(&sin6, 0, sin6len);

//define the struct sin6 fields for ipv6 sockets connection.
//Gateway-Controller default listening port is 5678. If a different port is preferred, it should be provided
// as an argument.
  if (argc == 1){
    gateway_controller_port = 5678;
  }
  else if (argc == 2){
    gateway_controller_port = atoi(argv[1]);
  }
  else{
    printf("Invalid number of arguments. Exiting.. ");
    return -1;
  }
   sin6.sin6_port = htons(gateway_controller_port);
   sin6.sin6_family = AF_INET6;
   sin6.sin6_addr = in6addr_any;

//connect sockets with setting
   status = bind(sock, (struct sockaddr *)&sin6, sin6len);

   if(-1 == status)
     perror("bind"), exit(1);

//...server starts listening...
   status = getsockname(sock, (struct sockaddr *)&sin6, &sin6len);
   printf("Gateway controller listening at port %d for incoming messages.\n", ntohs(sin6.sin6_port));

  while (1)
  {

    
     inbuf_size = recvfrom(sock, buffer, MAXBUF, 0,
  		     (struct sockaddr *)&sin6, &sin6len);
      printf("incoming buffer size: %d\n", inbuf_size);
      printf("buffer : \n");

      dump(buffer, inbuf_size);
      printf("\n --- End of Incoming Message --- \n");

      /*
      inet_ntop function is use to translate sender's ip address from bytes to human readable format.
      */
      printf("from IP address %s\n", inet_ntop(AF_INET6, &(sin6.sin6_addr), in_addr_str, INET6_ADDRSTRLEN));

      printf("\n");
      printf("Decrypting message.. \n");
      memcpy(nonce_payload, buffer + 3, DTLS_CCM_NONCE_SIZE + 1 );  // nonce begins after the 3 first bytes
      // TODO define nonce position in transmitted message

      // With the following lines, the device id is copied from the
      // incoming buffer and stored in the corresponing variable
      int devid_idx = 0;
      char * device_id_p = device_id;

      while (devid_idx<DEVICEID_BYTES){
        device_id_p += sprintf(device_id_p, "%02X", buffer[devid_idx]);
        devid_idx++;
      }
      
      printf("\n");
      printf("Searching for device id '%s' record in Authentication DB... \n", device_id);

      unsigned char * key_p = (unsigned char *)(&key);
      int det = device_authentication(device_id, key_p);


      printf("Attempting to decrypt with downloaded key.. \n");
      long int len = ccm_decrypt(buffer, key_p,
                        nonce_payload,
                        (long int)inbuf_size);
      if (len > 0){
        memcpy(&service_port, &buffer[LA], sizeof(short int));
        printf("The client is accepted. \n");
        printf("The required port is %hd.\n", service_port);
    		printf("Adding access rule at the firewall...\n");

        // function ufw_allow_ip_port is explained in serverutils.c
        ufw_allow_ip_port(in_addr_str, service_port, 0,0);
        sleep(1);
        printf("Scheduling rule timeout...\n");
        ufw_allow_ip_port(in_addr_str, service_port, 1,RULES_TIMEOUT);
      }
      else{
    		printf("The client is not accepted\n");
    	}
  }

   shutdown(sock, 2);
   close(sock);
   return 0;
}
