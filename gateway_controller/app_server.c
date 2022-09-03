#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>

#include <errno.h>

#include <string.h>

//size of IoT payload approximately
#define MAXBUF 60

int main(int argc, char *argv[])
{
   int sock;
   int status, s_out;
   struct sockaddr_in6 sin6;
   int sin6len;
   int app_server_port;

   unsigned char buffer[MAXBUF];  // array to store incoming data from recvfrom function
   char * response = (char *)malloc(50*sizeof(char));
   char in_addr_str[INET6_ADDRSTRLEN];  // character array to store the sender's ip address in human readable format.


   //open the socket
   sock = socket(PF_INET6, SOCK_DGRAM,0);

   sin6len = sizeof(struct sockaddr_in6);

   memset(&sin6, 0, sin6len);

  // The listening port is either the default one (5240) or
  // the one provided as argument.
  if (argc == 1){
    app_server_port = 5240;
  }
  else if (argc == 2){
    app_server_port = atoi(argv[1]);
  }
  else{
    printf("Invalid number of arguments. Exiting.. ");
    return -1;
  }
   sin6.sin6_port = htons(app_server_port);
   sin6.sin6_family = AF_INET6;
   sin6.sin6_addr = in6addr_any;

//connect sockets with setting
   status = bind(sock, (struct sockaddr *)&sin6, sin6len);

   if(-1 == status)
     perror("bind"), exit(1);

//...server starts listening...
   status = getsockname(sock, (struct sockaddr *)&sin6, &sin6len);
// print listening port
   printf("Application Server listening at port %d for incoming messages.\n", ntohs(sin6.sin6_port));

  while (1)
  {

    // using recvfrom to receive app payload
     status = recvfrom(sock, buffer, MAXBUF, 0,
  		     (struct sockaddr *)&sin6, &sin6len);
      printf("incoming buffer size: %d\n", status);
      printf("buffer : \n");

      printf("%s\n",buffer);
      printf("\n --- End of Incoming Message --- \n");

      /*
      inet_ntop function is use to translate sender's ip address from bytes to human readable format.
      */
      printf("from IP address %s\n", inet_ntop(AF_INET6, &(sin6.sin6_addr), in_addr_str, INET6_ADDRSTRLEN));
      printf("\n Replying to source device..\n");
      memcpy(response, buffer, status);
      strcat(response, " acknowledged.");
      s_out = sendto(sock, (const char *)response, status + 14 * sizeof(char), 0,
   		     (struct sockaddr *)&sin6, sin6len);
  }

   shutdown(sock, 2);
   close(sock);
   return 0;
}
