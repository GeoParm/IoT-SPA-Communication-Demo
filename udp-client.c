#include <string.h>
#include "dtls-ccm.h"
#include "utilfunctions.h"

#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"

#include "sys/log.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1

#define SPA_SERVER_PORT	5678
#define SPA_CLIENT_PORT	8765

#define UDP_SERVER_PORT	5000
#define UDP_CLIENT_PORT	5000

#define RETRIES_THRESHOLD 3

#define SEND_INTERVAL		  (60 * CLOCK_SECOND)
#define UDP_SEND_INTERVAL		  (30 * CLOCK_SECOND)

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif

static struct simple_udp_connection spa_conn, udp_conn;

long int len;
int n;

static unsigned counter_snd = 0;  // counter of the outgoing messages
static unsigned counter_rcv = 0;  // counter of the incoming messages
static unsigned retries = 0;  // counter that is increased each time a message
                              // is retransmitted.

/*---------------------------------------------------------------------------*/
PROCESS(spa_client_process, "SPA client");
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&spa_client_process, &udp_client_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
  counter_rcv++;
  if (counter_snd == counter_rcv){
    retries = 0;
  }
#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");

}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(spa_client_process, ev, data)
{
  static struct etimer periodic_timer;

  unsigned char key[DTLS_CCM_BLOCKSIZE] =
   { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF};	/* AES key */;
  unsigned char nonce_payload[DTLS_CCM_NONCE_SIZE + 1];
  unsigned char aad[LA];
  unsigned char header_payload[L_HEADER];
  static uint64_t counter = 0;

  Nonce nonce = {
    { 0xaa,0xbb,0xcc,0xdd},
    &counter
  };  // nonce initialization


  Spa_data spa_msg_content = {
    {0xD6, 0xB0},  // id_mote
    0,  // encryption type
    nonce,
    UDP_SERVER_PORT  // port of the required service
  };  // initialize a message header

  uip_ipaddr_t dest_ipaddr;
    uip_ip6addr(&dest_ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 1);

  uint64_t * c = spa_msg_content.nonce.counter;

  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&spa_conn, SPA_CLIENT_PORT, NULL,
                      SPA_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    /* An SPA packet is sent only when retries exceeds a threshold. */
    if (retries >= RETRIES_THRESHOLD)
    {
      if(NETSTACK_ROUTING.node_is_reachable() ) {
        /* Send to DAG root */

        // Create nonce
        unsigned char * p = (unsigned char *)(&nonce_payload);  // set p to indicate to nonce array
        *p = 0x00;  // first byte of nonce is 0
        memcpy(p + 1, nonce.random, sizeof(nonce.random));
        memcpy(p + 1 + (int)sizeof(nonce.random), c, sizeof(*c));
        LOG_INFO("Nonce counter: %d \n", (int)*c);
        // dump(p, DTLS_CCM_NONCE_SIZE + 1);  // print the contents of nonce_payload buffer


        p = (unsigned char *)(&aad);
        int len_aad = prepare_additional(p, spa_msg_content, nonce_payload, DTLS_CCM_NONCE_SIZE+1);
        // LOG_INFO("Additional data payload : ");
        // dump(p, LA);

      // Copy the text to encrypt in the final payload buffer
      memcpy(&header_payload, p, len_aad);
      LOG_INFO("Length of additional : %d.\n", len_aad);
        // Copy the text to encrypt in the final payload buffer
      uint16_t * srv = (uint16_t *)(&spa_msg_content.service);

      memcpy((unsigned char *)(&header_payload)+len_aad, srv, sizeof(spa_msg_content.service));
      LOG_INFO("Text to encrypt ");
      dump(header_payload + LA, L_ENC);

      unsigned char * key_p = (unsigned char *)(&key);
      long int len = ccm_encrypt(header_payload, key_p,
                                  nonce_payload,
                                  aad);
        *c = next_counter(*c);  // increase counter

        simple_udp_sendto(&spa_conn, header_payload, len, &dest_ipaddr);
      } else {
        LOG_INFO("Not reachable yet\n");
      }
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static char str[32];
  uip_ipaddr_t dest_ipaddr;
  uip_ip6addr(&dest_ipaddr, 0xfd00, 0, 0, 0, 0, 0, 0, 1);

  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() ) {
      /* Send to DAG root */
      if (counter_rcv == counter_snd)
      {
        counter_snd++;
        LOG_INFO("Sending request %u to ", counter_snd);
        LOG_INFO_6ADDR(&dest_ipaddr);
        LOG_INFO("(attempts %u)\n", retries);
        snprintf(str, sizeof(str), "hello %d", counter_snd);
        simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);

      }
      else{
        retries++;
        simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
        LOG_INFO("Msg %u not acknowledged (retries: %u)\n",
        counter_snd,retries);
      }
    } else {
      LOG_INFO("Not reachable yet\n");
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, UDP_SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
