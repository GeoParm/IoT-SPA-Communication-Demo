CONTIKI_PROJECT = udp-client udp-server
all: $(CONTIKI_PROJECT)

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += rijndael.c
PROJECT_SOURCEFILES += dtls-ccm.c
PROJECT_SOURCEFILES += utilfunctions.c


CONTIKI=../..
include $(CONTIKI)/Makefile.include
