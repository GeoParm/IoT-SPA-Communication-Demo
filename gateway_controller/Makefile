CONTIKI_PROJECT = gateway_controller app_server
all: $(CONTIKI_PROJECT)

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += ../rijndael.c
PROJECT_SOURCEFILES += ../dtls-ccm.c
PROJECT_SOURCEFILES += ../utilfunctions.c
PROJECT_SOURCEFILES += serverutils.c
CFLAGS += -I..
LDFLAGS += -lsqlite3

CONTIKI=../../..
include $(CONTIKI)/Makefile.include
