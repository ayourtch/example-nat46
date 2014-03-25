#include <stdio.h>
#include <stdlib.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "nat46-glue.h"

#include "debug-ay.h"
#include "hash-ay.h"
#include "dbuf-ay.h"
#include "sock-ay.h"
#include "sock-pcap-ay.h"

int tuni;
int pcapi;


int tun_read_ev(int idx, dbuf_t *d, void *p) {
  printf("Got packet!\n");
  debug_dump(DBG_GLOBAL, -1, d->buf, d->dsize);
  return d->dsize; // sock_send_data(tuni, d);
}


int main(int argc, char *argv[]) {
  int timeout = 0;
  sock_handlers_t *hdl;
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s <dev>\n", argv[0]);
    exit(1);
  }

  set_debug_level(DBG_GLOBAL, 1000);

  pcapi = attach_pcap(argv[1]);

  tuni = attach_tun_interface(NULL);

  hdl = cdata_get_handlers(tuni);
  hdl->ev_read = tun_read_ev;
  while(1) {
    if (timeout == 0) { 
      timeout = 1000;
    }
    timeout = sock_one_cycle(timeout, NULL);
    debug(0,0, ".");
  }
}


