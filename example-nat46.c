/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

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
  handle_v4_packet(d);
  return d->dsize;
}

int pcap_read_ev(int idx, dbuf_t *d, void *p) {
  handle_v6_packet(d);
  return d->dsize;
}


int main(int argc, char *argv[]) {
  int timeout = 0;
  sock_handlers_t *hdl;
  if (argc < 2) { 
    fprintf(stderr, "Usage: %s <dev>\n", argv[0]);
    exit(1);
  }

  set_debug_level(DBG_GLOBAL, 30); 

  pcapi = attach_pcap_with_filter(argv[1], "ip6");
  set_v6_idx(pcapi);

  tuni = attach_tun_interface(NULL);
  set_v4_idx(tuni);

  set_debug_level(DBG_GLOBAL, 0); 

  hdl = cdata_get_handlers(tuni);
  hdl->ev_read = tun_read_ev;

  hdl = cdata_get_handlers(pcapi);
  hdl->ev_read = pcap_read_ev;
  while(1) {
    if (timeout <= 10) { 
      timeout = 1000;
    }
    timeout = sock_one_cycle(timeout, NULL);
    nat46_glue_periodic();
  }
}


