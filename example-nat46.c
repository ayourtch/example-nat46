/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

#include <stdio.h>
#include <stdlib.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
// #include <netinet/tcp.h>

#include "nat46-glue.h"

#include "debug-ay.h"
#include "hash-ay.h"
#include "dbuf-ay.h"
#include "sock-ay.h"
#include "sock-pcap-ay.h"
#include "sock-cli.h"

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

int cli_read_ev(int idx, dbuf_t *di, void *p) {
  char *op;
  dbuf_t *d = NULL;
  char *cmd = (void *)di->buf;
  debug(0,0, "Cmd: '%s'", cmd);
  if (NULL == cmd) {
    return 1;
  }
  op = strtok(cmd, " ");
  if (NULL == op) {
    return 1;
  }

  if (0 == strcmp(op, "h")) {
    debug(0,0, "d <level>");
  }
  if (0 == strcmp(op, "d")) {
  }
  if (0 == strcmp(op, "q") || 0 == strcmp(op, "\x03")) {
    detach_stdin();
    printf("\n\n\n");
    exit(1);
  }
/*
  if (0 == strcmp(op, "r")) {
    uint32_t xid = atol(strtok(NULL, " "));
    uint16_t offs = atoi(strtok(NULL, " "));
    int mf = atoi(strtok(NULL, " "));
    char *data = strtok(NULL, " ");
    char *now_s = strtok(NULL, " ");
  }
*/
  return (d ? d->dsize : 0) || 1;
}


int main(int argc, char *argv[]) {
  int timeout = 0;
  sock_handlers_t *hdl;
  int cli;
  char tun_ifname[16];
  char cmdstr[256];

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <dev> ['config string']\n", argv[0]);
    exit(1);
  }

  set_debug_level(DBG_GLOBAL, 30); 

  pcapi = attach_pcap_with_filter(argv[1], "ip6");
  set_v6_idx(pcapi);

  if (argc > 2) {
    set_nat46_config(argv[2]);
  }

  tuni = attach_tun_interface(tun_ifname);
  set_v4_idx(tuni);
  debug(0,0, "Attached to tun interface: %s", tun_ifname);
  // snprintf(cmdstr, sizeof(cmdstr), "ifconfig %s 100.64.1.2 100.64.1.1; ifconfig %s mtu 1460", tun_ifname, tun_ifname);
  snprintf(cmdstr, sizeof(cmdstr), "ifconfig %s 100.64.1.2 100.64.1.1; ifconfig %s mtu 1460", tun_ifname, tun_ifname);
  debug(0,0, "Running: '%s'", cmdstr);
  system(cmdstr);
  snprintf(cmdstr, sizeof(cmdstr), "route delete default; route add default 100.64.1.1; sudo route add -net 144.254.221.0/24 100.64.1.1");
  debug(0,0, "Running: '%s'", cmdstr);
  system(cmdstr);
/*
  cli = attach_cli(attach_stdin(0));
  hdl = cdata_get_handlers(cli);
  hdl->ev_read = cli_read_ev;
  debug(0,0, "Press Ctrl-C to quit");
*/

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


