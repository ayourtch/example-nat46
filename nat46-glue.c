/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

/*
   This file is an adaptation layer to convert the dbuf into sk_buff,
   parse the packet, and call the callbacks.
*/

#include "nat46-glue.h"
#include "nat46-core.h"
#include "sock-ay.h"


int v4_idx;
int v6_idx;

int route_ipv4(struct sk_buff *skb) {
  sock_send_data(v4_idx, skb->dbuf);
  return 1;
}

int route_ipv6(struct sk_buff *skb) {
  sock_send_data(v6_idx, skb->dbuf);
  return 1;
}

void set_v4_idx(int idx) {
  v4_idx = idx;
}

void set_v6_idx(int idx) {
  v6_idx = idx;
}

void handle_v4_packet(dbuf_t *d) {
  struct sk_buff sk;
  sk.dbuf = d;
  nat64_ipv4_input(&sk);
}

void handle_v6_packet(dbuf_t *d) {

  struct sk_buff sk;
  sk.dbuf = d;
  nat64_ipv6_input(&sk);
}
