/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */
#ifndef __V6_GLUE_H__
#define __V6_GLUE_H__

#include "lk-types.h"

debug_type_t DBG_V6;

void nat46_glue_periodic(void);

int route_ipv4(struct sk_buff *skb);
int route_ipv6(struct sk_buff *skb);
void set_v4_idx(int idx);
void set_v6_idx(int idx);
void handle_v4_packet(dbuf_t *d);
void handle_v6_packet(dbuf_t *d);

#endif

