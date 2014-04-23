/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */
#ifndef __V6_GLUE_H__
#define __V6_GLUE_H__

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>

#include "lk-types.h"
#include "nat46-core.h"

#define printk printf

debug_type_t DBG_V6;
debug_type_t DBG_REASM;

void nat46_glue_periodic(void);
void nat46_conf(char *cfg_str);

nat46_instance_t *get_nat46_instance(struct sk_buff *skb);
void release_nat46_instance(nat46_instance_t *nat46);

int route_ipv4(struct sk_buff *skb);
void set_v4_idx(int idx);
void set_v6_idx(int idx);
void handle_v4_packet(dbuf_t *d);
void handle_v6_packet(dbuf_t *d);

#endif

