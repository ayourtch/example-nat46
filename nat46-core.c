/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "nat46-glue.h"



void nat64_ipv6_input(struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IPV6)) {
    return;
  }
}
void nat64_ipv4_input(struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IP)) {
    return;
  }
}
