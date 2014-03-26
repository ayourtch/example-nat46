/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "nat46-glue.h"
#include "nat46-core.h"


int ip6_input_not_interested(struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IPV6)) {
    return 1;
  }
  if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6) {
    return 1;
  }
  if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {
    return 1;
  }
  return 0;
}

void nat46_ipv6_input(struct sk_buff *old_skb) {
  struct ipv6hdr *ip6h = ipv6_hdr(old_skb);
  uint16_t proto;

  if(ip6_input_not_interested(ip6h, old_skb)) {
    return;
  }
  skb_pull(old_skb, sizeof(struct ipv6hdr));
  proto = ip6h->nexthdr;
  switch(proto) {
    case NEXTHDR_TCP:
      break;
    case NEXTHDR_UDP:
      break;
    case NEXTHDR_ICMP:
      break;
    default:
      nat46debug(3, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP6 are supported.", proto);
  }


}
void nat46_ipv4_input(struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IP)) {
    return;
  }
}
