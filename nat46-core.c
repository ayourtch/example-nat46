/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "nat46-glue.h"
#include "nat46-core.h"

void xxx_swap_mem(void *ip1, void *ip2, int cnt) {
  uint8_t *p1 = ip1;
  uint8_t *p2 = ip2;
  uint8_t t;
  int i;
  for (i=0; i<cnt; i++) { 
    t = *p1;
    *p1 = *p2;
    *p2 = t;
  }
}

void nat46_handle_icmp6(struct sk_buff *old_skb, struct ipv6hdr *ip6h) {
  struct icmp6hdr *icmp6h;
  struct ipv6hdr *v6new;
  struct sk_buff *new_skb;
  struct icmp6hdr *icmp6new;

  icmp6h = (struct icmphdr *)old_skb->data;
  skb_pull(old_skb, sizeof(struct icmp6hdr));
  nat46debug(5, "ICMP6 type: %d", icmp6h->icmp6_type);

  switch(icmp6h->icmp6_type) {
    case ICMPV6_ECHO_REQUEST:
      nat46debug(5, "Rcvd echo request, sending echo reply", 0);
      new_skb = alloc_skb(old_skb->len + sizeof(struct ipv6hdr), GFP_ATOMIC);
      memcpy(new_skb->data, ip6h, sizeof(*ip6h));
      memcpy(new_skb->data + sizeof(*ip6h), old_skb->data, old_skb->len);
      v6new = new_skb->data;
      xxx_swap_mem(&v6new->saddr, &v6new->daddr, 16);
      icmp6new = new_skb->data + sizeof(*ip6h);
      icmp6new->icmp6_cksum--;
      icmp6new->icmp6_type++;
      
      route_ipv6(new_skb);
      break;
  }

}


int ip6_input_not_interested(struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IPV6)) {
    nat46debug(3, "Not an IPv6 packet", 0);
    return 1;
  }
  if(old_skb->len < sizeof(struct ipv6hdr) || ip6h->version != 6) {
    nat46debug(3, "Len short or not correct version: %d", ip6h->version);
    return 1;
  }
  if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST)) {
    nat46debug(3, "Source address not unicast", ip6h->version);
    return 1;
  }
  return 0;
}

void nat46_ipv6_input(struct sk_buff *old_skb) {
  struct ipv6hdr *ip6h = ipv6_hdr(old_skb);
  uint16_t proto;

  nat46debug(1, "nat46_ipv6_input packet", 0);

  if(ip6_input_not_interested(ip6h, old_skb)) {
    nat46debug(1, "nat46_ipv6_input not interested", 0);
    return;
  }
  nat46debug(1, "nat46_ipv6_input next hdr: %d", ip6h->nexthdr);
  skb_pull(old_skb, sizeof(struct ipv6hdr));
  proto = ip6h->nexthdr;
  switch(proto) {
    case NEXTHDR_TCP:
      break;
    case NEXTHDR_UDP:
      break;
    case NEXTHDR_ICMP:
      nat46debug(1, "nat46 ICMP6 packet", 0);
      nat46_handle_icmp6(old_skb, ip6h);
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
