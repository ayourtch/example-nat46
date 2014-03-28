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
    p1++; p2++;
  }
}


/* return the current arg, and advance the tail to the next space-separated word */
static char *get_next_arg(char **ptail) {
  char *pc = NULL;
  char *pc2;
  while ((*ptail) && (**ptail) && ((**ptail == ' ') || (**ptail == '\n'))) { 
    **ptail = 0;
    (*ptail)++;
  }
  pc = *ptail;
  
  while ((*ptail) && (**ptail) && ((**ptail != ' ') && (**ptail != '\n'))) { 
    (*ptail)++;
  }

  while ((*ptail) && (**ptail) && ((**ptail == ' ') || (**ptail == '\n'))) { 
    **ptail = 0;
    (*ptail)++;
  }

  if ((pc) && (0 == *pc)) {
    pc = NULL;
  }
  return pc;
}

/* 
 * Parse an IPv6 address (if pref_len is NULL), or prefix (if it isn't).
 * parses destructively (places \0 between address and prefix len)
 */
int try_parse_ipv6_prefix(struct in6_addr *pref, int *pref_len, char *arg) {
  int err = 0;
  char *arg_plen = strchr(arg, '/');
  if (arg_plen) {
    *arg_plen++ = 0;
    if (pref_len) {
      *pref_len = simple_strtol(arg_plen, NULL, 10);
    }
  }
  err = (1 != in6_pton(arg, -1, (u8 *)pref, '\0', NULL));
  return err;
}

/* 
 * Parse the config commands in the buffer, 
 * destructive (puts zero between the args) 
 */

int nat46_set_config(nat46_instance_t *nat46, char *buf, int count) {
  char *tail = buf;
  char *arg_name;
  int err = 0;
  while ((0 == err) && (NULL != (arg_name = get_next_arg(&tail)))) {
    if (0 == strcmp(arg_name, "debug")) {
      nat46->debug = simple_strtol(get_next_arg(&tail), NULL, 10);
    } else if (0 == strcmp(arg_name, "v6bits")) {
      err = try_parse_ipv6_prefix(&nat46->my_v6bits, NULL, get_next_arg(&tail)); 
    } else if (0 == strcmp(arg_name, "v6mask")) {
      err = try_parse_ipv6_prefix(&nat46->my_v6mask, NULL, get_next_arg(&tail)); 
    }
  }
  return err;
}


/* 
 * Get the nat46 configuration into a supplied buffer (if non-null),
 * return the needed buffer size to get the configuration into.
 */
int nat46_get_config(nat46_instance_t *nat46, char *buf, int count) {
  int ret = 0;
  return ret;
}


void nat46_handle_icmp6(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
  struct icmp6hdr *icmp6h = NULL;
  struct ipv6hdr *v6new  = NULL;
  struct sk_buff *new_skb = NULL;
  struct icmp6hdr *icmp6new = NULL;

  icmp6h = (struct icmphdr *)old_skb->data;
  skb_pull(old_skb, sizeof(struct icmp6hdr));
  nat46debug(5, "ICMP6 type: %d", icmp6h->icmp6_type);

  switch(icmp6h->icmp6_type) {
    case ICMPV6_ECHO_REQUEST:
      nat46debug(5, "Rcvd echo request, sending echo reply", 0);
      new_skb = alloc_skb(old_skb->len + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr), GFP_ATOMIC);
      memcpy(new_skb->data, ip6h, sizeof(*ip6h));
      memcpy(new_skb->data + sizeof(*ip6h), icmp6h, sizeof(*icmp6h));
      memcpy(new_skb->data + sizeof(*ip6h) + sizeof(*icmp6h), old_skb->data, old_skb->len);
      v6new = new_skb->data;
      xxx_swap_mem(&v6new->saddr, &v6new->daddr, 16);
      icmp6new = new_skb->data + sizeof(*ip6h);
      icmp6new->icmp6_cksum--;
      icmp6new->icmp6_type++;
      
      route_ipv6(new_skb);
      break;
  }

}


int ip6_input_not_interested(nat46_instance_t *nat46, struct ipv6hdr *ip6h, struct sk_buff *old_skb) {
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
  // FIXME: add the verification that the source is within the DMR
  // FIXME: add the verification that the destination matches our v6 "outside" address
  return 0;
}

void nat46_ipv6_input(struct sk_buff *old_skb) {
  struct ipv6hdr *ip6h = ipv6_hdr(old_skb);
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  uint16_t proto;

  nat46debug(1, "nat46_ipv6_input packet", 0);

  if(ip6_input_not_interested(nat46, ip6h, old_skb)) {
    nat46debug(1, "nat46_ipv6_input not interested", 0);
    return;
  }
  nat46debug(1, "nat46_ipv6_input next hdr: %d, len: %d", 
                ip6h->nexthdr, old_skb->len);
  debug_dump(DBG_V6, 1, old_skb->data, 64);

  proto = ip6h->nexthdr;
  
  skb_pull(old_skb, sizeof(struct ipv6hdr));
  switch(proto) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
      break;
    case NEXTHDR_ICMP:
      nat46debug(1, "nat46 ICMP6 packet", 0);
      nat46_handle_icmp6(nat46, ip6h, old_skb);
      goto done;
    default:
      nat46debug(3, "[ipv6] Next header: %u. Only TCP, UDP, and ICMP6 are supported.", proto);
      goto done;
  }

  
done:
  release_nat46_instance(nat46);
}

int ip4_input_not_interested(nat46_instance_t *nat46, struct ipv6hdr *iph, struct sk_buff *old_skb) {
  if (old_skb->protocol != htons(ETH_P_IP)) {
    nat46debug(3, "Not an IPv4 packet", 0);
    return 1;
  }
  // FIXME: check source to be within our prefix
}

void nat46_ipv4_input(struct sk_buff *old_skb) {
  nat46_instance_t *nat46 = get_nat46_instance(old_skb);
  struct iphdr *iph = ip_hdr(old_skb);

  if (ip4_input_not_interested(nat46, iph, old_skb)) {
    return;
  }
  nat46debug(1, "nat46_ipv6_input packet", 0);


done:
  release_nat46_instance(nat46);
}
