/* (c) Andrew Yourtchenko 2014, ayourtch@gmail.com */

/*
   This file is an adaptation layer to convert the dbuf into sk_buff,
   parse the packet, and call the callbacks.
*/

#include "nat46-glue.h"
#include "nat46-core.h"
#include "lk-types.h"
#include "sock-ay.h"
#include "sock-pcap-ay.h"
#include "timers-ay.h"

int v4_idx;
int v6_idx;

struct debug_type DBG_V6_S = { "ipv6", "IPV6", 0, 0 };
debug_type_t DBG_V6 = &DBG_V6_S;


/*
 *
 * Linux look-alike functions.
 *
 */

struct iphdr *ip_hdr(struct sk_buff *skb) {
  return ((struct iphdr *) &skb->dbuf->buf[skb->l3_offset]);
}

struct ipv6hdr *ipv6_hdr(struct sk_buff *skb) {
  return ((struct ipv6hdr *) &skb->dbuf->buf[skb->l3_offset]);
}

/*
 *
 * Local mock IPv6 stack.
 *
 */

#define MAX_V6ADDR     8

typedef enum {
  V6_NONE = 0,
  V6_TENTATIVE,
  V6_PREFERRED,
  V6_DEPRECATED,
  V6_DUPLICATE
} v6_addr_state_t;


#define DAD_ATTEMPTS   2
#define DAD_INTERVAL   1000

typedef struct {
  uint8_t my_mac[6];
  struct  in6_addr my_v6addr[MAX_V6ADDR];
  v6_addr_state_t my_v6addr_state[MAX_V6ADDR];
  int my_v6_addr_dad_attempts[MAX_V6ADDR];
  uint64_t when_send_dad[MAX_V6ADDR];

  uint64_t when_router_expires;
  uint64_t when_send_rs;
} v6_stack_t;

v6_stack_t v6_main_stack;


void store_Xbytes(uint8_t **p, uint8_t val, int len) {
  memset(*p, val, len);
  (*p) += len;
}

void store_bytes(uint8_t **p, uint8_t *src, int len) {
  memcpy(*p, src, len);
  (*p) += len;
}

void store_mac(uint8_t **p, uint8_t *src) {
  store_bytes(p, src, 6);
}

void store_u8(uint8_t **p, uint8_t val) {
  * (*p) ++ = val;
}

void store_be16(uint8_t **p, uint16_t val) {
  *((uint16_t *) (*p)) = htons(val);
  p += 2;
}

dbuf_t *make_ll_icmp6(v6_stack_t *v6) {
  dbuf_t *d = dalloc(1500);
  memset(d->buf, 0, 1500);
  struct ipv6hdr *v6hdr = (void *)d->buf;
  v6hdr->version = 6;
  memcpy(&v6hdr->saddr, &v6->my_v6addr[0], sizeof(v6hdr->saddr));
  v6hdr->flow_lbl[0] = 0;
  v6hdr->flow_lbl[1] = 0;
  v6hdr->flow_lbl[2] = 0;
  v6hdr->nexthdr = NEXTHDR_ICMP;
  v6hdr->hop_limit = 255;
  return d;
}

uint16_t icmp6_sum(dbuf_t *d) {
  struct ipv6hdr *v6hdr = (void *)d->buf;
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);
  uint32_t sum = 0;
  uint8_t *p = (void *) (icmp6hdr);
  int i;

  for(i=0; i<ntohs(v6hdr->payload_len); i += 2) {
    sum += ((*p<<8)&0xff00)+(*(p+1)&0xff);
    p = p + 2;
  }
  for(i=0; i<16; i += 2) {
    sum += ((v6hdr->saddr.s6_addr[i]<<8) & 0xff00) + (v6hdr->saddr.s6_addr[i+1] & 0xff);
    sum += ((v6hdr->daddr.s6_addr[i]<<8) & 0xff00) + (v6hdr->daddr.s6_addr[i+1] & 0xff);
  }
  sum += ntohs(v6hdr->payload_len);
  sum += NEXTHDR_ICMP;
  while (sum>>16) {
    sum = (sum & 0xFFFF)+(sum >> 16);
  }
  sum = ~sum;
  return htons(sum);
}

uint8_t *get_mcast_mac(uint8_t *p, struct in6_addr *addr) {
  memset(p, 0x33, 2);
  memcpy(p+2, &addr->s6_addr[12], 4);
  return p;
}

void v6_send_rs(v6_stack_t *v6) {
  dbuf_t *d = make_ll_icmp6(v6);
  uint8_t mac[6];
  uint8_t *p;
  struct ipv6hdr *v6hdr = (void *)d->buf;
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);

  memset(&v6hdr->daddr, 0, sizeof(v6hdr->daddr));
  v6hdr->daddr.s6_addr[0] = 0xff;
  v6hdr->daddr.s6_addr[1] = 0x02;
  v6hdr->daddr.s6_addr[15] = 0x02;
  icmp6hdr->icmp6_cksum = 0;

  memcpy(&v6hdr->saddr, &v6->my_v6addr[0], sizeof(v6hdr->saddr));
  // memset(&v6hdr->saddr, 0, sizeof(v6hdr->saddr));

  icmp6hdr->icmp6_type = 133; // Router Solicitation
  icmp6hdr->icmp6_code = 0;
  p = (void *) (icmp6hdr + 1);
  store_Xbytes(&p, 1, 2);
  store_mac(&p, v6->my_mac);

  v6hdr->payload_len = htons(((uint8_t *)p) - ((uint8_t *)icmp6hdr));
  d->dsize = ((uint8_t *)p) - ((uint8_t *)v6hdr) + 14;


  icmp6hdr->icmp6_cksum = icmp6_sum(d);
  get_mcast_mac(mac, &v6hdr->daddr);

  dprepend(d, 14);
  p = d->buf;
  store_mac(&p, mac);
  store_mac(&p, v6->my_mac);
  store_be16(&p, ETH_P_IPV6);

  debug(DBG_V6, 20, "Sending RS");
  debug_dump(DBG_V6, 25, d->buf, d->dsize);
  sock_send_data(v6_idx, d);
}



void send_dad(v6_stack_t *v6, int i) {
  dbuf_t *d = make_ll_icmp6(v6);
  uint8_t *p;
  struct ipv6hdr *v6hdr = (void *)d->buf;
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);

  memset(&v6hdr->daddr, 0, sizeof(v6hdr->daddr));
  memcpy(&v6hdr->daddr.s6_addr[13], &v6->my_v6addr[i].s6_addr[13], 3);
  v6hdr->daddr.s6_addr[0] = 0xff;
  v6hdr->daddr.s6_addr[1] = 0x02;
  v6hdr->daddr.s6_addr[11] = 0x01;
  v6hdr->daddr.s6_addr[12] = 0xff;
  memset(&v6hdr->saddr, 0, sizeof(v6hdr->saddr));

  icmp6hdr->icmp6_type = 135; // Neighbor Solicitation
  icmp6hdr->icmp6_code = 0;
  p = (void *) (icmp6hdr + 1);
  store_bytes(&p, (void *)&v6->my_v6addr[i], sizeof(v6->my_v6addr[i]));

  v6hdr->payload_len = ntohs(((uint8_t *)p) - ((uint8_t *)icmp6hdr));
  d->dsize = ((uint8_t *)p) - ((uint8_t *)v6hdr) + 14;


  icmp6hdr->icmp6_cksum = icmp6_sum(d);

  dprepend(d, 14);
  p = d->buf;
  store_mac(&p, get_mcast_mac(p, &v6hdr->daddr));
  store_mac(&p, v6->my_mac);
  store_be16(&p, ETH_P_IPV6);

  debug(DBG_V6, 20, "Sending DAD");
  debug_dump(DBG_V6, 25, d->buf, d->dsize);
  sock_send_data(v6_idx, d);
}


void v6_stack_periodic(v6_stack_t *v6) {
  uint64_t now = get_time_msec();
  int i;
  set_debug_level(DBG_V6, 1000);

  debug(DBG_V6, 100, "Periodic... now: %lld", now);

  if (v6->my_v6addr_state[0] == V6_NONE) {
    pcap_socket_info_t *psi = get_pcap_socket_info(v6_idx);
    memcpy(v6->my_mac, psi->mac, 6);

    /* Initialize link-local */
    memset(&v6->my_v6addr[0], 0, sizeof(v6->my_v6addr[0]));
    v6->my_v6addr[0].s6_addr[0] = 0xfe;
    v6->my_v6addr[0].s6_addr[1] = 0x80;
    for(i=0;i<8;i++) {
       v6->my_v6addr[0].s6_addr[8+i] = random() & 0xff;
    }
/*
    v6->my_v6addr[0].s6_addr[8] = v6->my_mac[0] ^ 0x02;
    v6->my_v6addr[0].s6_addr[9] = v6->my_mac[1];
    v6->my_v6addr[0].s6_addr[10] = v6->my_mac[2];
    v6->my_v6addr[0].s6_addr[11] = 0xff;
    v6->my_v6addr[0].s6_addr[12] = 0xfe;
    v6->my_v6addr[0].s6_addr[13] = v6->my_mac[3];
    v6->my_v6addr[0].s6_addr[14] = v6->my_mac[4];
    v6->my_v6addr[0].s6_addr[15] = v6->my_mac[5];
*/

    v6->my_v6addr_state[0] = V6_TENTATIVE;
    v6->my_v6_addr_dad_attempts[0] = DAD_ATTEMPTS;
    debug(DBG_V6, 100, "Configured LL address");
  } else if (v6->my_v6addr_state[0] == V6_PREFERRED) {
    /* If link-local address is active, check if we need to send RA, etc. */
    if (now > v6->when_send_rs) {
      v6_send_rs(v6);
      v6->when_send_rs = now + 2000;
    }
  }
  /* Run a DAD cycle if needed */
  for(i=0; i< MAX_V6ADDR; i++) {
    if(v6->my_v6addr_state[i] == V6_TENTATIVE) {
      if(v6->when_send_dad[i] < now) {
        if(v6->my_v6_addr_dad_attempts[i] == 0) {
          v6->my_v6addr_state[i] = V6_PREFERRED;
        } else {
          send_dad(v6, i);
          v6->my_v6_addr_dad_attempts[i]--;
          v6->when_send_dad[i] = now + DAD_INTERVAL;
        }
      }
    }
  }

}

/*
 *
 * Glue with libay
 *
 */



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


void parse_sk_dbuf(struct sk_buff *skb) {
}


void handle_v4_packet(dbuf_t *d) {
  struct sk_buff sk;
  sk.dbuf = d;
  v6_stack_periodic(&v6_main_stack);
  if (d->buf[5] == 0x45) {
    sk.protocol = ETH_P_IP;
    sk.l3_offset = 5;
    parse_sk_dbuf(&sk);
    debug_dump(DBG_GLOBAL, 0, d->buf, d->dsize);
    nat64_ipv4_input(&sk);
  }
}

void do_ipv6_nd(struct sk_buff *skb) {
}

void handle_v6_packet(dbuf_t *d) {

  struct sk_buff sk;
  sk.dbuf = d;
  sk.protocol = ntohs(* (uint16_t *)(&d->buf[12]));
  if (sk.protocol == ETH_P_IPV6) {
    // debug_dump(DBG_GLOBAL, 0, d->buf, d->dsize);
    sk.l3_offset = 14;
    parse_sk_dbuf(&sk);
    do_ipv6_nd(&sk);
    nat64_ipv6_input(&sk);
  }
  v6_stack_periodic(&v6_main_stack);
}
