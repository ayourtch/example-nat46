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

struct debug_type DBG_REASM_S = { "reasm", "REASM", 0, 0 };
debug_type_t DBG_REASM = &DBG_REASM_S;
/*
 *
 * Linux look-alike functions.
 *
 */
long simple_strtol(const char *cp, char **endp, unsigned int base) {
  return strtol(cp, endp, base);
}

int in4_pton(const char *src, int srclen, u8 *dst, int delim, const char **end) {
  return inet_aton(src, dst);
}

int in6_pton(const char *src, int srclen, u8 *dst, int delim, const char **end) {
   return inet_pton(AF_INET6, src, dst); 
}


__be32 s6_addr32(const struct in6_addr *addr, int i) {
  int s = 4*i;
  return htonl(addr->s6_addr[3+s] +
         (addr->s6_addr[2+s] << 8) +
         (addr->s6_addr[1+s] << 16) +
         (addr->s6_addr[0+s] << 24));
}

 unsigned int ipv6_addr_scope2type(unsigned int scope)
{
        switch (scope) {
        case IPV6_ADDR_SCOPE_NODELOCAL:
                return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
                        IPV6_ADDR_LOOPBACK);
        case IPV6_ADDR_SCOPE_LINKLOCAL:
                return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
                        IPV6_ADDR_LINKLOCAL);
        case IPV6_ADDR_SCOPE_SITELOCAL:
                return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
                        IPV6_ADDR_SITELOCAL);
        }
        return IPV6_ADDR_SCOPE_TYPE(scope);
}


int __ipv6_addr_type(const struct in6_addr *addr)
{
        __be32 st;

        st = s6_addr32(addr, 0);

        /* Consider all addresses with the first three bits different of
           000 and 111 as unicasts.
         */
        if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
            (st & htonl(0xE0000000)) != htonl(0xE0000000))
                return (IPV6_ADDR_UNICAST |
                        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));

        if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
                /* multicast */
                /* addr-select 3.1 */
                return (IPV6_ADDR_MULTICAST |
                        ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr)));
        }

        if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
                return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
                        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));               /* addr-select 3.1 */
        if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
                return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
                        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));               /* addr-select 3.1 */
        if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
                return (IPV6_ADDR_UNICAST |
                        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));                  /* RFC 4193 */

        if ((s6_addr32(addr, 0) | s6_addr32(addr, 1)) == 0) {
                if (s6_addr32(addr, 2) == 0) {
                        if (s6_addr32(addr, 3) == 0)
                                return IPV6_ADDR_ANY;

                        if (s6_addr32(addr, 3) == htonl(0x00000001))
                                return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
                                        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));       /* addr-select 3.4 */

                        return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
                                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));  /* addr-select 3.3 */
                }

                if (s6_addr32(addr, 2) == htonl(0x0000ffff))
                        return (IPV6_ADDR_MAPPED |
                                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));  /* addr-select 3.3 */
        }

        return (IPV6_ADDR_UNICAST |
                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));  /* addr-select 3.4 */
}

int ipv6_addr_type(const struct in6_addr *addr)
{
        return __ipv6_addr_type(addr) & 0xffff;
}

 int ipv6_addr_scope(const struct in6_addr *addr)
{
        return __ipv6_addr_type(addr) & IPV6_ADDR_SCOPE_MASK;
}

 int __ipv6_addr_src_scope(int type)
{
        return (type == IPV6_ADDR_ANY) ? __IPV6_ADDR_SCOPE_INVALID : (type >> 16);
}

 int ipv6_addr_src_scope(const struct in6_addr *addr)
{
        return __ipv6_addr_src_scope(__ipv6_addr_type(addr));
}

bool ipv6_addr_all_hosts(const struct in6_addr *addr) {
  return ( (s6_addr32(addr, 0) == 0xff020000) &&
           (s6_addr32(addr, 1) == 0) &&
           (s6_addr32(addr, 2) == 0) &&
           (s6_addr32(addr, 3) == 1) );
}

 bool __ipv6_addr_needs_scope_id(int type)
{
        return type & IPV6_ADDR_LINKLOCAL ||
               (type & IPV6_ADDR_MULTICAST &&
                (type & (IPV6_ADDR_LOOPBACK|IPV6_ADDR_LINKLOCAL)));
}

 __u32 ipv6_iface_scope_id(const struct in6_addr *addr, int iface)
{
        return __ipv6_addr_needs_scope_id(__ipv6_addr_type(addr)) ? iface : 0;
}

 int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
        return memcmp(a1, a2, sizeof(struct in6_addr));
}

 bool
ipv6_masked_addr_cmp(const struct in6_addr *a1, const struct in6_addr *m,
                     const struct in6_addr *a2)
{
        return !!(
                  ((s6_addr32(a1,0) ^ s6_addr32(a2, 0)) & s6_addr32(m, 0)) |
                  ((s6_addr32(a1,1) ^ s6_addr32(a2, 1)) & s6_addr32(m, 1)) |
                  ((s6_addr32(a1,2) ^ s6_addr32(a2, 2)) & s6_addr32(m, 2)) |
                  ((s6_addr32(a1,3) ^ s6_addr32(a2, 3)) & s6_addr32(m, 3))
                 );
}

 void ipv6_addr_copy(struct in6_addr *a1, const struct in6_addr *a2)
{
        memcpy(a1, a2, sizeof(struct in6_addr));
}


 void ipv6_addr_prefix(struct in6_addr *pfx,
                                    const struct in6_addr *addr,
                                    int plen)
{
        /* caller must guarantee 0 <= plen <= 128 */
        int o = plen >> 3,
            b = plen & 0x7;

        memset(pfx->s6_addr, 0, sizeof(pfx->s6_addr));
        memcpy(pfx->s6_addr, addr, o);
        if (b != 0)
                pfx->s6_addr[o] = addr->s6_addr[o] & (0xff00 >> b);
}

 unsigned char *__skb_pull(struct sk_buff *skb, unsigned int len) {
        skb->len -= len;
        BUG_ON(skb->len < skb->data_len);
        return skb->data += len;
}

unsigned char *skb_pull(struct sk_buff *skb, unsigned int len) {
        return unlikely(len > skb->len) ? NULL : __skb_pull(skb, len);
}

void *skb_tail_pointer(struct sk_buff *skb) {
  return skb->tail;
}

void kfree_skb(struct sk_buff *skb) {
  dunlock(skb->dbuf);
}

void skb_reserve(struct sk_buff *skb, int len) {
        skb->data += len;
        skb->tail += len;
}

void skb_put(struct sk_buff *skb, int len) {
	skb->tail += len;
	skb->len += len;
}

/*
 * We use the newly added "user data structure" within dbuf 
 * for skb. It's freed together with the dbuf, so we do not need
 * to think of memory management.
 */

struct sk_buff *alloc_skb(unsigned int size, gfp_t priority) {
  unsigned int sz = size;
  struct sk_buff *sk = malloc(sizeof(struct sk_buff));

  if (sk) {
    dbuf_t *d = dalloc(sz);
    if (d) {
      memset(sk, 0, sizeof(*sk));
      sk->dbuf = d;
      d->user_struct = sk;

      d->dsize = d->size;
      sk->data = d->buf;
      sk->head = d->buf;
      sk->len = size;
      sk->tail = sk->data + size;
    } else {
      debug(0,0, "Could not allocate a dbuf of size %d\n", size);
      free(sk);
      sk = NULL;
    }
  }
  return sk;
}

__sum16 csum_fold(__u32 sum) {
  while (sum>>16) {
    sum = (sum & 0xFFFF)+(sum >> 16);
  }
  sum = ~sum;
  return sum;
  // ? return htons(sum);
}

__u32 add32(__u32 a, __u32 b) {
  __u32 sum = a + b;
  if((sum < a) || (sum < b)) {
    sum++;
  }
  return sum;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
                         unsigned short len,
                         unsigned short proto,
                         __wsum sum) {
  unsigned long long s = (u32)sum;

  s += (u32)saddr;
  s += (u32)daddr;
#ifdef __BIG_ENDIAN
  s += proto + len;
#else
  s += (proto + len) << 8;
#endif
  s += (s >> 32);
  return (__wsum)s;
}

__sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len,
                  unsigned short proto, __wsum sum) {
  return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
                        const struct in6_addr *daddr,
                        __u32 len, unsigned short proto,
                        __wsum csum) {

  int i;
  __u32 ulen;
  __u32 uproto;
  __u32 sum = (u32)csum;

  for(i=0;i<4;i++) {
    sum = add32(sum, s6_addr32(saddr, i));
    sum = add32(sum, s6_addr32(daddr, i));
  } 

  ulen = (__u32) htonl(len);
  sum = add32(sum, ulen);
  
  uproto = (__u32) htonl(proto);
  sum = add32(sum, uproto);

  return csum_fold(sum);
}

__wsum csum_partial(const void *p, int len, __wsum __sum) {
  u32 sum = (u32)__sum;
  u16 *buf = (u16 *)p;
  int i;
  for(i=0;i<(len/2);i++) {
    sum += *buf++;
  }
  if (len % 2) {
    sum += ( *((u8 *)buf) );
  }
  return sum;
}

__sum16 ip_fast_csum(const void *iph, unsigned int ihl) {
  return csum_fold(csum_partial(iph, ihl*4, 0));
}

void ip6_route_input(struct sk_buff *skb) {
  // FIXME
}

int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src, u8 tos, struct net_device *devin) {
  // FIXME
  return 0;
}

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp_mask) {
  int data_offs = skb->data - skb->head;
  int tail_offs = skb->tail - skb->head;

  if (nhead > 0) {
    dprepend(skb->dbuf, nhead);
  }
  if (ntail > 0) {
    dgrow(skb->dbuf, ntail);
  }
  skb->head = skb->dbuf->buf;
  skb->data = skb->head + data_offs + nhead;
  skb->tail = skb->head + tail_offs;
  skb->end = skb->head + skb->dbuf->size;
  return 0;
}

struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp_mask) {
  struct sk_buff *sknew = alloc_skb(skb->len, gfp_mask);
  memcpy(sknew->data, skb->data, skb->len);
  sknew->len = skb->tail - skb->head;
  sknew->tail = sknew->head + (skb->len);
  return sknew; 
}

unsigned char *skb_push(struct sk_buff *skb, unsigned int len) {
  if (skb->data - len < skb->head) {
    pskb_expand_head(skb, len, 0, GFP_ATOMIC);
  }
  skb->data -= len;
  skb->len  += len;
  return skb->data;
}

unsigned char *skb_transport_header(const struct sk_buff *skb)
{
        return skb->head + skb->transport_header;
}

void skb_reset_transport_header(struct sk_buff *skb)
{
        skb->transport_header = skb->data - skb->head;
}

void skb_set_transport_header(struct sk_buff *skb, const int offset)
{
        skb_reset_transport_header(skb);
        skb->transport_header += offset;
}

unsigned char *skb_network_header(const struct sk_buff *skb)
{
        return skb->head + skb->network_header;
}

void skb_reset_network_header(struct sk_buff *skb)
{
        skb->network_header = skb->data - skb->head;
}

void skb_set_network_header(struct sk_buff *skb, const int offset)
{
        skb_reset_network_header(skb);
        skb->network_header += offset;
}

struct tcphdr *tcp_hdr(const struct sk_buff *skb) {
  return (struct tcphdr *)skb_transport_header(skb);
}

struct udphdr *udp_hdr(const struct sk_buff *skb) {
  return (struct udphdr *)skb_transport_header(skb);
}

struct iphdr *ip_hdr(struct sk_buff *skb) {
  return ((struct iphdr *) &skb->dbuf->buf[skb->network_header]);
}

struct icmp6hdr *icmp6_hdr(const struct sk_buff *skb) {
  return (void *)skb_transport_header(skb);
}

struct ipv6hdr *ipv6_hdr(struct sk_buff *skb) {
  return ((struct ipv6hdr *) &skb->dbuf->buf[skb->network_header]);
}

unsigned int ip_hdrlen(const struct sk_buff *skb) {
  return ip_hdr((struct sk_buff *)skb)->ihl * 4;
}

/*
 *
 * Local mock IPv6 stack.
 *
 */

#define MAX_V6ADDR     8

typedef enum {
  V6_NONE = 0,
  V6_DUPLICATE,
  V6_TENTATIVE,
  V6_PREFERRED,
  V6_DEPRECATED
} v6_addr_state_t;


#define DAD_ATTEMPTS   2
#define DAD_INTERVAL   1000

#define ETHER_SIZE 14

typedef struct {
  uint32_t mtu;
  uint8_t my_mac[6];
  uint8_t gw_mac[6];
  struct  in6_addr my_v6addr[MAX_V6ADDR];
  v6_addr_state_t my_v6addr_state[MAX_V6ADDR];
  int my_v6_addr_dad_attempts[MAX_V6ADDR];
  uint64_t when_send_dad[MAX_V6ADDR];

  uint64_t when_router_expires;
  uint64_t when_send_rs;
} v6_stack_t;

v6_stack_t v6_main_stack;

int find_my_address_free_slot(v6_stack_t *v6) {
  int i;
  for(i=0; i<MAX_V6ADDR; i++) {
    if(v6->my_v6addr_state[i] == V6_NONE) {
      return i;
    }
  }
  return -1;

}

int find_my_address_for_prefix(v6_stack_t *v6, struct in6_addr *prefix, int prefix_len) {
  int i;
  if (prefix_len != 64) {
    return -1;
  }
  for(i=0; i<MAX_V6ADDR; i++) {
    if(0 == memcmp(&v6->my_v6addr[i], prefix, 8)) {
      return i;
    }
  }
  return -1;
}


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
  struct ipv6hdr *v6hdr = (void *)(d->buf + ETHER_SIZE);
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
  struct ipv6hdr *v6hdr = (void *)(d->buf + ETHER_SIZE);
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
  struct ipv6hdr *v6hdr = (void *)(d->buf + ETHER_SIZE);
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);

  memset(&v6hdr->daddr, 0, sizeof(v6hdr->daddr));
  v6hdr->daddr.s6_addr[0] = 0xff;
  v6hdr->daddr.s6_addr[1] = 0x02;
  v6hdr->daddr.s6_addr[15] = 0x02;
  icmp6hdr->icmp6_cksum = 0;

  memcpy(&v6hdr->saddr, &v6->my_v6addr[0], sizeof(v6hdr->saddr));

  icmp6hdr->icmp6_type = NDISC_ROUTER_SOLICITATION; // Router Solicitation
  icmp6hdr->icmp6_code = 0;
  p = (void *) (icmp6hdr + 1);
  store_Xbytes(&p, 1, 2);
  store_mac(&p, v6->my_mac);

  v6hdr->payload_len = htons(((uint8_t *)p) - ((uint8_t *)icmp6hdr));
  d->dsize = ((uint8_t *)p) - ((uint8_t *)v6hdr) + ETHER_SIZE;


  icmp6hdr->icmp6_cksum = icmp6_sum(d);
  get_mcast_mac(mac, &v6hdr->daddr);

  p = d->buf;
  store_mac(&p, mac);
  store_mac(&p, v6->my_mac);
  store_be16(&p, ETH_P_IPV6);

  debug(DBG_V6, 20, "Sending RS");
  debug_dump(DBG_V6, 125, d->buf, d->dsize);
  sock_send_data(v6_idx, d);
}



void send_dad(v6_stack_t *v6, int i) {
  dbuf_t *d = make_ll_icmp6(v6);
  uint8_t *p;
  struct ipv6hdr *v6hdr = (void *)(d->buf + ETHER_SIZE);
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);

  memset(&v6hdr->daddr, 0, sizeof(v6hdr->daddr));
  memcpy(&v6hdr->daddr.s6_addr[13], &v6->my_v6addr[i].s6_addr[13], 3);
  v6hdr->daddr.s6_addr[0] = 0xff;
  v6hdr->daddr.s6_addr[1] = 0x02;
  v6hdr->daddr.s6_addr[11] = 0x01;
  v6hdr->daddr.s6_addr[12] = 0xff;
  memset(&v6hdr->saddr, 0, sizeof(v6hdr->saddr));

  icmp6hdr->icmp6_type = NDISC_NEIGHBOUR_SOLICITATION; 
  icmp6hdr->icmp6_code = 0;
  p = (void *) (icmp6hdr + 1);
  store_bytes(&p, (void *)&v6->my_v6addr[i], sizeof(v6->my_v6addr[i]));

  v6hdr->payload_len = ntohs(((uint8_t *)p) - ((uint8_t *)icmp6hdr));
  d->dsize = ((uint8_t *)p) - ((uint8_t *)v6hdr) + ETHER_SIZE;


  icmp6hdr->icmp6_cksum = icmp6_sum(d);

  p = d->buf;
  store_mac(&p, get_mcast_mac(p, &v6hdr->daddr));
  store_mac(&p, v6->my_mac);
  store_be16(&p, ETH_P_IPV6);

  debug(DBG_V6, 20, "Sending DAD");
  debug_dump(DBG_V6, 125, d->buf, d->dsize);
  sock_send_data(v6_idx, d);
}

uint8_t *get_icmp6_opt_source_mac(struct sk_buff *skb) {
  struct ipv6hdr *v6hdr = ipv6_hdr(skb);
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);
  uint8_t *p = (void *) (icmp6hdr+1);
  uint8_t *pe = skb->data + skb->len;
  p += sizeof(v6hdr->saddr);
  debug(DBG_V6, 10, "Getting Source MAC");
  debug_dump(DBG_V6, 10, p, pe-p);
  while (p < pe) {
    if (*p == 1) {
      p++;
      if (*p == 1) {
        return ++p;
      }
      return NULL;
    } else {
      p++;
      p += (8* (*p))-1;
    }
  }
  return NULL;
  
}

#define ONE_DAY_MSEC (1000*3600*24)

void ndisc_recv_ra(struct sk_buff *skb, v6_stack_t *v6) {
  struct icmp6hdr *icmp6hdr = (void *) skb->data;
  uint8_t *p = (void *)(icmp6hdr + 1);
  uint8_t *pe = skb->data + skb->len;
  int i;

  /* p += 4; p += 4; */
  debug(DBG_V6, 10, "RA options:");
  while (p < pe) {
    debug(DBG_V6, 10, "  Option %d", *p);
    switch (*p) {
      case 1: 
        memcpy(v6->gw_mac, p+2, 6);
        debug(DBG_V6, 10, "    Src MAC %02x:%02x:%02x:%02x:%02x:%02x", 
                            p[2], p[3], p[4], p[5], p[6], p[7]);

        
        break;
      case 5: 
        v6->mtu = ntohl( *(uint32_t *) (p+4));
        debug(DBG_V6, 10, "    MTU %ld", v6->mtu);
        break; 
      case 3:
        debug(DBG_V6, 10, "    Prefix");
        debug_dump(DBG_V6, 10, (void *)&p[16], 16);
        i = find_my_address_for_prefix(v6, (void *)&p[16], 64);
        if (i < 0) {
          i = find_my_address_free_slot(v6);
        }
        if (i > 0) {
          debug(DBG_V6, 11, "      Updating addr #%d\n", i);
          if(v6->my_v6addr_state[i] < V6_TENTATIVE) {
            memcpy(&v6->my_v6addr[i], &p[16], 8);
            memcpy(&v6->my_v6addr[i].s6_addr[8], &v6->my_v6addr[0].s6_addr[8], 8);
            v6->my_v6addr_state[i] = V6_TENTATIVE;
            v6->my_v6_addr_dad_attempts[i] = DAD_ATTEMPTS;
            debug(DBG_V6, 20, "Configured address via SLAAC");
          }
        } 
        break; 
    }
    p++;
    if (0 == *p) {
      debug(DBG_V6, 1, "An option with zero length, exit the parsing...");
      return;
    }
    p += (8* (*p))-1;
  }

  debug(DBG_V6, 10, "Received RA, stop sending RS");
  v6->when_send_rs = get_time_msec() + ONE_DAY_MSEC;
}

int get_ns_target_index(struct sk_buff *skb, v6_stack_t *v6) {
  struct icmp6hdr *icmp6hdr = (void *) (ipv6_hdr(skb) + 1);
  uint8_t *p = (void *) (icmp6hdr+1);
  int i;
  for(i=0; i<MAX_V6ADDR; i++) {
    if(ipv6_addr_cmp(&v6->my_v6addr[i], (void *)p) == 0) {
      debug(DBG_V6, 10, "NS is for my addr #%d", i);
      return i;
    }
  }
  debug(DBG_V6, 10, "NS is not for my addresses");
  
  return -1;
}

void ndisc_recv_ns(struct sk_buff *skb, v6_stack_t *v6) {
  dbuf_t *d = make_ll_icmp6(v6);
  uint8_t *p;
  uint8_t *dmac = NULL;
  int i = get_ns_target_index(skb, v6);
  struct ipv6hdr *v6hdr = (void *)(d->buf + ETHER_SIZE);
  struct icmp6hdr *icmp6hdr = (void *) (v6hdr + 1);
  debug(DBG_V6, 20, "Received NS");
  if (i < 0) {
    debug(DBG_V6, 20, "... but not for us");
    dunlock(d);
    return;
  }

  ipv6_addr_copy(&v6hdr->daddr, &ipv6_hdr(skb)->saddr);
  ipv6_addr_copy(&v6hdr->saddr, &v6->my_v6addr[i]);

  icmp6hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
  icmp6hdr->icmp6_code = 0;
  icmp6hdr->icmp6_solicited = 1;
  icmp6hdr->icmp6_override = 1;
  p = (void *) (icmp6hdr + 1);
  store_bytes(&p, (void *)&v6->my_v6addr[i], sizeof(v6->my_v6addr[i]));
  store_Xbytes(&p, 2, 1);
  store_Xbytes(&p, 1, 1);
  store_mac(&p, v6->my_mac);

  v6hdr->payload_len = ntohs(((uint8_t *)p) - ((uint8_t *)icmp6hdr));
  d->dsize = ((uint8_t *)p) - ((uint8_t *)v6hdr) + ETHER_SIZE;


  icmp6hdr->icmp6_cksum = icmp6_sum(d);

  p = d->buf;
  dmac = get_icmp6_opt_source_mac(skb);
  if(!dmac) { 
    debug(DBG_V6, 1, "No LL address option, using source MAC from NS");
    dmac = &skb->dbuf->buf[6];
  }
  store_mac(&p, dmac);
  store_mac(&p, v6->my_mac);
  store_be16(&p, ETH_P_IPV6);

  debug(DBG_V6, 20, "Sending NA");
  // debug_dump(DBG_V6, 25, d->buf, d->dsize);
  sock_send_data(v6_idx, d);

}

uint32_t rs_interval = 1000;
char *nat46_config = NULL;

void set_nat46_config(char *cfg) {
  debug(DBG_V6, 0, "Setting config to: '%s'", cfg);
  nat46_config = cfg;
}

void v6_stack_periodic(v6_stack_t *v6) {
  uint64_t now = get_time_msec();
  int i;
  set_debug_level(DBG_V6, 100);
  set_debug_level(DBG_V6, 0);
  set_debug_level(DBG_REASM, 100);

  // debug(DBG_V6, 100, "Periodic... now: %lld", now);

  if (v6->my_v6addr_state[0] == V6_NONE) {
    /*
     * General Initialization
     */
    pcap_socket_info_t *psi = get_pcap_socket_info(v6_idx);
    memcpy(v6->my_mac, psi->mac, 6);
    memset(v6->gw_mac, 0xff, 6);
    v6->mtu = 1500;

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
      v6->when_send_rs = now + rs_interval;
      rs_interval *= 2;
    }
  }
  /* Run a DAD cycle if needed */
  for(i=0; i< MAX_V6ADDR; i++) {
    if(v6->my_v6addr_state[i] == V6_TENTATIVE) {
      if(v6->when_send_dad[i] < now) {
        if(v6->my_v6_addr_dad_attempts[i] == 0) {
          v6->my_v6addr_state[i] = V6_PREFERRED;
          if(i == 1) {
            nat46_instance_t *nat46 = get_nat46_instance(NULL);
            /* The globally routable address is active. Setup NAT46 */

            nat46_conf("local.v6 ::/128 remote.style RFC6052 local.style MAP0 local.v4 100.64.1.2/32");
            memcpy(&nat46->local_rule.v6_pref, &v6->my_v6addr[i], 16);
            // nat46_conf("nat64pref 64:ff9b::/96");
            // Go6 ASR1k
            nat46_conf("remote.v6 2001:67c:27e4:11::/96");
            // PAN
            // nat46_conf("nat64pref 2001:67c:27e4:64::/96");
            // Ecsdysis
            // nat46_conf("nat64pref 2001:67c:27e4:641::/96");
            //nat46_conf("nat64pref 64:ff9b::/96");
            // AY hetzner
            // nat46_conf("nat64pref 2001:470:73CD:CAFE::/96");
            // cisco NOSTG
            // nat46_conf("nat64pref 2001:420:2ca:410b::/96");
            // configure IPv4 address
            nat46_conf(nat46_config);
            release_nat46_instance(nat46);
          }
        } else {
          send_dad(v6, i);
          v6->my_v6_addr_dad_attempts[i]--;
          v6->when_send_dad[i] = now + DAD_INTERVAL;
        }
      }
    }
  }

}

void swap_mem(void *xp1, void *xp2, int n) {
  uint8_t c;
  uint8_t *p1 = xp1;
  uint8_t *p2 = xp2;
  
  int i;
  for(i=0; i<n; i++) {
    c = *p2;
    *p2 = *p1;
    *p1 = c;
    p1++;
    p2++;
  }
}

/*
 * Process all incoming IPv6 packets,
 * React on the IPv6 ND,
 * and return 1 in case the packet is
 * to be "proxy-handled" through us.
 */

int need_to_process_v6(struct sk_buff *skb, v6_stack_t *v6) {
  struct ipv6hdr *v6hdr = ipv6_hdr(skb);
  struct icmp6hdr *icmp6h;
  uint16_t proto;
  int i;

  BUG_ON(skb->protocol != htons(ETH_P_IPV6));

  if (
       (ipv6_addr_type(&v6hdr->daddr) & IPV6_ADDR_MULTICAST) &&
       (ipv6_addr_scope(&v6hdr->daddr) & IPV6_ADDR_LINKLOCAL)
     ) { 
    skb_pull(skb, sizeof(struct ipv6hdr));
    debug(DBG_V6, 40, "LL Multicast packet received");
    if(v6hdr->nexthdr == NEXTHDR_ICMP) { 
      icmp6h = (void*) skb->data;
      switch(icmp6h->icmp6_type) {
        case NDISC_NEIGHBOUR_SOLICITATION:
          skb_pull(skb, sizeof(struct icmp6hdr));
          ndisc_recv_ns(skb, v6);
          break;
        case NDISC_ROUTER_ADVERTISEMENT:
          skb_pull(skb, sizeof(struct icmp6hdr));
          ndisc_recv_ra(skb, v6);
          break;
      }
    }
    return 0;
  }

  for(i=0; i<MAX_V6ADDR; i++) {
    if ((ipv6_addr_type(&v6hdr->daddr) & IPV6_ADDR_UNICAST)) {
      if( (ipv6_addr_cmp(&v6->my_v6addr[i], &v6hdr->daddr) == 0) &&
          (v6->my_v6addr_state[i] >= V6_TENTATIVE) ) {
        debug(DBG_V6, 1000, "Unicast packet received, scope: %02x", ipv6_addr_scope(&v6hdr->daddr));
	if(ipv6_addr_scope(&v6hdr->daddr) & IPV6_ADDR_LINKLOCAL) {
          /*
           * To-us packet with link-local destination.
           */
          proto = v6hdr->nexthdr;
          switch(proto) {
            case NEXTHDR_ICMP:
              skb_pull(skb, sizeof(struct ipv6hdr));
              icmp6h = (void*) skb->data;
              switch(icmp6h->icmp6_type) {
                case NDISC_NEIGHBOUR_SOLICITATION:
                  skb_pull(skb, sizeof(struct icmp6hdr));
                  ndisc_recv_ns(skb, v6);
                  break;
                case NDISC_ROUTER_ADVERTISEMENT:
                  skb_pull(skb, sizeof(struct icmp6hdr));
                  ndisc_recv_ra(skb, v6);
                  break;
                case ICMPV6_ECHO_REQUEST:
                  swap_mem(&v6hdr->saddr, &v6hdr->daddr, sizeof(v6hdr->daddr));
                  swap_mem(&skb->dbuf->buf[0], &skb->dbuf->buf[6], 6);
                  icmp6h->icmp6_type++;
                  icmp6h->icmp6_cksum--; // FIXME: this is wrong.
                  dlock(skb->dbuf); // send unlocks the data.
                  sock_send_data(v6_idx, skb->dbuf);
                  break;
                default:
                  debug(DBG_V6, 0, "ICMP6 type %d is not supported", icmp6h->icmp6_type);
              }
              break;
            default:
              debug(DBG_V6, 0, "Next header %d is not supported", proto);
          }
          return 0;
	} else {
	  /*
           * Non-link-local packet to one of our addresses.
           * This needs to be processed by the translator.
           */
          return 1;
	}
      }
    }
  }
  return 0;
}


/*
 *
 * Glue with libay
 *
 */


nat46_instance_t single_nat46;

nat46_instance_t *get_nat46_instance(struct sk_buff *skb) {
  /* In kernel this will also lock */
  return &single_nat46;
}

void release_nat46_instance(nat46_instance_t *nat46) {
  /* In kernel this will unlock */
}

int ip_forward(struct sk_buff *skb) {
  memmove(skb->dbuf->buf, skb->data, skb->len);
  skb->dbuf->dsize = skb->len+4;
  dprepend(skb->dbuf, 4);
  memset(skb->dbuf->buf, 0, 4);
  skb->dbuf->buf[3] = 2;
  debug(DBG_V6, 10, "About to send the V4 packet on the wire:");
  assert(skb->dbuf->dsize < 2000);
  debug_dump(DBG_V6, 20, skb->dbuf->buf, skb->dbuf->dsize);
  sock_send_data(v4_idx, skb->dbuf);
  return 1;
}

int ip6_forward(struct sk_buff *skb) {
  skb->dbuf->dsize = skb->len+14;
  dprepend(skb->dbuf, 14);
  memcpy(&skb->dbuf->buf[0], v6_main_stack.gw_mac, 6);
  memcpy(&skb->dbuf->buf[6], v6_main_stack.my_mac, 6);
  skb->dbuf->buf[12] = 0x86;
  skb->dbuf->buf[13] = 0xdd;
  debug(DBG_V6, 10, "About to send the V6 packet on the wire:");
  debug_dump(DBG_V6, 20, skb->dbuf->buf, skb->dbuf->dsize);
  sock_send_data(v6_idx, skb->dbuf);
  return 1;
}

void netif_rx(struct sk_buff *skb) {
  if (0x45 == skb->data[0]) {
    /* IPv4 packet. */
    skb_put(skb, -14);
    ip_forward(skb);
  } else {
    /* not IPv4 packet. We call this only for v4 and v6, so this is IPv6 */
    ip6_forward(skb);
  }
}

void set_v4_idx(int idx) {
  v4_idx = idx;
}

void set_v6_idx(int idx) {
  v6_idx = idx;
}

void nat46_netdev_count_xmit(struct sk_buff *skb, struct net_device *dev) {
 // NO-OP
}


void nat46_glue_periodic(void) {
  v6_stack_periodic(&v6_main_stack);
}

void nat46_conf(char *cfg_str) {
  nat46_instance_t *nat46 = get_nat46_instance(NULL);
  if (!cfg_str) { cfg_str = ""; }
  char *buf = malloc(strlen(cfg_str) + 1);
  memcpy(buf, cfg_str, strlen(cfg_str) + 1);

  debug(DBG_GLOBAL, 0, "Configuring the nat46 instance from string: %s", buf);
  nat46_set_config(nat46, buf, strlen(buf));
  debug_dump(DBG_GLOBAL, 10, nat46, sizeof(*nat46));
  free(buf);
}


void handle_v4_packet(dbuf_t *d) {
  struct sk_buff sk;
  sk.dbuf = d;
  v6_stack_periodic(&v6_main_stack);
  if (d->buf[4] == 0x45) {
    sk.protocol = htons(ETH_P_IP);
    sk.network_header = 4;
    sk.head = sk.dbuf->buf;
    sk.end = sk.dbuf->buf + sk.dbuf->dsize;
    sk.data = sk.dbuf->buf + sk.network_header;
    sk.len = sk.dbuf->dsize - (sk.network_header);
    sk.tail = sk.end;
    debug_dump(DBG_GLOBAL, 30, d->buf, d->dsize);
    nat46_ipv4_input(&sk);
  }
}


void handle_v6_packet(dbuf_t *d) {
  struct sk_buff sk;

  sk.dbuf = d;
  sk.protocol = (*(uint16_t *)(&d->buf[12]));
  if (sk.protocol == htons(ETH_P_IPV6)) {
    // debug_dump(DBG_GLOBAL, 0, d->buf, d->dsize);
    sk.network_header = ETHER_SIZE;
    // FIXME: this is not correct/complete - will break cases with fragments.
    sk.transport_header = sk.network_header + 40;
    sk.head = sk.dbuf->buf;
    sk.end = sk.dbuf->buf + sk.dbuf->dsize;
    sk.data = sk.dbuf->buf + sk.network_header;
    sk.len = sk.dbuf->dsize - sk.network_header;
    sk.tail = sk.end;
    if (need_to_process_v6(&sk, &v6_main_stack)) {
      nat46_ipv6_input(&sk);
    }
  }
  v6_stack_periodic(&v6_main_stack);
}
