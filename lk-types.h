#ifndef __LK_TYPES_H__
#define __LK_TYPES_H__

#include <netinet/in.h>
#include <netinet/ip6.h>


#include <stdint.h>
//#include <netinet/in.h>
#include <assert.h>

#include "dbuf-ay.h"

#define BUG_ON(x) assert(!(x))
#define likely(x) (x)
#define unlikely(x) (x)
#define GFP_ATOMIC 0
typedef int gfp_t;

#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

#define IPV6_ADDR_ANY           0x0000U

#define IPV6_ADDR_UNICAST       0x0001U
#define IPV6_ADDR_MULTICAST     0x0002U

#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U

#define IPV6_ADDR_COMPATv4      0x0080U

#define IPV6_ADDR_SCOPE_MASK    0x00f0U

#define IPV6_ADDR_MAPPED        0x1000U

/*
 *      Addr scopes
 */
#define IPV6_ADDR_MC_SCOPE(a)   \
        ((a)->s6_addr[1] & 0x0f)        /* nonstandard */
#define __IPV6_ADDR_SCOPE_INVALID       -1
#define IPV6_ADDR_SCOPE_NODELOCAL       0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL       0x02
#define IPV6_ADDR_SCOPE_SITELOCAL       0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL        0x08
#define IPV6_ADDR_SCOPE_GLOBAL          0x0e

#define IPV6_ADDR_SCOPE_TYPE(scope)     ((scope) << 16)


struct sock {
};

typedef uint32_t u32;
typedef uint32_t __wsum;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef uint8_t u8;
typedef uint16_t __u16;
typedef uint16_t u16;
typedef uint16_t __sum16;
typedef int atomic_t;
typedef int bool;

struct skb_timeval {
    u32 off_sec;
    u32 off_usec;
};

struct net_device {
};

typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
 
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

/*
__u16	le16_to_cpu(const __le16);
__u32	le32_to_cpu(const __le32);
__u64	le64_to_cpu(const __le64);
 
__le16	cpu_to_le16(const __u16);
__le32	cpu_to_le32(const __u32);
__le64	cpu_to_le64(const __u64);
 
__u16	be16_to_cpu(const __be16);
__u32	be32_to_cpu(const __be32);
__u64	be64_to_cpu(const __be64);
 
__be16	cpu_to_be16(const __u16);
__be32	cpu_to_be32(const __u32);
__be64	cpu_to_be64(const __u64);

__u16	le16_to_cpup(const __le16 *);
__u32	le32_to_cpup(const __le32 *);
__u64	le64_to_cpup(const __le64 *);
 
__le16	cpu_to_le16p(const __u16 *);
__le32	cpu_to_le32p(const __u32 *);
__le64	cpu_to_le64p(const __u64 *);
 
__u16	be16_to_cpup(const __be16 *);
__u32	be32_to_cpup(const __be32 *);
__u64	be64_to_cpup(const __be64 *);
 
__be16	cpu_to_be16p(const __u16 *);
__be32	cpu_to_be32p(const __u32 *);
__be64	cpu_to_be64p(const __u64 *);


#define htons(x) cpu_to_be16(x)
#define htonl(x) cpu_to_be32(x)
#define ntohs(x) be16_to_cpu(x)
#define ntohl(x) be32_to_cpu(x)

*/

struct ip_options {
  __be32          faddr;
  __be32          nexthop;
  unsigned char   optlen;
  unsigned char   srr;
  unsigned char   rr;
  unsigned char   ts;
  unsigned char   is_strictroute:1,
                  srr_is_hit:1,
                  is_changed:1,
                  rr_needaddr:1,
                  ts_needtime:1,
                  ts_needaddr:1;
  unsigned char   router_alert;
  unsigned char   cipso;
  unsigned char   __pad2;
  unsigned char   __data[0];
};

struct inet_skb_parm {
  struct ip_options       opt;            /* Compiled IP options          */
  unsigned char           flags;

#define IPSKB_FORWARDED         1
#define IPSKB_XFRM_TUNNEL_SIZE  2
#define IPSKB_XFRM_TRANSFORMED  4
#define IPSKB_FRAG_COMPLETE     8
#define IPSKB_REROUTED          16

  u16                     frag_max_size;
};

#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))

struct sk_buff {
  struct sk_buff * next;
  struct sk_buff * prev;
  struct sock * sk;
  struct skb_timeval tstamp;
  struct net_device * dev;
  struct net_device * input_dev;
  union h;
  union nh;
  union mac;
  struct dst_entry * dst;
  struct sec_path * sp;
  char cb[48];
  unsigned int len;
  unsigned int data_len;
  unsigned int mac_len;
  unsigned int csum;
  __u32 priority;
  __u8 local_df:1;
  __u8 cloned:1;
  __u8 ip_summed:2;
  __u8 nohdr:1;
  __u8 nfctinfo:3;
  __u8 pkt_type:3;
  __u8 fclone:2;
  __u8 ipvs_property:1;
  __be16 protocol;
  void (* destructor) (struct sk_buff *skb);
  struct nf_conntrack * nfct;
  struct sk_buff * nfct_reasm;
  struct nf_bridge_info * nf_bridge;
  __u32 nfmark;
  __u16 tc_index;
  __u16 tc_verd;
  __u32 secmark;
  __u16 nf_trace;
  __u16 peeked;
  dbuf_t *dbuf; /* reference to dbuf inner type */
  union {
    __u32           mark;
    __u32           dropcount;
    __u32           reserved_tailroom;
  };

  __u16                   transport_header;
  __u16                   network_header;
  __u16                   mac_header;

  unsigned int truesize;
  atomic_t users;
  unsigned char * head;
  unsigned char * data;
  unsigned char * tail;
  unsigned char * end;
};  



#define __LITTLE_ENDIAN_BITFIELD

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
         __u8    ihl:4,
                 version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
         __u8    version:4,
                 ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
        /*The options start here. */
} __attribute__((__aligned__(1)));

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8                    priority:4,
                                version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u8                    version:4,
                                priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
        __u8                    flow_lbl[3];

        __be16                  payload_len;
        __u8                    nexthdr;
        __u8                    hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
} __attribute__((__aligned__(1)));

/* IP flags. */
#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_COMPLETE 2
#define CHECKSUM_PARTIAL 3
 
struct frag_hdr {
         __u8    nexthdr;
         __u8    reserved;
         __be16  frag_off;
         __be32  identification;
};
 
#define IP6_MF          0x0001
#define IP6_OFFSET      0xFFF8


#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define NR_ICMP_TYPES           18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL            0       /* TTL count exceeded           */
#define ICMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded */



struct icmphdr {
  __u8          type;
  __u8          code;
  __sum16       checksum;
  union {
        struct {
                __be16  id;
                __be16  sequence;
        } echo;
        __be32  gateway;
        struct {
                __be16  __unused;
                __be16  mtu;
        } frag;
  } un;
};


struct icmp6hdr {

        __u8            icmp6_type;
        __u8            icmp6_code;
        __sum16         icmp6_cksum;


        union {
                __be32                  un_data32[1];
                __be16                  un_data16[2];
                __u8                    un_data8[4];

                struct icmpv6_echo {
                        __be16          identifier;
                        __be16          sequence;
                } u_echo;

                struct icmpv6_nd_advt {
#if defined(__LITTLE_ENDIAN_BITFIELD)
                        __u32           reserved:5,
                                        override:1,
                                        solicited:1,
                                        router:1,
                                        reserved2:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
                        __u32           router:1,
                                        solicited:1,
                                        override:1,
                                        reserved:29;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
                } u_nd_advt;

                struct icmpv6_nd_ra {
                        __u8            hop_limit;
#if defined(__LITTLE_ENDIAN_BITFIELD)
                        __u8            reserved:3,
                                        router_pref:2,
                                        home_agent:1,
                                        other:1,
                                        managed:1;

#elif defined(__BIG_ENDIAN_BITFIELD)
                        __u8            managed:1,
                                        other:1,
                                        home_agent:1,
                                        router_pref:2,
                                        reserved:3;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
                        __be16          rt_lifetime;
                } u_nd_ra;

        } icmp6_dataun;

#define icmp6_identifier        icmp6_dataun.u_echo.identifier
#define icmp6_sequence          icmp6_dataun.u_echo.sequence
#define icmp6_pointer           icmp6_dataun.un_data32[0]
#define icmp6_mtu               icmp6_dataun.un_data32[0]
#define icmp6_unused            icmp6_dataun.un_data32[0]
#define icmp6_maxdelay          icmp6_dataun.un_data16[0]
#define icmp6_router            icmp6_dataun.u_nd_advt.router
#define icmp6_solicited         icmp6_dataun.u_nd_advt.solicited
#define icmp6_override          icmp6_dataun.u_nd_advt.override
#define icmp6_ndiscreserved     icmp6_dataun.u_nd_advt.reserved
#define icmp6_hop_limit         icmp6_dataun.u_nd_ra.hop_limit
#define icmp6_addrconf_managed  icmp6_dataun.u_nd_ra.managed
#define icmp6_addrconf_other    icmp6_dataun.u_nd_ra.other
#define icmp6_rt_lifetime       icmp6_dataun.u_nd_ra.rt_lifetime
#define icmp6_router_pref       icmp6_dataun.u_nd_ra.router_pref
} __attribute__((__aligned__(1)));


#define ICMPV6_ROUTER_PREF_LOW          0x3
#define ICMPV6_ROUTER_PREF_MEDIUM       0x0
#define ICMPV6_ROUTER_PREF_HIGH         0x1
#define ICMPV6_ROUTER_PREF_INVALID      0x2

#define ICMPV6_DEST_UNREACH             1
#define ICMPV6_PKT_TOOBIG               2
#define ICMPV6_TIME_EXCEED              3
#define ICMPV6_PARAMPROB                4

#define ICMPV6_INFOMSG_MASK             0x80

#define ICMPV6_ECHO_REQUEST             128
#define ICMPV6_ECHO_REPLY               129
#define ICMPV6_MGM_QUERY                130
#define ICMPV6_MGM_REPORT               131
#define ICMPV6_MGM_REDUCTION            132

#define NDISC_ROUTER_SOLICITATION       133
#define NDISC_ROUTER_ADVERTISEMENT      134
#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136
#define NDISC_REDIRECT                  137

#define ICMPV6_NI_QUERY                 139
#define ICMPV6_NI_REPLY                 140

#define ICMPV6_MLD2_REPORT              143

#define ICMPV6_DHAAD_REQUEST            144
#define ICMPV6_DHAAD_REPLY              145
#define ICMPV6_MOBILE_PREFIX_SOL        146
#define ICMPV6_MOBILE_PREFIX_ADV        147

/*
 *      Codes for Destination Unreachable
 */
#define ICMPV6_NOROUTE                  0
#define ICMPV6_ADM_PROHIBITED           1
#define ICMPV6_NOT_NEIGHBOUR            2
#define ICMPV6_ADDR_UNREACH             3
#define ICMPV6_PORT_UNREACH             4
#define ICMPV6_POLICY_FAIL              5
#define ICMPV6_REJECT_ROUTE             6

/*
 *      Codes for Time Exceeded
 */
#define ICMPV6_EXC_HOPLIMIT             0
#define ICMPV6_EXC_FRAGTIME             1


struct udphdr {
  __be16  source;
  __be16  dest;
  __be16  len;
  __sum16 check;
};


struct tcphdr {
        __be16  source;
        __be16  dest;
        __be32  seq;
        __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif  
        __be16  window;
        __sum16 check;
        __be16  urg_ptr;
};



int ipv6_addr_type(const struct in6_addr *addr);
struct ipv6hdr *ipv6_hdr(struct sk_buff *skb);
unsigned char *skb_pull(struct sk_buff *skb, unsigned int len);
struct sk_buff *alloc_skb(unsigned int size, gfp_t priority);
long simple_strtol(const char *cp, char **endp, unsigned int base);
int in6_pton(const char *src, int srclen, u8 *dst, int delim, const char **end);
__wsum csum_partial(const void *p, int len, __wsum __sum);
int ip6_forward(struct sk_buff *skb);
void ip6_route_input(struct sk_buff *skb);
unsigned char *skb_push(struct sk_buff *skb, unsigned int len);
struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp_mask);
void skb_reset_network_header(struct sk_buff *skb);
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp_mask);
void skb_set_transport_header(struct sk_buff *skb, const int offset);
struct iphdr *ip_hdr(struct sk_buff *skb);
struct udphdr *udp_hdr(const struct sk_buff *skb);
struct tcphdr *tcp_hdr(const struct sk_buff *skb);
struct icmp6hdr *icmp6_hdr(const struct sk_buff *skb);

__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
                        const struct in6_addr *daddr,
                        __u32 len, unsigned short proto,
                        __wsum csum);
__sum16 ip_fast_csum(const void *iph, unsigned int ihl);
__sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len,
                  unsigned short proto, __wsum sum);

unsigned int ip_hdrlen(const struct sk_buff *skb);
int ip_forward(struct sk_buff *skb);


#endif
