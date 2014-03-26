#ifndef __LK_TYPES_H__
#define __LK_TYPES_H__

#include <stdint.h>
#include <netinet/in.h>
#include "dbuf-ay.h"

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


struct sock {
};

typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint16_t __sum16;
typedef int atomic_t;

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
#ifdef CONFIG_NETFILTER
  struct nf_conntrack * nfct;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
  struct sk_buff * nfct_reasm;
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
  struct nf_bridge_info * nf_bridge;
#endif
  __u32 nfmark;
#endif
#ifdef CONFIG_NET_SCHED
  __u16 tc_index;
#ifdef CONFIG_NET_CLS_ACT
  __u16 tc_verd;
#endif
#endif
#ifdef CONFIG_NET_DMA
  dma_cookie_t dma_cookie;
#endif
#ifdef CONFIG_NETWORK_SECMARK
  __u32 secmark;
#endif
  dbuf_t *dbuf; /* reference to dbuf inner type */
  int l3_offset;
  int l4_offset;
  int l5_offset;

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
};

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
};


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



#endif
