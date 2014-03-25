struct sock {
};

typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef uint16_t __u16;
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
  unsigned int truesize;
  atomic_t users;
  unsigned char * head;
  unsigned char * data;
  unsigned char * tail;
  unsigned char * end;
};  

