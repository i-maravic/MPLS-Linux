/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * File:  linux/include/net/mpls.h
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *******************************************************************************/

#ifndef __LINUX_NET_MPLS__H_
#define __LINUX_NET_MPLS__H_

#include <net/dst.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <net/ip.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#endif

/*
 * Forward declarations
 */
extern int sysctl_mpls_default_ttl;

#define __dscp_to_tc(_tos) ((_tos) >> 5)
#define __tc_to_dscp(_tc) ((_tc) << 5)

enum {
	MPLSPROTO_UNSPEC = 0,
	MPLSPROTO_IPV4   =  AF_INET,
	MPLSPROTO_IPV6   =  AF_INET6,
	MPLSPROTO_MAX,
};

static inline unsigned short mpls_proto_to_family(unsigned short proto)
{
	switch (proto) {
	case htons(ETH_P_IP):
		return MPLSPROTO_IPV4;
	case htons(ETH_P_IPV6):
		return MPLSPROTO_IPV6;
	default:
		return MPLSPROTO_UNSPEC;
	}
}

struct nhlfe;

struct mpls_afinfo {
	unsigned short		family;
	u32			header_len;
	struct dst_entry *	(*get_route) (const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb);
	bool			(*frag_allowed) (const struct sk_buff *skb, const void *hdr);
	int			(*fragment) (struct sk_buff *skb, int (*output)(struct sk_buff *));
	int			(*set_nh_addr) (struct nhlfe *nhlfe, const struct sockaddr *addr, int len);
	void			(*put_nh_addr) (struct sockaddr *addr, const struct nhlfe *nhlfe);
	int			(*set_dscp) (struct sk_buff *skb, u8 tos);
	u8			(*get_tos) (const struct sk_buff *skb);
	void			(*set_ttl) (void *hdr, u8 ttl);
	u8			(*get_ttl) (const struct sk_buff *skb);
	void			(*icmp_pkt2big_send) (struct sk_buff *skb_in, __be32 info);
	void			(*icmp_ext_send) (struct sk_buff *skb_in, int type, int code, __be32 info,
							u16 ext_length, u8 ext_class, u8 ext_c_type, void *ext_data);
};


extern const struct mpls_afinfo __rcu *mpls_afinfo[MPLSPROTO_MAX];
static inline const struct mpls_afinfo *mpls_get_afinfo(unsigned short family)
{
	BUG_ON(family >= MPLSPROTO_MAX);
	return rcu_dereference(mpls_afinfo[family]);
}

/* Helper macros */
#define MPLS_AFINFO_AF(af, func, ret, args...)							\
	({											\
		const struct mpls_afinfo *info = mpls_get_afinfo(af);				\
		likely(info && info->func) ? info->func(args) : ret;				\
	})

#define MPLS_AFINFO_PROTO(proto, func, ret, args...)						\
	MPLS_AFINFO_AF(mpls_proto_to_family(proto), func, ret, args)

/* functions by af */
#define get_hdr_len_af(af)									\
	({											\
		const struct mpls_afinfo *info = mpls_get_afinfo(af);				\
		info ? info->header_len : MPLS_HDR_LEN;						\
	})
#define get_route_af(af, args...)								\
	MPLS_AFINFO_AF(af, get_route, ERR_PTR(-EPIPE), args)
#define frag_allowed_af(af, args...)								\
	MPLS_AFINFO_AF(af, frag_allowed, false, args)
#define fragment_af(af, args...)								\
	MPLS_AFINFO_AF(af, fragment, -EPIPE, args)
#define set_nh_addr_af(af, args...)								\
	MPLS_AFINFO_AF(af, set_nh_addr, -EPIPE, args)
#define put_nh_addr_af(af, args...)								\
	MPLS_AFINFO_AF(af, put_nh_addr, 0, args)
#define set_dscp_af(af, args...)								\
	MPLS_AFINFO_AF(af, set_dscp, -EPIPE, args)
#define get_tos_af(af, args...)									\
	MPLS_AFINFO_AF(af, get_tos, 0, args)
#define set_ttl_af(af, args...)									\
	MPLS_AFINFO_AF(af, set_ttl, 0, args)
#define get_ttl_af(af, args...)									\
	MPLS_AFINFO_AF(af, get_ttl, sysctl_mpls_default_ttl, args)
#define icmp_send_af(af, args...)								\
	MPLS_AFINFO_AF(af, icmp_send, 0, args)
#define icmp_ext_send_af(af, args...)								\
	MPLS_AFINFO_AF(af, icmp_ext_send, 0, args)

/* functions by proto */
#define get_hdr_len_p(proto)									\
	get_hdr_len_af(mpls_proto_to_family(proto))
#define get_route_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, get_route, ERR_PTR(-EPIPE), args)
#define frag_allowed_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, frag_allowed, false, args)
#define fragment_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, fragment, -EPIPE, args)
#define set_nh_addr_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, set_nh_addr, -EPIPE, args)
#define put_nh_addr_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, put_nh_addr, 0, args)
#define set_dscp_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, set_dscp, -EPIPE, args)
#define get_tos_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, get_tos, 0, args)
#define set_ttl_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, set_ttl, 0, args)
#define get_ttl_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, get_ttl, sysctl_mpls_default_ttl, args)
#define icmp_pkt2big_send_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, icmp_pkt2big_send, 0, args)
#define icmp_ext_send_p(proto, args...)								\
	MPLS_AFINFO_PROTO(proto, icmp_ext_send, 0, args)


struct mpls_ops {
	struct net_device *	(*mpls_master_dev) (const struct net* net);
	int			(*mpls_finish_send) (struct sk_buff *skb);
	struct nhlfe *		(*nhlfe_build) (const struct net* net, struct nlattr *mpls,
						const struct nla_policy *policy, struct nlattr *data[]);
	void			(*nhlfe_free_rcu) (struct nhlfe *nhlfe);
	void			(*nhlfe_free) (struct nhlfe *nhlfe);
	int			(*nhlfe_dump) (const struct nhlfe *nhlfe, struct sk_buff *skb);
	int			(*nhlfe_send) (const struct nhlfe *nhlfe, struct sk_buff *skb);
	struct nla_policy *	nhlfe_policy;
};

extern const struct mpls_ops *mpls_ops;

#define mpls_get_master_dev(net) (mpls_ops ? mpls_ops->mpls_master_dev(net) : NULL)
#define mpls_finish_send(skb) (mpls_ops ? mpls_ops->mpls_finish_send(skb) : NET_XMIT_DROP)
#define nhlfe_build(net, instr, policy) (mpls_ops ? mpls_ops->nhlfe_build(net, instr, policy, NULL) : ERR_PTR(-EPIPE))
#define nhlfe_free_rcu(nhlfe) ({if (mpls_ops) mpls_ops->nhlfe_free_rcu(nhlfe); })
#define nhlfe_free(nhlfe) ({if (mpls_ops) mpls_ops->nhlfe_free(nhlfe); })
#define nhlfe_dump(nhlfe, skb) (mpls_ops ? mpls_ops->nhlfe_dump(nhlfe, skb) : 0)
#define nhlfe_send(nhlfe, skb) (mpls_ops ? mpls_ops->nhlfe_send(nhlfe, skb) : 0)
#define mpls_policy (mpls_ops ? mpls_ops->nhlfe_policy : NULL)

#if IS_ENABLED(CONFIG_MPLS)

/* This is called by the IP fragmenting code and it ensures there is
 * enough room for the MPLS headers (if there are any). */
static inline unsigned int nf_mpls_pad(const struct sk_buff *skb)
{
	if (skb->nf_mpls)
		return skb->nf_mpls->hdr_len;
	return 0;
}

static inline int mpls_nla_size(void)
{
	return nla_total_size(1) +		/* MPLSA_POP */
		nla_total_size(1) +		/* MPLSA_DSCP */
		nla_total_size(2) +		/* MPLSA_TC_INDEX */
		nla_total_size(MPLS_HDR_LEN) +	/* MPLSA_SWAP */
		10*nla_total_size(MPLS_HDR_LEN) + /* MPLSA_PUSH */
		nla_total_size(4) +		/* MPLSA_NEXTHOP_OIF */
		/* MPLSA_NEXTHOP_ADDR */
#if IS_ENABLED(CONFIG_IPV6)
		nla_total_size(sizeof(struct sockaddr_in6))
#else
		nla_total_size(sizeof(struct sockaddr_in))
#endif
		;
}

#else

#define nf_bridge_pad(skb) (0)

#define mpls_nla_size() (0)

#endif

/*
 * SNMP statistics for MPLS
 */
#define MPLS_INC_STATS(net, field)								\
	SNMP_INC_STATS((net)->mib.mpls_statistics, field)

#define MPLS_INC_STATS_BH(net, field)								\
	SNMP_INC_STATS_BH((net)->mib.mpls_statistics, field)

#define MPLS_ADD_STATS(net, field, add)								\
	SNMP_ADD_STATS((net)->mib.mpls_statistics, field, add)

#define MPLS_ADD_STATS_BH(net, field, add)							\
	SNMP_ADD_STATS_BH((net)->mib.mpls_statistics, field, add)

static inline struct mpls_hdr *mpls_hdr(const struct sk_buff *skb)
{
	return (struct mpls_hdr *)skb_network_header(skb);
}

struct mpls_skb_cb {
	struct mpls_hdr hdr;
};

#define MPLSCB(skb) ((struct mpls_skb_cb *)((skb)->cb))

static inline void mpls_peek_label(struct sk_buff *skb)
{
	MPLSCB(skb)->hdr = *mpls_hdr(skb);
}

static inline void set_mpls_ttl(struct sk_buff *skb, u8 ttl)
{
	if (likely(skb->protocol == htons(ETH_P_MPLS_UC)))
		mpls_hdr(skb)->ttl = ttl;
}

struct mpls_tunnel {
	struct nhlfe __rcu *nhlfe;
	u32 hlen;
	struct net_device_stats stats;
};

struct nhlfe {
	/*
	 * NHLFE accounting data,
	 * that isn't used in comparisons
	 */
	union {
		struct rcu_head rcu;
		atomic_t refcnt;
	};
#define NHLFE_CMPR_START(ptr) ((char *)(&((struct nhlfe *)ptr)->dead))
	u8 dead;
	/* NHLFE data */
	u8 flags;
#define MPLS_HAS_NH		0x01
#define MPLS_SET_DSCP		0x02
#define MPLS_SET_TC_INDEX	0x04
	u8 num_pop;
	u8 dscp;
	u16 tc_index;
	/* nexthop info */
	u16 family;
	struct net_device *dev;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} nh;
	/*
	 * Keep these two here,
	 * so they would be closer to the
	 * actual headers that are going to be pushed
	 */
	u8 __pad[2];
	u8 num_push;
	u8 has_swap;
	struct mpls_hdr data[0];
};

#define MPLS_ALIGN sizeof(long long)

#define NHLFE_CMPR_OFFSET(nhlfe) ((unsigned long long)NHLFE_CMPR_START(0))

#define NHLFE_SIZE(num_push, swap)							\
	(sizeof(struct nhlfe) + (((num_push) + (swap)) * MPLS_HDR_LEN))

#define NHLFE_CMPR_LEN(nhlfe)								\
	(NHLFE_SIZE((nhlfe)->num_push, (nhlfe)->has_swap) - NHLFE_CMPR_OFFSET(nhlfe))

struct ilm {
	struct rcu_head rcu;
	struct nhlfe __rcu *nhlfe;
	u32 label;
	u8 tc;
	u8 owner;
	u8 pad[2];
};

extern int ilm_net_id;

/* A hash bucket */
struct hbucket {
	struct ilm __rcu *ilm;	/* the array of the values */
	u8 size;		/* size of the array */
	u8 pos;			/* position of the first free entry */
};

/* The hash table: the table size stored here in order to make resizing easy */
struct htable {
	union {
		struct rcu_head rcu;
		struct work_struct work;
	};
	u8 htable_bits;		/* size of hash table == 2^htable_bits */
	struct hbucket bucket[0]; /* hashtable buckets */
};

/* The hash structure */
struct ilm_hash {
	struct htable __rcu *table; /* the hash table */
	u32 elements;		/* current element */
	u32 initval;		/* random jhash init value */
	u8 hash_max;		/* max elements in an array block */
};

/* Per-net hash tables */
struct ilm_net {
	struct ilm_hash h;
};

extern int mpls_dev_net_id;

struct mpls_dev_net {
	struct net_device *master_dev;
};

#define MPLS_DEFAULT_TTL 64

extern struct nla_policy __nhlfe_policy[__MPLS_ATTR_MAX];

static inline struct nhlfe *
nhlfe_hold(struct nhlfe *nhlfe)
{
	if (likely(nhlfe)) {
		WARN_ON(nhlfe->dead);
		atomic_inc(&nhlfe->refcnt);
	}
	return nhlfe;
}

static inline void
nhlfe_put(struct nhlfe *nhlfe)
{
	if (likely(atomic_dec_and_test(&nhlfe->refcnt))) {
		WARN_ON(!nhlfe->dead);
		kfree_rcu(nhlfe, rcu);
	}
}

static inline bool
mpls_nhlfe_eq(struct nhlfe *lhs, struct nhlfe *rhs)
{
	if (rhs == lhs)
		return true;
	if (rhs == NULL || lhs == NULL)
		return false;
	if (rhs->num_push != lhs->num_push || rhs->has_swap != lhs->has_swap)
		return false;
	return memcmp(NHLFE_CMPR_START(lhs), NHLFE_CMPR_START(rhs), NHLFE_CMPR_LEN(lhs)) == 0;
}

#define nf_mpls_nhlfe(nf_mpls)								\
	(*((struct nhlfe const **)(nf_mpls)->data))

#define nf_mpls_dev(nf_mpls)								\
	(*((struct net_device **)((char *)(nf_mpls)->data + sizeof(void **))))

#define nf_mpls_hdr_stack(nf_mpls)							\
	((struct mpls_hdr *)((char *)(nf_mpls)->data + 2 * sizeof(void **)))

#define NF_MPLS_SIZE(hdr_len, has_info)							\
	({										\
		size_t size;								\
		if (!has_info)								\
			size = sizeof(struct nf_mpls);					\
		else									\
			size = sizeof(struct nf_mpls) + 2 * sizeof(void **) + hdr_len * sizeof(u32); \
		ALIGN(size, MPLS_ALIGN);						\
	})

static inline struct nf_mpls *nf_mpls_alloc(struct sk_buff *skb, u16 hdr_len, u16 has_info)
{
	skb->nf_mpls = kzalloc(NF_MPLS_SIZE(hdr_len, has_info), GFP_ATOMIC);
	if (likely(skb->nf_mpls)) {
		atomic_set(&(skb->nf_mpls->use), 1);
		skb->nf_mpls->hdr_len = hdr_len;
		skb->nf_mpls->has_info = has_info;
	}

	return skb->nf_mpls;
}

static inline struct nf_mpls *nf_mpls_unshare(struct sk_buff *skb, u16 hdr_len, u16 has_info)
{
	struct nf_mpls *nf_mpls = skb->nf_mpls;

	if (likely(!nf_mpls || nf_mpls->hdr_len != hdr_len || nf_mpls->has_info != has_info) ||
		    atomic_read(&nf_mpls->use) > 1) {
		struct nf_mpls *tmp = nf_mpls_alloc(skb, hdr_len, has_info);
		if (likely(nf_mpls && tmp))
			memcpy(tmp->daddr, nf_mpls->daddr, sizeof(((struct nf_mpls *)0)->daddr));
		nf_mpls_put(nf_mpls);
	}
	return skb->nf_mpls;
}

static inline bool push_mpls_hdr_payload(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct nf_mpls *nf_mpls = skb->nf_mpls;
	u16 data_len = nf_mpls->hdr_len;

	BUG_ON(!nf_mpls);

	if (unlikely(skb_cow_head(skb, data_len + LL_RESERVED_SPACE(dst->dev)) < 0))
		goto err;

	if (data_len) {
		skb_push(skb, data_len);
		skb_reset_network_header(skb);
		memcpy(skb_network_header(skb), nf_mpls_hdr_stack(nf_mpls), data_len);

		if (unlikely(skb->len > dst_mtu(dst)))
			goto err;
		skb->protocol = htons(ETH_P_MPLS_UC);
		mpls_peek_label(skb);
	}

	return true;
err:
	return false;
}

static inline struct net_device *
__mpls_master_dev(const struct net* net)
{
	struct mpls_dev_net *mdn = net_generic(net, mpls_dev_net_id);
	return mdn->master_dev;
}

int __mpls_master_dev_state(const struct net* net);

int __mpls_finish_send(struct sk_buff *skb);
void __nhlfe_free_rcu(struct nhlfe *nhlfe);
void __nhlfe_free(struct nhlfe *nhlfe);
struct nhlfe *__nhlfe_build(const struct net *net, struct nlattr *instr,
				const struct nla_policy *policy, struct nlattr *data[]);
int __nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff *skb);
int __nhlfe_send(const struct nhlfe *nhlfe, struct sk_buff *skb);

int ilm_init(void);
void ilm_exit(void);

int mpls_dev_init(void);
void mpls_dev_exit(void);

#if IS_ENABLED(CONFIG_SYSCTL)
extern int mpls_sysctl_net_id;
extern int sysctl_mpls_propagate_ttl;
extern int sysctl_mpls_propagate_tc;

struct mpls_sysctl_net {
	int sysctl_mpls_propagate_ttl;
	int sysctl_mpls_propagate_tc;
	struct ctl_table_header *mpls_hdr;
};

static inline int
mpls_propagate_ttl(struct net* net)
{
	if (net_eq(net, &init_net))
		return sysctl_mpls_propagate_ttl;
	else {
		struct mpls_sysctl_net *msn;
		msn = net_generic(net, mpls_sysctl_net_id);
		return msn->sysctl_mpls_propagate_ttl;
	}
}

static inline int
mpls_propagate_tc(struct net* net)
{
	if (net_eq(net, &init_net))
		return sysctl_mpls_propagate_tc;
	else {
		struct mpls_sysctl_net *msn;
		msn = net_generic(net, mpls_sysctl_net_id);
		return msn->sysctl_mpls_propagate_tc;
	}
}
#else

#define mpls_propagate_ttl(net) (1)
#define mpls_propagate_tc(net) (1)

#endif

int mpls_recv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *ptype, struct net_device *orig);

extern int mpls_register_afinfo(const struct mpls_afinfo *afinfo);
extern void mpls_unregister_afinfo(const struct mpls_afinfo *afinfo);

#endif
