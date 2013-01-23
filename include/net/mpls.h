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

struct mpls_ops {
	struct net_device *	(*mpls_master_dev) (const struct net* net);
	struct nhlfe *		(*nhlfe_build) (const struct net* net, struct nlattr *mpls,
						const struct nla_policy *policy, struct nlattr *data[]);
	void			(*nhlfe_free_rcu) (struct nhlfe *nhlfe);
	void			(*nhlfe_free) (struct nhlfe *nhlfe);
	int 			(*nhlfe_dump) (const struct nhlfe *nhlfe,
						struct sk_buff *skb);
	struct nla_policy *	nhlfe_policy;
};

extern struct mpls_ops *mpls_ops;

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
#define MPLS_INC_STATS(net, field)									\
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
#define MPLS_NH_GLOBAL		0x02
#define MPLS_SET_DSCP		0x04
#define MPLS_SET_TC_INDEX	0x08
	u8 num_pop;
	u8 dscp;
	/* nexthop info */
	u16 family;
	u32 ifindex;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} nh;
	/* net info */
	struct net *net;
	u16 tc_index;
	/*
	 * Keep these two here,
	 * so they would be closer to the
	 * actual headers that are going to be pushed
	 */
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
	u32 pid;
	char name[MPLS_NETNS_NAME_MAX];
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

struct net_device *__mpls_master_dev(const struct net* net);
void __nhlfe_free_rcu(struct nhlfe *nhlfe);
void __nhlfe_free(struct nhlfe *nhlfe);
struct nhlfe *__nhlfe_build(const struct net *net, struct nlattr *instr,
				const struct nla_policy *policy, struct nlattr *data[]);
int __nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff *skb);

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

#define mpls_get_master_dev(net) (mpls_ops ? mpls_ops->mpls_master_dev(net) : NULL)
#define nhlfe_build(net, instr, policy) (mpls_ops ? mpls_ops->nhlfe_build(net, instr, policy, NULL) : ERR_PTR(-EPIPE))
#define nhlfe_free_rcu(nhlfe) ({if (mpls_ops) mpls_ops->nhlfe_free_rcu(nhlfe); })
#define nhlfe_free(nhlfe) ({if (mpls_ops) mpls_ops->nhlfe_free(nhlfe); })
#define nhlfe_dump(nhlfe, skb) (mpls_ops ? mpls_ops->nhlfe_dump(nhlfe, skb) : 0)
#define mpls_policy (mpls_ops ? mpls_ops->nhlfe_policy : NULL)

#endif
