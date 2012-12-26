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

/*
 * Forward declarations
 */
extern int sysctl_mpls_default_ttl;

struct mpls_ops {
	struct nhlfe		*(*nhlfe_build) (struct nlattr **instr);
	void			(*nhlfe_free) (struct nhlfe *nhlfe);
	int 			(*nhlfe_dump) (const struct nhlfe *nhlfe,
						struct sk_buff *skb);
	struct net_device	*(*mpls_master_dev) (struct net* net);
	bool			(*mpls_nhlfe_eq) (struct nhlfe *lhs,
						  struct nhlfe *rhs);
	struct nla_policy	*nhlfe_policy;
};

extern struct mpls_ops *mpls_ops;

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

struct mpls_hdr {
	__be16 label_l;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 s:1;
	__u8 tc:3;
	__u8 label_u:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 label_u:4;
	__u8 tc:3;
	__u8 s:1;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8 ttl;
};

static inline struct mpls_hdr *mpls_hdr(const struct sk_buff *skb)
{
	return (struct mpls_hdr *)skb_network_header(skb);
}

struct mpls_skb_cb {
	struct mpls_hdr hdr;
	__be32 daddr[4];
};

#define MPLSCB(skb) ((struct mpls_skb_cb *)((skb)->cb))

#define label_entry_peek(skb)							\
	do {									\
		struct mpls_skb_cb *cb = MPLSCB(skb);				\
		struct mpls_hdr *mplsh = mpls_hdr(skb);				\
		cb->hdr.label_l = mplsh->label_l;				\
		cb->hdr.label_u = mplsh->label_u;				\
		cb->hdr.tc = mplsh->tc;						\
		cb->hdr.s = mplsh->s;						\
		cb->hdr.ttl = mplsh->ttl;					\
	} while(0)

struct mpls_tunnel {
	struct nhlfe __rcu *nhlfe;
	u32 hlen;
	struct net_device_stats stats;
};

struct __instr {
	unsigned long data;
	u16 cmd;
};

struct nhlfe {
	union {
		struct rcu_head rcu;
		atomic_t refcnt;
	};
	u8 no_instr;
	u8 no_push;
	u8 no_pop;
	u8 dead;
	struct __instr data[0];
};

struct ilm {
	struct rcu_head rcu;
	struct mpls_key key;
	struct nhlfe __rcu *nhlfe;
};

#define MPLS_DEFAULT_TTL 64

extern struct nla_policy __nhlfe_policy[__MPLS_ATTR_MAX];

static inline void
nhlfe_hold(struct nhlfe *nhlfe)
{
	WARN_ON(nhlfe->dead);
	atomic_inc(&nhlfe->refcnt);
}

static inline void
nhlfe_put(struct nhlfe *nhlfe)
{
	if (likely(atomic_dec_and_test(&nhlfe->refcnt))) {
		WARN_ON(!nhlfe->dead);
		kfree_rcu(nhlfe, rcu);
	}
}

void
__nhlfe_free(struct nhlfe *nhlfe);

struct nhlfe *
__nhlfe_build(struct nlattr **instr);

int
__nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff *skb);

int
ilm_init(void);

void
ilm_exit(void);

int
mpls_dev_init(void);

void
mpls_dev_exit(void);

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

int
mpls_recv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *ptype, struct net_device *orig);

#define nhlfe_build(instr) (mpls_ops ? mpls_ops->nhlfe_build(instr) : ERR_PTR(-EPIPE))
#define nhlfe_free(nhlfe) ({if (mpls_ops) mpls_ops->nhlfe_free(nhlfe); })
#define nhlfe_dump(nhlfe, skb) (mpls_ops ? mpls_ops->nhlfe_dump(nhlfe, skb) : 0)
#define mpls_policy (mpls_ops ? mpls_ops->nhlfe_policy : NULL)

#endif
