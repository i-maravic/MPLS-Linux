/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_instr.c
 *      - It implements: instruction maintainace
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
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/
#include <linux/skbuff.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/dst.h>
#include <net/mpls.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/arp.h>
#include <linux/rtnetlink.h>
#include <net/ip_fib.h>
#include <linux/inet.h>
#include <net/net_namespace.h>
#include "mpls_cmd.h"

struct nla_policy __nhlfe_policy[__MPLS_ATTR_MAX] __read_mostly = {
	[MPLSA_DSCP]		= { .type = NLA_U8 },
#if IS_ENABLED(CONFIG_NET_SCHED)
	[MPLSA_TC_INDEX]	= { .type = NLA_U16 },
#else
	[MPLSA_TC_INDEX]	= { .type = NLA_PROHIBIT },
#endif
	[MPLSA_PUSH]		= { .type = NLA_BINARY, },
	[MPLSA_NEXTHOP_GLOBAL]	= { .type = NLA_FLAG },
	[MPLSA_NEXTHOP_IFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ },
	[MPLSA_NEXTHOP_OIF]	= { .type = NLA_U32 },
	[MPLSA_NEXTHOP_ADDR]	= { .type = NLA_BINARY },
	[MPLSA_POP]		= { .type = NLA_PROHIBIT },
	[MPLSA_SWAP]		= { .type = NLA_PROHIBIT },
	[MPLSA_NETNS_FD]	= { .type = NLA_PROHIBIT },
	[MPLSA_NETNS_PID]	= { .type = NLA_PROHIBIT },
	[MPLSA_NETNS_NAME]	= { .type = NLA_PROHIBIT },
};

static inline int mpls_prepare_skb(struct sk_buff *skb,
				   unsigned int header_size,
				   struct net_device *dev)
{
	secpath_reset(skb);
	skb->mac_header = skb->network_header;
	skb_reset_network_header(skb);

	if (!pskb_may_pull(skb, header_size))
		return -ENOBUFS;

	skb->pkt_type = PACKET_HOST;
	__skb_tunnel_rx(skb, dev);
	return 0;
}

static inline void set_ip_ttl(struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static inline u8 get_tc(struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return __dscp_to_tc(ip_hdr(skb)->tos);
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		return __dscp_to_tc(ipv6_get_dsfield(ipv6_hdr(skb)));
#endif
	case htons(ETH_P_MPLS_UC):
		return mpls_hdr(skb)->tc;
	default:
		return 0;
	}
}

static inline int set_ip_dscp(struct sk_buff *skb, u8 tos)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iphdr;
		if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
			goto discard;
		iphdr = ip_hdr(skb);
		ipv4_change_dsfield(iphdr, (u8)~IPTOS_PREC_MASK, IPTOS_PREC(tos));
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6hdr;
		if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
			goto discard;
		ipv6hdr = ipv6_hdr(skb);
		ipv6_change_dsfield(ipv6hdr, (u8)~IPTOS_PREC_MASK, IPTOS_PREC(tos));
	}
#endif
	else
		goto discard;
	return NET_XMIT_SUCCESS;

discard:
	return NET_XMIT_DROP;
}

static inline void set_mpls_ttl(struct sk_buff *skb, u8 ttl)
{
	if (likely(skb->protocol == htons(ETH_P_MPLS_UC)))
		mpls_hdr(skb)->ttl = ttl;
}

static inline u8 get_ttl(struct sk_buff *skb)
{
	switch(skb->protocol) {
	case htons(ETH_P_IP):
		return ip_hdr(skb)->ttl;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		return ipv6_hdr(skb)->hop_limit;
#endif
	case htons(ETH_P_MPLS_UC):
		return mpls_hdr(skb)->ttl;
	default:
		return sysctl_mpls_default_ttl;
	}
}

#if IS_ENABLED(CONFIG_IPV6)
static bool
ipv6_has_fragment_hdr(const struct ipv6hdr *ip6hdr, const struct sk_buff *skb)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr) + ((unsigned char *)ip6hdr - skb_network_header(skb));
	u8 nexthdr = ip6hdr->nexthdr;

	while (nexthdr != NEXTHDR_FRAGMENT) {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE)
			return false;

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return false;

		if (nexthdr == NEXTHDR_AUTH) {
			hdrlen = (hp->hdrlen + 2) << 2;
		} else
			hdrlen = ipv6_optlen(hp);

		start += hdrlen;
		nexthdr = hp->nexthdr;
	}

	return true;
}
#endif

#define NF_MPLS_SIZE(hdr_len, has_info)							\
	({										\
		size_t size;								\
		if (!has_info)								\
			size = sizeof(struct nf_mpls);					\
		else									\
			size = sizeof(struct nf_mpls) + 2 * sizeof(void **) + hdr_len * sizeof(u32);\
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

static inline
struct dst_entry *nhlfe_get_dst_ipv4(const struct nhlfe *nhlfe,
				     struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct flowi4 fl4 = {
		.flowi4_oif = nhlfe->ifindex,
		.daddr = nhlfe->nh.ipv4.s_addr,
		.flowi4_flags = FLOWI_FLAG_MPLS,
	};

	dst = (struct dst_entry *)ip_route_output_key(net, &fl4);
	if (IS_ERR(dst))
		return dst;

	if (skb) {
		struct nf_mpls *tmp = nf_mpls_unshare(skb, 0, 0);
		if (likely(tmp))
			memcpy(tmp->daddr, &nhlfe->nh.ipv4.s_addr, sizeof(nhlfe->nh.ipv4.s_addr));
		else {
			dst_release(dst);
			return ERR_PTR(-ENOMEM);
		}
	}

	return dst;
}

#if IS_ENABLED(CONFIG_IPV6)
static inline
struct dst_entry *nhlfe_get_dst_ipv6(const struct nhlfe *nhlfe,
				     struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct flowi6 fl6 = {
		.flowi6_oif = nhlfe->ifindex,
		.daddr = nhlfe->nh.ipv6,
		.flowi6_flags = FLOWI_FLAG_MPLS,
	};

	dst = ip6_route_output(net, NULL, &fl6);
	if (!dst || dst->error) {
		dst_release(dst);
		return ERR_PTR(-ENETUNREACH);
	}

	if (skb) {
		struct nf_mpls *tmp = nf_mpls_unshare(skb, 0, 0);
		if (likely(tmp))
			memcpy(tmp->daddr, &nhlfe->nh.ipv6.s6_addr, sizeof(nhlfe->nh.ipv6.s6_addr));
		else {
			dst_release(dst);
			return ERR_PTR(-ENOMEM);
		}
	}
	return dst;
}
#endif

bool __push_mpls_hdr_payload(struct sk_buff *skb)
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

int strip_mpls_headers(struct sk_buff *skb)
{
	struct mpls_hdr *hdr = mpls_hdr(skb);
	struct iphdr *iph;
	u16 data_len;
	struct nf_mpls *nf_mpls;

	if (skb->protocol == htons(ETH_P_IP)

#if IS_ENABLED(CONFIG_IPV6)
		   || skb->protocol == htons(ETH_P_IPV6)
#endif
		   ) {
		data_len = 0;
		goto found_ip;
	}

	if (skb->protocol != htons(ETH_P_MPLS_UC))
		goto err;

	data_len = MPLS_HDR_LEN;
	while (!hdr->s) {
		if (unlikely(!pskb_may_pull(skb, data_len)))
			goto err;
		data_len += MPLS_HDR_LEN;
		hdr++;
	}

found_ip:
	nf_mpls = nf_mpls_unshare(skb, data_len, 1);
	if (unlikely(!nf_mpls))
		return -ENOMEM;

	memcpy(nf_mpls_hdr_stack(nf_mpls), mpls_hdr(skb), data_len);

	skb_pull(skb, data_len);
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	if (iph->version == 4)
		skb->protocol = htons(ETH_P_IP);
	else if (iph->version == 6)
		skb->protocol = htons(ETH_P_IPV6);
	else
		goto err;

	return 0;

err:
	return -EINVAL;
}

static inline int mpls_finish_send(struct sk_buff *skb)
{
	struct neighbour *neigh;
	u32 packet_length = skb->len;
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

	BUG_ON(!skb->nf_mpls);

	neigh = dst_neigh_lookup(dst, skb->nf_mpls->daddr);
	if (unlikely(!neigh))
		goto err;

	__dst_neigh_output(dst, neigh, skb,
			   (skb->protocol == htons(ETH_P_MPLS_UC)) ?
			   &neigh->hh_mpls : &neigh->hh);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTPACKETS);
	MPLS_ADD_STATS_BH(net, MPLS_MIB_OUTOCTETS, packet_length);
	neigh_release(neigh);
	return NET_XMIT_SUCCESS;

err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return NET_XMIT_DROP;
}

static int mpls_finish_send2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

	if (unlikely(!__push_mpls_hdr_payload(skb))) {
		dev_kfree_skb(skb);
		MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
		return NET_XMIT_DROP;
	}
	MPLS_INC_STATS_BH(net, MPLS_MIB_IFOUTFRAGMENTEDPKTS);
	return mpls_finish_send(skb);
}

static int mpls_fragment_packet(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	int ret;
	struct net *net = dev_net(skb_dst(skb)->dev);

	if (unlikely(!(nhlfe->flags & MPLS_HAS_NH)))
		goto err;

	ret = strip_mpls_headers(skb);
	if (unlikely(ret))
		goto err;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto err;

	if (skb->protocol == htons(ETH_P_IP)) {
		BUG_ON(ip_hdr(skb)->frag_off & htons(IP_DF));
		return ip_fragment(skb, mpls_finish_send2);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		BUG_ON(skb->len >= IPV6_MIN_MTU || !ipv6_has_fragment_hdr(ipv6_hdr(skb), skb));
		return ip6_fragment(skb, mpls_finish_send2);
	}
#endif
err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return NET_XMIT_DROP;
}

static inline int mpls_send(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	BUG_ON(!skb->nf_mpls);
	if (unlikely(skb->len > dst_mtu(skb_dst(skb))))
		return mpls_fragment_packet(skb, nhlfe);
	return mpls_finish_send(skb);
}

static struct nhlfe *
nhlfe_alloc(int num_push, int has_swap)
{
	struct nhlfe *nhlfe;
	size_t sz = NHLFE_SIZE(num_push, has_swap);
	sz = ALIGN(sz, MPLS_ALIGN);

	nhlfe = kzalloc(sz, GFP_KERNEL);
	if (unlikely(nhlfe == NULL))
		return ERR_PTR(-ENOMEM);

	atomic_set(&nhlfe->refcnt, 1);

	return nhlfe;
}

void __nhlfe_free_rcu(struct nhlfe *nhlfe)
{
	if (unlikely(nhlfe == NULL))
		return;

	WARN_ON(nhlfe->dead);
	nhlfe->dead = 1;

	if (nhlfe->net)
		release_net(nhlfe->net);

	if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
		kfree_rcu(nhlfe, rcu);
}

void __nhlfe_free(struct nhlfe *nhlfe)
{
	if (unlikely(nhlfe == NULL))
		return;

	WARN_ON(nhlfe->dead);
	nhlfe->dead = 1;

	if (nhlfe->net)
		release_net(nhlfe->net);

	if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
		kfree(nhlfe);
	else
		WARN_ON(1);
}


struct nhlfe * __nhlfe_build(const struct net *net, struct nlattr *attr, const struct nla_policy *policy, struct nlattr *tb[])
{
	struct nhlfe *nhlfe;
	struct ilm_net *ilmn = NULL;
	struct nlattr *data[MPLS_ATTR_MAX + 1];
	int num_push = 0, has_swap = 0;
	const struct net_device *dev = NULL;
	struct mpls_hdr *hdrs;
	int error;

	/* If the policy is set to NULL, we're using pre-parsed data  */
	if (policy) {
		error = nla_parse(data, MPLS_ATTR_MAX, nla_data(attr), nla_len(attr), policy);
		if (error < 0)
			return ERR_PTR(error);

		tb = data;
	}

	error = -EINVAL;

	if (tb[MPLSA_PUSH])
		num_push = nla_len(tb[MPLSA_PUSH]) / MPLS_HDR_LEN;

	if (tb[MPLSA_SWAP])
		has_swap = 1;

	nhlfe = nhlfe_alloc(num_push, has_swap);
	if (IS_ERR(nhlfe))
		return ERR_CAST(nhlfe);

	hdrs = nhlfe->data;

	if (tb[MPLSA_POP])
		nhlfe->num_pop = nla_get_u8(tb[MPLSA_POP]);

	if (tb[MPLSA_SWAP]) {
		nhlfe->has_swap = 1;
		memcpy(hdrs, nla_data(tb[MPLSA_SWAP]), MPLS_HDR_LEN);
		++hdrs;
	}

	if (tb[MPLSA_DSCP]) {
		nhlfe->flags |= MPLS_SET_DSCP;
		nhlfe->dscp = nla_get_u8(tb[MPLSA_DSCP]);
	}


	if (tb[MPLSA_TC_INDEX]) {
		nhlfe->flags |= MPLS_SET_TC_INDEX;
		nhlfe->tc_index = nla_get_u8(tb[MPLSA_TC_INDEX]);
	}

	if (tb[MPLSA_PUSH]) {
		nhlfe->num_push = nla_len(tb[MPLSA_PUSH]) / MPLS_HDR_LEN;
		memcpy(hdrs, nla_data(tb[MPLSA_PUSH]), nla_len(tb[MPLSA_PUSH]));
	}

	if (tb[MPLSA_NETNS_FD]) {
		if (!net_eq(&init_net, net))
			goto err;

		nhlfe->net = get_net_ns_by_fd(nla_get_u32(tb[MPLSA_NETNS_FD]));

		if (IS_ERR(nhlfe->net)) {
			error = PTR_ERR(nhlfe->net);
			goto err;
		}

		if (!tb[MPLSA_NETNS_NAME]) {
			put_net(nhlfe->net);
			goto err;
		} else {
			ilmn = net_generic(nhlfe->net, ilm_net_id);
			nla_strlcpy(ilmn->name, tb[MPLSA_NETNS_NAME], MPLS_NETNS_NAME_MAX);
		}

		put_net(nhlfe->net);
	}

	if (tb[MPLSA_NETNS_PID]) {
		if (!net_eq(&init_net, net) || nhlfe->net)
			goto err;

		nhlfe->net = get_net_ns_by_pid(nla_get_u32(tb[MPLSA_NETNS_PID]));

		if (IS_ERR(nhlfe->net)) {
			error = PTR_ERR(nhlfe->net);
			goto err;
		}

		ilmn = net_generic(nhlfe->net, ilm_net_id);
		ilmn->pid = nla_get_u32(tb[MPLSA_NETNS_PID]);

		put_net(nhlfe->net);
	}

	if (tb[MPLSA_NEXTHOP_ADDR]) {
		struct sockaddr *addr = nla_data(tb[MPLSA_NEXTHOP_ADDR]);
		if (nla_len(tb[MPLSA_NEXTHOP_ADDR]) < sizeof(struct sockaddr))
			goto err;

		if (nhlfe->net)
			goto err;

		nhlfe->flags |= MPLS_HAS_NH;

		nhlfe->family = addr->sa_family;
		switch (addr->sa_family) {
		case AF_INET:
			nhlfe->nh.ipv4 = ((struct sockaddr_in *)addr)->sin_addr;
			if (nhlfe->nh.ipv4.s_addr == 0)
				goto err;
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case AF_INET6:
			if (nla_len(tb[MPLSA_NEXTHOP_ADDR]) < sizeof(struct sockaddr_in6))
				goto err;
			nhlfe->nh.ipv6 = ((struct sockaddr_in6 *)addr)->sin6_addr;
			if (ipv6_addr_any(&nhlfe->nh.ipv6))
				goto err;
			break;
#endif
		default:
			goto err;
		}
	}

	if (tb[MPLSA_NEXTHOP_GLOBAL]) {
		if (!(nhlfe->flags & MPLS_HAS_NH))
			goto err;
		nhlfe->flags |= MPLS_NH_GLOBAL;
	}

	if (tb[MPLSA_NEXTHOP_IFNAME]) {
		if (!(nhlfe->flags & MPLS_NH_GLOBAL) || !(nhlfe->flags & MPLS_HAS_NH))
			goto err;
		dev = dev_get_by_name_rcu(&init_net, nla_data(tb[MPLSA_NEXTHOP_IFNAME]));
		if (!dev) {
			error = -ENODEV;
			goto err;
		}
		nhlfe->ifindex = dev->ifindex;
	}

	if (tb[MPLSA_NEXTHOP_OIF]) {
		if (nhlfe->ifindex || !(nhlfe->flags & MPLS_HAS_NH) || (nhlfe->flags & MPLS_NH_GLOBAL))
			goto err;
		/* Cast away const from net */
		dev = dev_get_by_index_rcu((struct net *)net, nla_get_u32(tb[MPLSA_NEXTHOP_OIF]));
		if (!dev) {
			error = -ENODEV;
			goto err;
		}
		nhlfe->ifindex = nla_get_u32(tb[MPLSA_NEXTHOP_OIF]);
	}

	if (dev) {
		if (!(dev->flags & IFF_UP)) {
			error = -ENETDOWN;
			goto err;
		}
		if (!(dev->flags & IFF_MPLS)) {
			error = -EPFNOSUPPORT;
			goto err;
		}
	}

	/* Sanity check */
	if (!(nhlfe->flags & MPLS_HAS_NH) &&
		   (nhlfe->num_push || nhlfe->has_swap || !nhlfe->num_pop))
		goto err;

	if (nhlfe->net) {
		if (net_eq(&init_net, nhlfe->net))
			goto err;

		hold_net(nhlfe->net);
	}

	return nhlfe;
err:
	kfree(nhlfe);
	return ERR_PTR(error);
}

struct dst_entry *nhlfe_get_nexthop_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb)
{
	if (!(nhlfe->flags & MPLS_HAS_NH))
		return NULL;

	switch (nhlfe->family) {
	case AF_INET:
		return nhlfe_get_dst_ipv4(nhlfe, net, skb);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return nhlfe_get_dst_ipv6(nhlfe, net, skb);
#endif
	default:
		return ERR_PTR(-EPFNOSUPPORT);
	}
}

static int mpls_pop(struct sk_buff *skb, int pop)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_hdr *mplshdr;
	struct net *net = dev_net(skb->dev);
	int propagate_ttl = mpls_propagate_ttl(net);
	int propagate_tc = mpls_propagate_tc(net);

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC)))
		goto discard;

	if (unlikely(pop == POP_ALL)) {
		u32 data_len = MPLS_HDR_LEN;

		mplshdr = mpls_hdr(skb);
		while (!mplshdr->s) {
			if (unlikely(!pskb_may_pull(skb, data_len)))
				goto discard;

			data_len += MPLS_HDR_LEN;
			mplshdr++;
		}

		skb_pull(skb, data_len);
		skb_reset_network_header(skb);

		/*
		 * Reset number of pops and S bit
		 * so we could jump in to the while loop below
		 */
		pop = 0;
		cb->hdr.s = 1;
		goto set_ip_params;
	}

	if (unlikely(!pskb_may_pull(skb, pop * MPLS_HDR_LEN)))
		goto discard;

	while (pop-- > 0) {
		skb_pull(skb, MPLS_HDR_LEN);
		skb_reset_network_header(skb);

set_ip_params:
		if (!cb->hdr.s) {
			mplshdr = mpls_hdr(skb);
			mplshdr->ttl = cb->hdr.ttl;
			mplshdr->tc = cb->hdr.tc;
			mpls_peek_label(skb);
		} else {
			struct iphdr *iphdr;
			if (unlikely(pop || !pskb_may_pull(skb, sizeof(struct iphdr))))
				goto discard;

			iphdr = ip_hdr(skb);
			if (iphdr->version == 4) {
				skb->protocol = htons(ETH_P_IP);
				if (likely(propagate_ttl))
					set_ip_ttl(iphdr, cb->hdr.ttl);
				if (likely(propagate_tc))
					set_ip_dscp(skb, __tc_to_dscp(cb->hdr.tc));
			}
#if IS_ENABLED(CONFIG_IPV6)
			else if (iphdr->version == 6) {
				struct ipv6hdr *ipv6hdr;
				if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
					goto discard;

				ipv6hdr = ipv6_hdr(skb);
				skb->protocol = htons(ETH_P_IPV6);
				if (likely(propagate_ttl))
					ipv6hdr->hop_limit = cb->hdr.ttl;
				if (likely(propagate_tc))
					set_ip_dscp(skb, __tc_to_dscp(cb->hdr.tc));
			}
#endif
			else
				goto discard;
		}
	}

	return NET_XMIT_SUCCESS;

discard:
	return NET_XMIT_DROP;
}

static int mpls_swap(struct sk_buff *skb, const struct mpls_hdr *swap)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_hdr *mplshdr;
	__u32 label;

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC) ||
			!pskb_may_pull(skb, MPLS_HDR_LEN)))
		return NET_XMIT_DROP;

	label = mpls_hdr_label(swap);
	mpls_hdr_set_label(&cb->hdr, label);
	if (unlikely(swap->tc))
		cb->hdr.tc = swap->tc;

	mplshdr = mpls_hdr(skb);
	mpls_hdr_set_label(mplshdr, label);
	mplshdr->tc = cb->hdr.tc;
	mplshdr->ttl = cb->hdr.ttl;

	return NET_XMIT_SUCCESS;
}

static int mpls_push(struct sk_buff *skb, const struct mpls_hdr *push, int num_push)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);

	if (skb->protocol == htons(ETH_P_MPLS_UC))
		cb->hdr.s = 0;
	else {
		cb->hdr.s = 1;
		cb->hdr.ttl = get_ttl(skb);
		cb->hdr.tc = get_tc(skb);
		skb->protocol = htons(ETH_P_MPLS_UC);
	}

	for (; num_push; num_push--, push++) {
		skb_push(skb, MPLS_HDR_LEN);
		skb_reset_network_header(skb);

		mpls_hdr_set_label(&cb->hdr, mpls_hdr_label(push));
		if (unlikely(push->tc))
			cb->hdr.tc = push->tc;

		*mpls_hdr(skb) = cb->hdr;
		cb->hdr.s = 0;
	}

	return NET_XMIT_SUCCESS;
}

static int mpls_receive_local(struct sk_buff *skb, const struct net *net)
{
	int header_len = MPLS_HDR_LEN, ret;

	if (skb->protocol == htons(ETH_P_IP))
		header_len = sizeof(struct iphdr);
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6))
		header_len = sizeof(struct ipv6hdr);
#endif

	ret = mpls_prepare_skb(skb, header_len, __mpls_master_dev(net));
	if (unlikely(ret)) {
		MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
		dev_kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	netif_receive_skb(skb);

	return NET_XMIT_SUCCESS;
}

int mpls_send_mpls_ipv4(struct sock *sk, struct flowi4 *fl4)
{
	struct sk_buff *skb;
	struct nf_mpls *nf_mpls;
	struct iphdr *iph;
	u8 ttl;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		return 0;

	nf_mpls = skb->nf_mpls;
	BUG_ON(!nf_mpls);

	skb->dev = nf_mpls_dev(nf_mpls);

	iph = ip_hdr(skb);
	ttl = iph->ttl;
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

	if (unlikely(!__push_mpls_hdr_payload(skb)))
		goto err;

	set_mpls_ttl(skb, ttl);
	MPLSCB(skb)->hdr.ttl = ttl;

	return nhlfe_send(nf_mpls_nhlfe(nf_mpls), skb);
err:
	return -ENOBUFS;
}

static void send_frag_needed(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	if (unlikely(strip_mpls_headers(skb) != 0))
		return;

	nf_mpls_nhlfe(skb->nf_mpls) = nhlfe;
	nf_mpls_dev(skb->nf_mpls) = skb->dev;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		__icmp_ext_send(skb, ICMP_DEST_UNREACH,
				ICMP_FRAG_NEEDED, htonl(dst_mtu(skb_dst(skb))),
				skb->nf_mpls->hdr_len,
				ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS,
				nf_mpls_hdr_stack(skb->nf_mpls), mpls_send_mpls_ipv4);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		/* TODO */
		break;
#endif
	}
}

static bool __fragmentation_allowed(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	struct iphdr *iph;

	if (likely(skb->protocol == htons(ETH_P_MPLS_UC))) {
		struct mpls_hdr *hdr = mpls_hdr(skb);
		while (!hdr->s)
			hdr++;
		iph = (struct iphdr *)(++hdr);
	} else {
		iph = ip_hdr(skb);
	}

	switch (iph->version) {
	case 4:
		if (iph->frag_off & htons(IP_DF))
			return false;
		return true;
#if IS_ENABLED(CONFIG_IPV6)
	case 6:
		if (skb->len < IPV6_MIN_MTU || ipv6_has_fragment_hdr((struct ipv6hdr*) iph, skb))
			return false;
		return true;
#endif
	}

	return false;
}

netdev_tx_t nhlfe_send(const struct nhlfe *nhlfe, struct sk_buff *skb)
{
	int err = -ENOBUFS;
	int mpls_delta_headroom = (nhlfe->num_push - nhlfe->num_pop) * MPLS_HDR_LEN;
	unsigned int mpls_headroom = (mpls_delta_headroom > 0) ? mpls_delta_headroom : 0;
	struct dst_entry *dst = NULL;
	struct dst_entry *orig_dst = NULL; /* Needed for sending ICMP via dst_link_failure */
	struct net *net = (nhlfe->flags & MPLS_NH_GLOBAL) ? &init_net : dev_net(skb->dev);
	struct net *rcv_net = dev_net(skb->dev);
	const struct mpls_hdr *hdrs = nhlfe->data;
	int set_ttl = 1;

	/* Reset skb's nf fields, before obtaining dst!
	 * If we would reset it after obtaining dst,
	 * we would invalidate the nf_mpls member too!
	 */
	nf_reset(skb);

	if ((skb->protocol == htons(ETH_P_IP)
#if IS_ENABLED(CONFIG_IPV6)
		   || skb->protocol == htons(ETH_P_IPV6)
#endif
		   ) && skb_dst(skb)) {
		orig_dst = skb_dst(skb);
		dst_hold(orig_dst);
	}

	dst = nhlfe_get_nexthop_dst(nhlfe, net, skb);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto link_failure;
	}

	if (dst != NULL) {
		u32 mtu = dst_mtu(dst) - mpls_delta_headroom;

		/* We should detect loops only for MPLS devices */
		if (unlikely(dst->dev == skb->dev &&
				dst->dev->type == ARPHRD_MPLS)) {
			err = -ELOOP;
			dst_release(dst);
			goto link_failure;
		}

		if (likely(orig_dst))
			orig_dst->ops->update_pmtu(orig_dst, NULL, skb, mtu);

		skb_dst_drop(skb);
		skb_dst_set(skb, dst);

		if (unlikely(skb->len > mtu)) {
			if (!__fragmentation_allowed(skb, nhlfe)) {
				if (orig_dst) {
					skb_dst_drop(skb);
					skb_dst_set(skb, orig_dst);
					orig_dst = NULL;
					if (skb->protocol == htons(ETH_P_IP))
						icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
#if IS_ENABLED(CONFIG_IPV6)
					else if (skb->protocol == htons(ETH_P_IP))
						icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
#endif
				} else
					send_frag_needed(skb, nhlfe);

				goto free_skb;
			}
		}

		skb->dev = dst->dev;
		mpls_headroom += LL_RESERVED_SPACE(dst->dev);
	}

	if (nhlfe->has_swap || nhlfe->num_pop) {
		if (unlikely(skb_cow(skb, mpls_headroom) < 0))
			goto free_skb;
	} else {
		if (unlikely(skb_cow_head(skb, mpls_headroom) < 0))
			goto free_skb;
	}

	err = 0;

	if (nhlfe->num_pop) {
		err = mpls_pop(skb, nhlfe->num_pop);
		set_ttl = 0;
		if (unlikely(err))
			goto link_failure;
	}

	if (unlikely(nhlfe->flags & MPLS_SET_DSCP)) {
		err = set_ip_dscp(skb, nhlfe->dscp);
		if (unlikely(err))
			goto link_failure;
	}

#if IS_ENABLED(CONFIG_NET_SCHED)
	if (unlikely(nhlfe->flags & MPLS_SET_TC_INDEX))
		skb->tc_index = nhlfe->tc_index;
#endif

	if (nhlfe->has_swap) {
		err = mpls_swap(skb, hdrs);
		set_ttl = 0;
		if (unlikely(err))
			goto link_failure;
		hdrs++;
	}

	if (nhlfe->num_push) {
		err = mpls_push(skb, hdrs, nhlfe->num_push);
		set_ttl = 0;
		if (unlikely(err))
			goto link_failure;
	}

	if (nhlfe->net)
		rcv_net = nhlfe->net;

	if (unlikely(set_ttl))
		set_mpls_ttl(skb, MPLSCB(skb)->hdr.ttl);

	/* dst_release checks if orig_dst != NULL */
	dst_release(orig_dst);

	/* This functions cleanup after themselves */
	if (nhlfe->flags & MPLS_HAS_NH)
		err = mpls_send(skb, nhlfe);
	else
		err = mpls_receive_local(skb, rcv_net);

	return err;

link_failure:
	if (orig_dst) {
		skb_dst_drop(skb);
		skb_dst_set(skb, orig_dst);
		orig_dst = NULL;
		dst_link_failure(skb);
	}
free_skb:
	/* dst_release checks if orig_dst != NULL */
	dst_release(orig_dst);
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	dev_kfree_skb(skb);
	return err;
}

int __nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff *skb)
{
	const struct mpls_hdr *hdrs;
	int err = 0;

	if (unlikely(nhlfe == NULL))
		return 0;

	hdrs = nhlfe->data;

	if (nhlfe->num_pop) {
		err = nla_put_u8(skb, MPLSA_POP, nhlfe->num_pop);
		if (unlikely(err))
			goto out;
	}

	if (nhlfe->flags & MPLS_SET_DSCP) {
		err = nla_put_u8(skb, MPLSA_DSCP, nhlfe->dscp);
		if (unlikely(err))
			goto out;
	}

#if IS_ENABLED(CONFIG_NET_SCHED)
	if (nhlfe->flags & MPLS_SET_TC_INDEX) {
		err = nla_put_u16(skb, MPLSA_TC_INDEX, nhlfe->tc_index);
		if (unlikely(err))
			goto out;
	}
#endif

	if (nhlfe->has_swap) {
		err = nla_put(skb, MPLSA_SWAP, MPLS_HDR_LEN, hdrs);
		if (unlikely(err))
			goto out;
		hdrs++;
	}

	if (nhlfe->num_push) {
		err = nla_put(skb, MPLSA_PUSH, nhlfe->num_push * MPLS_HDR_LEN, hdrs);
		if (unlikely(err))
			goto out;
	}

	if (nhlfe->net) {
		const struct ilm_net *ilmn = net_generic(nhlfe->net, ilm_net_id);

		if (strlen(ilmn->name))
			err = nla_put_string(skb, MPLSA_NETNS_NAME, ilmn->name);
		else if (ilmn->pid)
			err = nla_put_u32(skb, MPLSA_NETNS_PID, ilmn->pid);
		else
			WARN_ON(1);

		if (unlikely(err))
			goto out;
	}

	if (nhlfe->flags & MPLS_HAS_NH) {
		/*
		 * sizeof sockaddr_in6 is larger then
		 * sizeof sockaddr. Hence use struct sockaddr_in6 as buffer.
		 */
		struct sockaddr_in6 addr = { };

		if (nhlfe->flags & MPLS_NH_GLOBAL) {
			err = nla_put_flag(skb, MPLSA_NEXTHOP_GLOBAL);
			if (unlikely(err))
				goto out;
		}

		if (nhlfe->ifindex) {
			if (nhlfe->flags & MPLS_NH_GLOBAL) {
				const struct net_device *dev;
				dev = dev_get_by_index_rcu(&init_net, nhlfe->ifindex);
				if (likely(dev))
					err = nla_put_string(skb, MPLSA_NEXTHOP_IFNAME, dev->name);
				else
					err = nla_put_string(skb, MPLSA_NEXTHOP_IFNAME, "(null)");
			} else
				err = nla_put_u32(skb, MPLSA_NEXTHOP_OIF, nhlfe->ifindex);

			if (unlikely(err))
				goto out;
		}

		addr.sin6_family = nhlfe->family;
		if (nhlfe->family == AF_INET)
			((struct sockaddr_in *)&addr)->sin_addr = nhlfe->nh.ipv4;
#if IS_ENABLED(CONFIG_IPV6)
		else if (nhlfe->family == AF_INET6)
			((struct sockaddr_in6 *)&addr)->sin6_addr = nhlfe->nh.ipv6;
#endif
		err = nla_put(skb, MPLSA_NEXTHOP_ADDR, sizeof(addr), &addr);
	}

out:
	return err;
}
