/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *******************************************************************************/

#ifndef __NET_MPLS_MPLS_CMD_H__
#define __NET_MPLS_MPLS_CMD_H__

#include <net/xfrm.h>
#include <net/dsfield.h>
#include <net/route.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/dst.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/icmpv6.h>
#include <net/ip6_route.h>
#endif

struct __mpls_nh {
	struct rcu_head rcu;
	__u32 iface;
	union {
		struct sockaddr_in ipv4;
#if IS_ENABLED(CONFIG_IPV6)
		struct sockaddr_in6 ipv6;
#endif
	};
};

struct __push {
	struct rcu_head rcu;
	u8 no_push;
	u8 __pad[3];
	struct mpls_hdr push[];
};

enum {
	MPLS_SUCCESS = 0x0,
	MPLS_ERR = 0x1,
};

#define MPLS_LABEL_EXPLICIT_NULL_IPV4	0
#define MPLS_LABEL_ROUTER_ALERT		1
#define MPLS_LABEL_EXPLICIT_NULL_IPV6	2
#define MPLS_LABEL_IMPLICIT_NULL	3
#define MPLS_LABEL_MAX_RESERVED		15

static inline int mpls_is_reserved_label(u32 label)
{
	return label <= MPLS_LABEL_MAX_RESERVED;
}

#define MAX_HDR_ARRAY_SIZE (10 * MPLS_HDR_LEN)

struct mpls_hdr_payload {
	u8 data[MAX_HDR_ARRAY_SIZE]; /* data must be first */
	__be32 daddr[4];
	const struct nhlfe *nhlfe;
	u8 data_len;
};

#define rcu_dereference_ulong(ptr) rcu_dereference_index_check((ptr), rcu_read_lock_held())
#define rtnl_dereference_ulong(ptr) rcu_dereference_index_check((ptr), lockdep_rtnl_is_held())
#define rtnl_dereference_rcu_ulong(ptr) \
	rcu_dereference_index_check((ptr), rcu_read_lock_held() || lockdep_rtnl_is_held())

#define get_instruction(_nhlfe, index)												\
	(struct __instr *)((char *)(_nhlfe)->data +										\
			(index) * (sizeof(struct __instr)/sizeof(char)))

#define get_last_instruction(_nhlfe)												\
		(get_instruction((_nhlfe), (_nhlfe)->no_instr - 1))

#define get_first_instruction(_nhlfe)												\
		(get_instruction((_nhlfe), 0))

#define for_each_instr(_nhlfe, _mi, _cnt)											\
	for ((_mi) = ((struct __instr *)(_nhlfe)->data), (_cnt) = 0;					\
			(_cnt) < (_nhlfe)->no_instr; (_mi)++, ++(_cnt))

#define no_instrs(nhlfe) ((nhlfe) ? (nhlfe)->no_instr : 0)

#define MPLS_COMP_PROTOTYPE(name)									\
bool (name) (const struct __instr *lhs, const struct __instr *rhs)

#define MPLS_COMP_CMD(name) MPLS_COMP_PROTOTYPE(mpls_comp_##name)

#define MPLS_DOIT_PROTOTYPE(name)									\
int (name) (struct sk_buff *skb, const struct __instr *elem)

#define MPLS_DOIT_CMD(name) MPLS_DOIT_PROTOTYPE(mpls_##name)

#define MPLS_BUILD_PROTOTYPE(name)									\
int (name) (const struct nlattr *instr, struct __instr *elem, u8 *last_able, u8 *no_pop, u8 *no_push)

#define MPLS_BUILD_CMD(name) MPLS_BUILD_PROTOTYPE(mpls_build_##name)

#define MPLS_DUMP_PROTOTYPE(name)									\
int (name) (struct sk_buff *skb, const struct __instr *elem)

#define MPLS_DUMP_CMD(name) MPLS_DUMP_PROTOTYPE(mpls_dump_##name)

#define MPLS_CLEAN_PROTOTYPE(name) 									\
	void (name) (struct __instr *elem)

#define MPLS_CLEAN_CMD(name) MPLS_CLEAN_PROTOTYPE(mpls_clean_##name)

struct mpls_cmd {
	MPLS_COMP_PROTOTYPE(*compare);
	MPLS_BUILD_PROTOTYPE(*build);
	MPLS_DUMP_PROTOTYPE(*dump);
	MPLS_CLEAN_PROTOTYPE(*cleanup);
};

static inline int
mpls_prepare_skb(struct sk_buff *skb,
				unsigned int header_size,
				struct net_device *dev)
{
	secpath_reset(skb);
	skb->mac_header = skb->network_header;
	skb_reset_network_header(skb);

	if (!pskb_may_pull(skb, header_size))
		goto discard;

	skb->pkt_type = PACKET_HOST;
	__skb_tunnel_rx(skb, dev);
	return 0;

discard:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static inline void
set_ip_ttl(struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

#define __dscp_to_tc(_tos) ((_tos) >> 5)
#define __tc_to_dscp(_tc) ((_tc) << 5)

static inline u8
get_tc(struct sk_buff *skb)
{
	switch(skb->protocol) {
	case htons(ETH_P_IP):
	{
		struct iphdr *iphdr = ip_hdr(skb);
		return __dscp_to_tc(iphdr->tos);
	}
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
	{
		struct ipv6hdr *ipv6hdr = ipv6_hdr(skb);
		return __dscp_to_tc(ipv6_get_dsfield(ipv6hdr));

	}
#endif
	case htons(ETH_P_MPLS_UC):
	{
		struct mpls_hdr *mplshdr = mpls_hdr(skb);
		return mplshdr->tc;
	}
	default:
		return 0;
	}
}

static inline int
set_ip_dscp(struct sk_buff *skb, u8 tos)
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
	return MPLS_SUCCESS;

discard:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static inline u8
get_ttl(struct sk_buff *skb)
{
	switch(skb->protocol) {
	case htons(ETH_P_IP):
	{
		struct iphdr *iphdr = ip_hdr(skb);
		return iphdr->ttl;
	}
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
	{
		struct ipv6hdr *ipv6hdr = ipv6_hdr(skb);
		return ipv6hdr->hop_limit;
	}
#endif
	case htons(ETH_P_MPLS_UC):
	{
		struct mpls_hdr *mplshdr = mpls_hdr(skb);
		return mplshdr->ttl;
	}
	default:
		return sysctl_mpls_default_ttl;
	}
}

#if IS_ENABLED(CONFIG_IPV6)
static bool
ipv6_has_fragment_hdr(const struct sk_buff *skb)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;

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

static bool
__push_mpls_hdr_payload(struct sk_buff *skb, const struct mpls_hdr_payload *payload)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);

	if (payload->data_len) {
		if (unlikely(payload->data_len > MAX_HDR_ARRAY_SIZE)) {
			WARN_ON_ONCE(payload->data_len > MAX_HDR_ARRAY_SIZE);
			goto err;
		}

		skb_push(skb, payload->data_len);
		skb_reset_network_header(skb);
		memcpy(skb_network_header(skb), payload->data, payload->data_len);

		if (unlikely(skb->len > skb_dst(skb)->dev->mtu))
			goto err;

		skb->protocol = htons(ETH_P_MPLS_UC);
		label_entry_peek(skb);
	}
	memcpy(cb->daddr, payload->daddr, sizeof(payload->daddr));

	return true;
err:
	return false;
}

/* Array holding opcodes */
extern struct mpls_cmd mpls_cmd[];

/*
 * DOIT functions
 */
static __maybe_unused MPLS_DOIT_CMD(pop)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	int pop = elem->data;
	int propagate_ttl = mpls_propagate_ttl(dev_net(skb->dev));
	int propagate_tc = mpls_propagate_tc(dev_net(skb->dev));

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC) ||
			!pskb_may_pull(skb, pop * MPLS_HDR_LEN)))
		goto discard;

	while (pop-- > 0) {
		skb_pull(skb, MPLS_HDR_LEN);
		skb_reset_network_header(skb);

		if (!cb->hdr.s) {
			struct mpls_hdr *mplshdr;

			mplshdr = mpls_hdr(skb);

			mplshdr->ttl = cb->hdr.ttl;
			mplshdr->tc = cb->hdr.tc;

			label_entry_peek(skb);
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

	return MPLS_SUCCESS;

discard:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static inline MPLS_DOIT_CMD(tc_index)
{
#if IS_ENABLED(CONFIG_NET_SCHED)
	skb->tc_index = elem->data;
#endif
	return MPLS_SUCCESS;
}

static inline MPLS_DOIT_CMD(dscp)
{
	return set_ip_dscp(skb, elem->data);
}

static __maybe_unused MPLS_DOIT_CMD(swap)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_hdr *mplshdr;
	struct mpls_hdr *swap;

	if (skb->protocol != htons(ETH_P_MPLS_UC))
		goto discard;

	swap = (struct mpls_hdr *)&elem->data;

	if (unlikely(swap->tc))
		cb->hdr.tc = swap->tc;

	mplshdr = mpls_hdr(skb);
	mplshdr->label_l = cb->hdr.label_l = swap->label_l;
	mplshdr->label_u = cb->hdr.label_u = swap->label_u;
	mplshdr->tc = cb->hdr.tc;

	return MPLS_SUCCESS;

discard:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static __maybe_unused MPLS_DOIT_CMD(push)
{
	struct __push *__push =
			(struct __push *)rcu_dereference_ulong(elem->data);
	u8 no_push = __push->no_push;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_hdr *mplshdr;
	struct mpls_hdr *push;

	if (skb->protocol == htons(ETH_P_MPLS_UC))
		cb->hdr.s = 0;
	else {
		cb->hdr.s = 1;
		cb->hdr.ttl = get_ttl(skb);
		cb->hdr.tc = get_tc(skb);
		skb->protocol = htons(ETH_P_MPLS_UC);
	}

	push = __push->push;

	do {
		skb_push(skb, MPLS_HDR_LEN);
		skb_reset_network_header(skb);

		if (unlikely(push->tc))
			cb->hdr.tc = push->tc;

		mplshdr = mpls_hdr(skb);
		mplshdr->label_l = cb->hdr.label_l = push->label_l;
		mplshdr->label_u = cb->hdr.label_u = push->label_u;
		mplshdr->tc = cb->hdr.tc;
		mplshdr->s = cb->hdr.s;
		mplshdr->ttl = cb->hdr.ttl;

		cb->hdr.s = 0;
	} while (--no_push > 0 && ({push++; 1;}));

	return MPLS_SUCCESS;
}

static __maybe_unused MPLS_DOIT_CMD(peek)
{
	int header_len = MPLS_HDR_LEN;
	struct net *net = dev_net(skb->dev);
	u32 packet_length = skb->len;
	int ret;

	if (skb->protocol == htons(ETH_P_IP))
		header_len = sizeof(struct iphdr);

#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6))
		header_len = sizeof(struct ipv6hdr);
#endif

	ret = mpls_prepare_skb(skb, header_len, net->loopback_dev);
	if (unlikely(ret))
		goto discard;

	skb_dst_drop(skb);
	netif_receive_skb(skb);

	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTPACKETS);
	MPLS_ADD_STATS_BH(net, MPLS_MIB_OUTOCTETS, packet_length);
	return MPLS_SUCCESS;

discard:
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static inline void
__mpls_set_dst(struct sk_buff *skb, struct dst_entry *dst)
{
	skb_dst_drop(skb);
	skb_dst_set(skb, dst);
	nf_reset(skb);
}

static inline struct dst_entry *
mpls_get_dst_ipv4(struct sk_buff *skb, const struct __instr *elem)
{
	struct dst_entry *dst;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct __mpls_nh *nh =
			(struct __mpls_nh *)rcu_dereference_ulong(elem->data);

	dst = (struct dst_entry *)ip_route_output(dev_net(skb->dev),
			nh->ipv4.sin_addr.s_addr, 0, 0, nh->iface);

	if (IS_ERR(dst))
		goto err;

	memcpy(cb->daddr, &nh->ipv4.sin_addr.s_addr, sizeof(nh->ipv4.sin_addr.s_addr));
	return dst;
err:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTERRORS);
	return NULL;
}

static inline struct dst_entry *
mpls_get_dst_ipv6(struct sk_buff *skb, const struct __instr *elem)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct dst_entry *dst;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct __mpls_nh *nh =
			(struct __mpls_nh *)rcu_dereference_ulong(elem->data);
	struct flowi6 fl6;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = nh->iface;
	fl6.daddr = nh->ipv6.sin6_addr;

	dst = ip6_route_output(dev_net(skb->dev), NULL, &fl6);
	if (!dst || dst->error)
		goto err;

	memcpy(cb->daddr, &nh->ipv6.sin6_addr, sizeof(nh->ipv6.sin6_addr));

	return dst;
err:
	dst_release(dst);
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTERRORS);
	return NULL;
#else
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	return NULL;
#endif
}

static int
mpls_update_pmtu(struct sk_buff *skb, const struct __instr *mi, u32 mtu)
{
	struct dst_entry *dst = skb_dst(skb);
	if (dst->ops->protocol == htons(ETH_P_IP)) {
		struct __mpls_nh *nh =
			(struct __mpls_nh *)rcu_dereference_ulong(mi->data);
		struct flowi4 fl4 = {
			.flowi4_oif = nh->iface,
			.flowi4_tos = 0,
			.daddr = nh->ipv4.sin_addr.s_addr,
			.saddr = 0,
		};
		__ip_rt_update_pmtu((struct rtable *)dst, &fl4, mtu);
		if (!dst_check(dst, 0))
			__mpls_set_dst(skb, mpls_get_dst_ipv4(skb, mi));
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (dst->ops->protocol == htons(ETH_P_IPV6)) {
		dst->ops->update_pmtu(dst, NULL, skb, mtu);
		if (!dst_check(dst, 0))
			__mpls_set_dst(skb, mpls_get_dst_ipv6(skb, mi));
	}
#endif
	else
		goto err;

	if (unlikely(!skb_dst(skb)))
		goto err;

	return 0;
err:
	return -EINVAL;
}

static int
strip_mpls_headers(struct sk_buff *skb, struct mpls_hdr_payload *payload)
{
	struct mpls_hdr *hdr = mpls_hdr(skb);
	struct iphdr *iph;
	struct mpls_skb_cb *cb = MPLSCB(skb);

	memcpy(payload->daddr, cb->daddr, sizeof(cb->daddr));

	if (skb->protocol == htons(ETH_P_IP)
#if IS_ENABLED(CONFIG_IPV6)
		|| skb->protocol == htons(ETH_P_IPV6)
#endif
		) {
		payload->data_len = 0;
		goto found_ip;
	}

	if (skb->protocol != htons(ETH_P_MPLS_UC))
		goto err;

	payload->data_len = MPLS_HDR_LEN;
	while (!hdr->s) {
		if (unlikely(!pskb_may_pull(skb, payload->data_len)))
			goto err;
		payload->data_len += MPLS_HDR_LEN;
		hdr++;
	}

	if (unlikely(payload->data_len > MAX_HDR_ARRAY_SIZE))
		goto err;

	memcpy(payload->data, mpls_hdr(skb), payload->data_len);

	skb_pull(skb, payload->data_len);
	skb_reset_network_header(skb);

	iph = ip_hdr(skb);

	if (iph->version == 4)
		skb->protocol = htons(ETH_P_IP);
	else if (iph->version == 6)
		skb->protocol = htons(ETH_P_IPV6);
	else
		goto err;

found_ip:
	return 0;

err:
	return -EINVAL;
}

static inline int
mpls_finish_send(struct sk_buff *skb, const void *data)
{
	struct neighbour *neigh;
	u32 packet_length = skb->len;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

	if (unlikely(data)) {
		if (unlikely(!__push_mpls_hdr_payload(skb, data)))
			goto err;
		MPLS_INC_STATS_BH(net, MPLS_MIB_IFOUTFRAGMENTEDPKTS);
	}

	skb->dev = dst->dev;

	if (unlikely(skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev)) < 0))
		goto discard;

	neigh = dst_neigh_lookup(dst, cb->daddr);
	if (unlikely(!neigh))
		goto err;

	__dst_neigh_output(dst, neigh, skb,
			   (skb->protocol == htons(ETH_P_MPLS_UC)) ?
			   &neigh->hh_mpls : &neigh->hh);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTPACKETS);
	MPLS_ADD_STATS_BH(net, MPLS_MIB_OUTOCTETS, packet_length);
	neigh_release(neigh);
	return MPLS_SUCCESS;
err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return -MPLS_ERR;

discard:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
	return -MPLS_ERR;
}

static inline int
mpls_fragment_packet(struct sk_buff *skb, const struct __instr *mi)
{
	u32 mtu;
	int ret;
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct mpls_hdr_payload buf;

	if (unlikely(!mi))
		goto err;

	ret = strip_mpls_headers(skb, &buf);
	if (unlikely(ret))
		goto err;

	mtu = skb_dst(skb)->dev->mtu - buf.data_len;
	ret = mpls_update_pmtu(skb, mi, mtu);
	if (unlikely(ret))
		goto err;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto err;

	if (skb->protocol == htons(ETH_P_IP)) {
		BUG_ON(ip_hdr(skb)->frag_off & htons(IP_DF));
		return __ip_fragment(skb, &buf, mpls_finish_send);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		BUG_ON(skb->len >= IPV6_MIN_MTU || !ipv6_has_fragment_hdr(skb));
		return __ip6_fragment(skb, &buf, mpls_finish_send);
	}
#endif

err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return -MPLS_ERR;
}

static inline int
mpls_send(struct sk_buff *skb, const struct __instr *mi)
{
	if (unlikely(skb->len > skb_dst(skb)->dev->mtu))
		return mpls_fragment_packet(skb, mi);

	return mpls_finish_send(skb, NULL);
}

#endif /* __NET_MPLS_MPLS_CMD_H__ */
