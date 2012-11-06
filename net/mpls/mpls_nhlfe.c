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
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <net/dst.h>
#include <net/ip_fib.h>
#include <net/net_namespace.h>
#include <net/mpls.h>
#include "mpls_cmd.h"

struct nla_policy __nhlfe_policy[__MPLS_ATTR_MAX] __read_mostly = {
	[MPLSA_DSCP]		= { .type = NLA_U8 },
#if IS_ENABLED(CONFIG_NET_SCHED)
	[MPLSA_TC_INDEX]	= { .type = NLA_U16 },
#else
	[MPLSA_TC_INDEX]	= { .type = NLA_PROHIBIT },
#endif
	[MPLSA_PUSH]		= { .type = NLA_BINARY, },
	[MPLSA_NEXTHOP_OIF]	= { .type = NLA_U32 },
	[MPLSA_NEXTHOP_ADDR]	= { .type = NLA_BINARY },
	[MPLSA_POP]		= { .type = NLA_PROHIBIT },
	[MPLSA_SWAP]		= { .type = NLA_PROHIBIT },
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

static inline u8 get_ip_tc(struct sk_buff *skb)
{
	return get_tos_p(skb->protocol, skb);
}

static inline int set_ip_dscp(struct sk_buff *skb, u8 tos)
{
	if (unlikely(set_dscp_p(skb->protocol, skb, tos)))
		goto discard;
	return NET_XMIT_SUCCESS;

discard:
	return NET_XMIT_DROP;
}

static inline u8 get_ip_ttl(const struct sk_buff *skb)
{
	return get_ttl_p(skb->protocol, skb);
}

int strip_mpls_headers(struct sk_buff *skb)
{
	struct mpls_hdr *hdr = mpls_hdr(skb);
	struct iphdr *iph;
	u16 data_len;
	struct nf_mpls *nf_mpls;

	if (mpls_get_afinfo(mpls_proto_to_family(skb->protocol))) {
		data_len = 0;
		goto found_ip;
	}

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC)))
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

static inline int mpls_finish_send2(struct sk_buff *skb)
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

int __mpls_finish_send(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

	if (unlikely(!push_mpls_hdr_payload(skb))) {
		dev_kfree_skb(skb);
		MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
		return NET_XMIT_DROP;
	}
	MPLS_INC_STATS_BH(net, MPLS_MIB_IFOUTFRAGMENTEDPKTS);
	return mpls_finish_send2(skb);
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

	ret = fragment_p(skb->protocol, skb, __mpls_finish_send);
	if (unlikely(ret == -EPIPE))
		goto err;

	return ret;

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
	return mpls_finish_send2(skb);
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

	if (nhlfe->dev)
		dev_put(nhlfe->dev);

	if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
		kfree_rcu(nhlfe, rcu);
}

void __nhlfe_free(struct nhlfe *nhlfe)
{
	if (unlikely(nhlfe == NULL))
		return;

	WARN_ON(nhlfe->dead);
	nhlfe->dead = 1;

	if (nhlfe->dev)
		dev_put(nhlfe->dev);

	if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
		kfree(nhlfe);
	else
		WARN_ON(1);
}


struct nhlfe * __nhlfe_build(const struct net *net, struct nlattr *attr,
				const struct nla_policy *policy, struct nlattr *tb[])
{
	struct nhlfe *nhlfe;
	struct nlattr *data[MPLS_ATTR_MAX + 1];
	int num_push = 0, has_swap = 0;
	struct mpls_hdr *hdrs;
	int error;

	/* Check if MPLS master dev is up and MPLS enabled */
	error = __mpls_master_dev_state(net);
	if (unlikely(error))
		return ERR_PTR(error);

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

	/* We need rcu_read_lock because we use
	 * pointers to protocol functions, which are
	 * protected with mutex/rcu lock
	 */
	rcu_read_lock();
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

	if (tb[MPLSA_NEXTHOP_ADDR]) {
		struct sockaddr *addr = nla_data(tb[MPLSA_NEXTHOP_ADDR]);

		nhlfe->flags |= MPLS_HAS_NH;

		nhlfe->family = addr->sa_family;
		error = set_nh_addr_af(addr->sa_family, nhlfe, addr, nla_len(tb[MPLSA_NEXTHOP_ADDR]));
		if (unlikely(error))
			goto err;

		error = -EINVAL;
	}

	if (tb[MPLSA_NEXTHOP_OIF]) {
		if (nhlfe->dev || !(nhlfe->flags & MPLS_HAS_NH))
			goto err;

		/* Cast away const from net */
		nhlfe->dev = __dev_get_by_index((struct net *)net, nla_get_u32(tb[MPLSA_NEXTHOP_OIF]));
		if (!nhlfe->dev) {
			error = -ENODEV;
			goto err;
		}
	}

	if (!(nhlfe->flags & MPLS_HAS_NH)) {
		/* Sanity check */
		if (nhlfe->num_push || nhlfe->has_swap || !nhlfe->num_pop)
			goto err;
	} else {
		/* Check if route is reachable */
		struct dst_entry *dst;
		dst = nhlfe_get_nexthop_dst(nhlfe, (struct net *)net, NULL);
		if (IS_ERR(dst)) {
			error = PTR_ERR(dst);
			goto err;
		}
		dst_release(dst);
	}

	if (nhlfe->dev) {
		if (!(nhlfe->dev->flags & IFF_UP)) {
			error = -ENETDOWN;
			goto err;
		}
		if (!(nhlfe->dev->flags & IFF_MPLS)) {
			error = -EPFNOSUPPORT;
			goto err;
		}
		dev_hold(nhlfe->dev);
	}

	rcu_read_unlock();
	return nhlfe;
err:
	rcu_read_unlock();
	kfree(nhlfe);
	return ERR_PTR(error);
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
			u16 af = MPLSPROTO_UNSPEC;
			if (unlikely(pop || !pskb_may_pull(skb, sizeof(struct iphdr))))
				goto discard;

			iphdr = ip_hdr(skb);
			if (iphdr->version == 4) {
				skb->protocol = htons(ETH_P_IP);
				af = MPLSPROTO_IPV4;
			}
			else if (iphdr->version == 6) {
				if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
					goto discard;

				skb->protocol = htons(ETH_P_IPV6);
				af = MPLSPROTO_IPV6;
			}
			if (likely(propagate_ttl))
				set_ttl_af(af, iphdr, cb->hdr.ttl);
			if (likely(propagate_tc))
				set_dscp_af(af, skb, __tc_to_dscp(cb->hdr.tc));
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
		cb->hdr.ttl = get_ip_ttl(skb);
		cb->hdr.tc = get_ip_tc(skb);
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
	int ret;

	ret = mpls_prepare_skb(skb, get_hdr_len_p(skb->protocol), __mpls_master_dev(net));
	if (unlikely(ret)) {
		MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
		dev_kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	netif_receive_skb(skb);

	return NET_XMIT_SUCCESS;
}

static void send_frag_needed(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	if (unlikely(strip_mpls_headers(skb) != 0))
		return;

	nf_mpls_nhlfe(skb->nf_mpls) = nhlfe;
	nf_mpls_dev(skb->nf_mpls) = skb->dev;

	icmp_ext_send_p(skb->protocol, skb, ICMP_DEST_UNREACH,
			ICMP_FRAG_NEEDED, htonl(dst_mtu(skb_dst(skb))),
			skb->nf_mpls->hdr_len,
			ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS,
			nf_mpls_hdr_stack(skb->nf_mpls));
}

static bool __fragmentation_allowed(const struct sk_buff *skb)
{
	struct iphdr *iph;
	u16 af = MPLSPROTO_UNSPEC;

	if (likely(skb->protocol == htons(ETH_P_MPLS_UC))) {
		struct mpls_hdr *hdr = mpls_hdr(skb);
		while (!hdr->s)
			hdr++;
		iph = (struct iphdr *)(++hdr);
	} else
		iph = ip_hdr(skb);

	switch (iph->version) {
	case 4:
		af = MPLSPROTO_IPV4;
		break;
	case 6:
		af = MPLSPROTO_IPV6;
		break;
	}
	return frag_allowed_af(af, skb, iph);
}

netdev_tx_t __nhlfe_send(const struct nhlfe *nhlfe, struct sk_buff *skb)
{
	int err = -ENOBUFS;
	int mpls_delta_headroom = (nhlfe->num_push - nhlfe->num_pop) * MPLS_HDR_LEN;
	unsigned int mpls_headroom = (mpls_delta_headroom > 0) ? mpls_delta_headroom : 0;
	struct dst_entry *dst = NULL;
	struct dst_entry *orig_dst = NULL; /* Needed for sending ICMP via dst_link_failure */
	struct net *net = dev_net(skb->dev);
	const struct mpls_hdr *hdrs = nhlfe->data;
	int set_ttl = 1;

	/* Reset skb's nf fields, before obtaining dst!
	 * If we would reset it after obtaining dst,
	 * we would invalidate the nf_mpls member too!
	 */
	nf_reset(skb);

	if (mpls_get_afinfo(mpls_proto_to_family(skb->protocol)) && skb_dst(skb)) {
		orig_dst = skb_dst(skb);
		dst_hold(orig_dst);
	}

	dst = nhlfe_get_nexthop_dst(nhlfe, dev_net(skb->dev), skb);
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
			if (!__fragmentation_allowed(skb)) {
				if (likely(orig_dst)) {
					skb_dst_drop(skb);
					skb_dst_set(skb, orig_dst);
					orig_dst = NULL;
					icmp_pkt2big_send_p(skb->protocol, skb, htonl(mtu));
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
	} else if (unlikely(skb_cow_head(skb, mpls_headroom) < 0))
		goto free_skb;

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

	if (unlikely(set_ttl))
		set_mpls_ttl(skb, MPLSCB(skb)->hdr.ttl);

	/* dst_release checks if orig_dst != NULL */
	dst_release(orig_dst);

	/* This functions cleanup after themselves */
	if (nhlfe->flags & MPLS_HAS_NH)
		err = mpls_send(skb, nhlfe);
	else
		err = mpls_receive_local(skb, net);

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

	/* We need rcu_read_lock because we use
	 * pointers to protocol functions, which are
	 * protected with mutex/rcu lock
	 */
	rcu_read_lock();
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

	if (nhlfe->flags & MPLS_HAS_NH) {
		/*
		 * sizeof sockaddr_in6 is larger then
		 * sizeof sockaddr. Hence use struct sockaddr_in6 as buffer.
		 */
		struct sockaddr_in6 addr = { };

		if (nhlfe->dev) {
			err = nla_put_u32(skb, MPLSA_NEXTHOP_OIF, nhlfe->dev->ifindex);
			if (unlikely(err))
				goto out;
		}

		addr.sin6_family = nhlfe->family;
		put_nh_addr_af(nhlfe->family, (struct sockaddr *)&addr, nhlfe);

		err = nla_put(skb, MPLSA_NEXTHOP_ADDR, sizeof(addr), &addr);
	}

out:
	rcu_read_unlock();
	return err;
}
