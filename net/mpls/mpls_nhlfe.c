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
	[MPLSA_TC_INDEX]	= { .type = NLA_U16, },
	[MPLSA_PUSH]		= { .type = NLA_BINARY, },
	[MPLSA_NEXTHOP_OIF]	= { .type = NLA_U32 },
	[MPLSA_NEXTHOP_ADDR]	= { .type = NLA_BINARY },
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

static inline
struct dst_entry *nhlfe_get_dst_ipv4(const struct nhlfe *nhlfe,
				     struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct sockaddr_in *sa;
 
	sa = (struct sockaddr_in *) nhlfe->nh;
	dst = (struct dst_entry *)ip_route_output(dev_net(skb->dev),
			sa->sin_addr.s_addr, 0, 0, nhlfe->ifindex);
	if (IS_ERR(dst))
		return NULL;

	if (skb) {
		struct mpls_skb_cb *cb = MPLSCB(skb);
		memcpy(cb->daddr, &sa->sin_addr.s_addr, sizeof(sa->sin_addr.s_addr));
	}

	return dst;
}

#if IS_ENABLED(CONFIG_IPV6)
static inline
struct dst_entry *nhlfe_get_dst_ipv6(const struct nhlfe *nhlfe,
				     struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct flowi6 fl6;
	struct sockaddr_in6 *sa;

	sa = (struct sockaddr_in6 *) nhlfe->nh;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = nhlfe->ifindex;
	fl6.daddr = sa->sin6_addr;

	dst = ip6_route_output(dev_net(skb->dev), NULL, &fl6);
	if (!dst || dst->error) {
		dst_release(dst);
		return NULL;
	}

	if (skb) {
		struct mpls_skb_cb *cb = MPLSCB(skb);
		memcpy(cb->daddr, &sa->sin6_addr, sizeof(sa->sin6_addr));
	}
	return dst;
}
#endif

bool __push_mpls_hdr_payload(struct sk_buff *skb, const struct mpls_hdr_payload *payload)
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

		if (unlikely(skb->len > dst_mtu(skb_dst(skb))))
			goto err;
		skb->protocol = htons(ETH_P_MPLS_UC);
		mpls_peek_label(skb);
	}
	memcpy(cb->daddr, payload->daddr, sizeof(payload->daddr));
	return true;
err:
	return false;
}

int strip_mpls_headers(struct sk_buff *skb, struct mpls_hdr_payload *payload)
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

static inline int mpls_finish_send(struct sk_buff *skb, const void *data)
{
	struct neighbour *neigh;
	u32 packet_length = skb->len;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

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
	return NET_XMIT_SUCCESS;

err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return NET_XMIT_DROP;

discard:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
	return NET_XMIT_DROP;
}

static int mpls_finish_send2(struct sk_buff *skb, const void *data)
{
	struct dst_entry *dst = skb_dst(skb);
	struct net *net = dev_net(dst->dev);

	if (unlikely(!__push_mpls_hdr_payload(skb, data))) {
		dev_kfree_skb(skb);
		MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
		return NET_XMIT_DROP;
	}
	MPLS_INC_STATS_BH(net, MPLS_MIB_IFOUTFRAGMENTEDPKTS);
	return mpls_finish_send(skb, data);
}

static int mpls_fragment_packet(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	u32 mtu;
	int ret;
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct mpls_hdr_payload buf;

	if (unlikely(nhlfe->nh == NULL))
		goto err;

	ret = strip_mpls_headers(skb, &buf);
	if (unlikely(ret))
		goto err;

	mtu = dst_mtu(skb_dst(skb)) - buf.data_len;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto err;

	if (skb->protocol == htons(ETH_P_IP)) {
		BUG_ON(ip_hdr(skb)->frag_off & htons(IP_DF));
		IPCB(skb)->frag_max_size = 0;
		return __ip_fragment(skb, &buf, mpls_finish_send2);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		BUG_ON(skb->len >= IPV6_MIN_MTU || !ipv6_has_fragment_hdr(ipv6_hdr(skb), skb));
		return __ip6_fragment(skb, &buf, mpls_finish_send2);
	}
#endif
err:
	dev_kfree_skb(skb);
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTERRORS);
	return NET_XMIT_DROP;
}

static inline int mpls_send(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	if (unlikely(skb->len > dst_mtu(skb_dst(skb))))
		return mpls_fragment_packet(skb, nhlfe);
	return mpls_finish_send(skb, NULL);
}

static struct nhlfe *
nhlfe_alloc(struct nlattr *data)
{
	struct nhlfe *nhlfe;

	nhlfe = kzalloc(sizeof(struct nhlfe) + nla_len(data), GFP_KERNEL);
	if (unlikely(nhlfe == NULL))
		return ERR_PTR(-ENOMEM);

	nhlfe->datalen = nla_len(data);
	memcpy(nhlfe->data, nla_data(data), nla_len(data));

	return nhlfe;
}

void __nhlfe_free(struct nhlfe *nhlfe)
{
	if (unlikely(nhlfe == NULL))
		return;

	WARN_ON(nhlfe->dead);
	nhlfe->dead = 1;

	if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
		kfree_rcu(nhlfe, rcu);
}


struct nhlfe * __nhlfe_build(struct nlattr *attr)
{
	struct nlattr *i;
	struct nhlfe *nhlfe;
	int remaining;
	int prev = MPLSA_UNSPEC;
	int has_swap = 0;

	nhlfe = nhlfe_alloc(attr);
	if (IS_ERR(nhlfe))
		return ERR_CAST(nhlfe);

	/* FIXME: check nla_len better, and wipe alignment bytes */

	nla_for_each_attr(i, nhlfe->data, nhlfe->datalen, remaining) {
		if (i->nla_type <= prev)
			goto err;

		prev = i->nla_type;
		switch (i->nla_type) {
		case MPLSA_POP:
			nhlfe->num_pop = nla_get_u8(i);
			break;
		case MPLSA_SWAP:
			has_swap = 1;
			break;
		case MPLSA_DSCP:
		case MPLSA_TC_INDEX:
			break;
		case MPLSA_PUSH:
			nhlfe->num_push = nla_len(i) / MPLS_HDR_LEN;
			break;
		case MPLSA_NEXTHOP_OIF:
			nhlfe->ifindex = nla_get_u32(i);
			break;
		case MPLSA_NEXTHOP_ADDR:
			nhlfe->nh = nla_data(i);
			if (nla_len(i) < sizeof(struct sockaddr))
				goto err;
			switch (nhlfe->nh->sa_family) {
			case AF_INET:
				if (nla_len(i) < sizeof(struct sockaddr_in))
					goto err;
				break;
#if IS_ENABLED(CONFIG_IPV6)
			case AF_INET6:
				if (nla_len(i) < sizeof(struct sockaddr_in6))
					goto err;
				break;
#endif
			default:
				goto err;
			}
			break;
		}
	}

	if (nhlfe->nh == NULL) {
		if (nhlfe->num_push || has_swap)
			goto err;
	}

	return nhlfe;
err:
	kfree(nhlfe);
	return ERR_PTR(-EINVAL);
}

struct dst_entry *nhlfe_get_nexthop_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb)
{
	if (nhlfe->nh == NULL)
		return NULL;

	switch (nhlfe->nh->sa_family) {
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
	struct net *net = dev_net(skb->dev);
	int propagate_ttl = mpls_propagate_ttl(net);
	int propagate_tc = mpls_propagate_tc(net);

	if (unlikely(skb->protocol != htons(ETH_P_MPLS_UC) ||
		     !pskb_may_pull(skb, pop * MPLS_HDR_LEN)))
		goto discard;

	while (pop-- > 0) {
		skb_pull(skb, MPLS_HDR_LEN);
		skb_reset_network_header(skb);

		if (!cb->hdr.s) {
			struct mpls_hdr *mplshdr = mpls_hdr(skb);
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

static int mpls_swap(struct sk_buff *skb, struct mpls_hdr *swap)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_hdr *mplshdr;
	__u32 label;

	if (skb->protocol != htons(ETH_P_MPLS_UC))
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

static int mpls_push(struct sk_buff *skb, struct mpls_hdr *push, int num_push)
{
	struct mpls_skb_cb *cb = MPLSCB(skb);

	if (skb->protocol == htons(ETH_P_MPLS_UC)) {
		cb->hdr.s = 0;
	} else {
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

static int mpls_receive_local(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	int header_len = MPLS_HDR_LEN, ret;

	if (skb->protocol == htons(ETH_P_IP))
		header_len = sizeof(struct iphdr);
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6))
		header_len = sizeof(struct ipv6hdr);
#endif

	ret = mpls_prepare_skb(skb, header_len, net->loopback_dev);
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
	struct mpls_hdr_payload buf;

	if (unlikely(strip_mpls_headers(skb, &buf) != 0))
		return;

	buf.nhlfe = nhlfe;
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		__icmp_ext_send(skb, ICMP_DEST_UNREACH,
				ICMP_FRAG_NEEDED, htonl(dst_mtu(skb_dst(skb))),
				buf.data_len,
				ICMP_EXT_MPLS_CLASS, ICMP_EXT_MPLS_IN_LS,
				&buf, mpls_send_mpls_ipv4);
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
		/* FIXME: ipv6_has_fragment_hdr does not know where the
		 * ip header really is since we have mpls stack pushed */
		if (skb->len < IPV6_MIN_MTU || ipv6_has_fragment_hdr((struct ipv6hdr*) iph, skb))
			return false;
		return true;
#endif
	}

	return false;
}

netdev_tx_t nhlfe_send(const struct nhlfe *nhlfe, struct sk_buff *skb)
{
	const struct nlattr *i;
	int remaining, err = -ENOBUFS;
	int mpls_delta_headroom = (nhlfe->num_push - nhlfe->num_pop) * MPLS_HDR_LEN;
	unsigned int mpls_headroom = (mpls_delta_headroom > 0) ? mpls_delta_headroom : 0;
	struct dst_entry *dst = NULL;

	/* FIXME: if doing swap or pop, we need to use skb_cow as we are
	 * rewriting the mpls entry which are not in headroom; should also
	 * take into account the LL_RESERVED_SPACE(dst->dev) */
	if (skb_cow_head(skb, mpls_headroom) < 0)
		goto free_skb;

	dst = nhlfe_get_nexthop_dst(nhlfe, dev_net(skb->dev), skb);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto free_skb;
	}

	if (dst != NULL) {
		u32 mtu = dst_mtu(dst) - mpls_delta_headroom;

		if (unlikely(dst->dev == skb->dev)) {
			err = -ELOOP;
			dst_release(dst);
			goto free_skb;
		}

		if (skb_dst(skb))
			skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

		nf_reset(skb);
		skb_dst_drop(skb);
		skb_dst_set(skb, dst);

		if (unlikely(skb->len > mtu)) {
			if (!__fragmentation_allowed(skb, nhlfe)) {
				send_frag_needed(skb, nhlfe);
				goto free_skb;
			}
		}

		skb->dev = dst->dev;
	}

	err = 0;
	nla_for_each_attr(i, nhlfe->data, nhlfe->datalen, remaining) {
		switch (i->nla_type) {
		case MPLSA_POP:
			err = mpls_pop(skb, nla_get_u8(i));
			break;
		case MPLSA_DSCP:
			err = set_ip_dscp(skb, nla_get_u8(i));
			break;
#if IS_ENABLED(CONFIG_NET_SCHED)
		case MPLSA_TC_INDEX:
			skb->tc_index = nla_get_u16(i);
			break;
#endif
		case MPLSA_SWAP:
			err = mpls_swap(skb, nla_data(i));
			break;
		case MPLSA_PUSH:
			err = mpls_push(skb, nla_data(i), nla_len(i) / MPLS_HDR_LEN);
			break;
		case MPLSA_NEXTHOP_OIF:
		case MPLSA_NEXTHOP_ADDR:
			break;
		default:
			err = -ENOSYS;
		}
		if (unlikely(err))
			goto free_skb;
	}

	if (nhlfe->nh == NULL)
		err = mpls_receive_local(skb);
	else
		err = mpls_send(skb, nhlfe);
	if (unlikely(err))
		goto free_skb;

	return 0;

free_skb:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	dev_kfree_skb(skb);
	return err;
}

bool __nhlfe_eq(struct nhlfe *lhs, struct nhlfe *rhs)
{
	if (rhs == lhs)
		return true;
	if (rhs == NULL || lhs == NULL)
		return false;
	if (rhs->datalen != lhs->datalen)
		return false;
	return memcmp(rhs->data, lhs->data, lhs->datalen) == 0;
}

int __nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff *skb)
{
	if (unlikely(nhlfe == NULL))
		return 0;

	return nla_put_nohdr(skb, nhlfe->datalen, nhlfe->data);
}
