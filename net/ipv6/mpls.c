/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 2012        Igor Maravic     <igorm@etf.rs>
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/err.h>
#include <linux/export.h>
#include <net/dst.h>
#include <net/dsfield.h>
#include <linux/icmpv6.h>
#include <net/mpls.h>
#include <net/flow.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>

static struct dst_entry *get_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct flowi6 fl6 = {
		.flowi6_oif = nhlfe->dev ? nhlfe->dev->ifindex : 0,
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

static bool frag_allowed(const struct sk_buff *skb, const void *hdr)
{
	if (skb->len < IPV6_MIN_MTU || ipv6_has_fragment_hdr((struct ipv6hdr*) hdr, skb))
		return false;
	return true;
}

static int set_nh_addr(struct nhlfe *nhlfe, const struct sockaddr *addr, int len)
{
	if (len < sizeof(struct sockaddr_in6))
		return -EINVAL;
	nhlfe->nh.ipv6 = ((struct sockaddr_in6 *)addr)->sin6_addr;
	if (ipv6_addr_any(&nhlfe->nh.ipv6))
		return -EINVAL;
	return 0;
}

static void put_nh_addr(struct sockaddr *addr, const struct nhlfe *nhlfe)
{
	((struct sockaddr_in6 *)addr)->sin6_addr = nhlfe->nh.ipv6;
}

static int set_dscp(struct sk_buff *skb, u8 tos)
{
	struct ipv6hdr *ipv6hdr;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
		return -ENOBUFS;
	ipv6hdr = ipv6_hdr(skb);
	ipv6_change_dsfield(ipv6hdr, (u8)~IPTOS_PREC_MASK, IPTOS_PREC(tos));
	return 0;
}

static u8 get_tos(const struct sk_buff *skb)
{
	return __dscp_to_tc(ipv6_get_dsfield(ipv6_hdr(skb)));
}

static void set_ttl(void *hdr, u8 ttl)
{
	struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)hdr;
	ipv6hdr->hop_limit = ttl;
}

static u8 get_ttl(const struct sk_buff *skb)
{
	return ipv6_hdr(skb)->hop_limit;
}

static void icmp_pkt2big_send(struct sk_buff *skb, __u32 info)
{
	icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, info);
}

static const struct mpls_afinfo mpls_ipv6_afinfo __read_mostly = {
	.family = AF_INET6,
	.header_len = sizeof(struct ipv6hdr),
	.get_route = get_dst,
	.frag_allowed = frag_allowed,
	.fragment = ip_fragment,
	.set_nh_addr = set_nh_addr,
	.put_nh_addr = put_nh_addr,
	.set_dscp = set_dscp,
	.get_tos = get_tos,
	.set_ttl = set_ttl,
	.get_ttl = get_ttl,
	.icmp_pkt2big_send = icmp_pkt2big_send,
	.icmp_ext_send = NULL, /* UNIMPLEMENTED */
};

int __init mpls_ipv6_init(void)
{
	int ret = mpls_register_afinfo(&mpls_ipv6_afinfo);

	if (unlikely(ret))
		pr_crit("%s: Cannot init mpls ipv6 extension\n", __func__);

	return ret;
}

void __exit mpls_ipv6_exit(void)
{
	mpls_unregister_afinfo(&mpls_ipv6_afinfo);
}

