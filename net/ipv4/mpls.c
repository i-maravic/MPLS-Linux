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
#include <net/icmp.h>
#include <net/mpls.h>
#include <net/flow.h>
#include <net/route.h>

static int mpls_send_mpls_ipv4(struct sock *sk, struct flowi4 *fl4)
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

	if (unlikely(!push_mpls_hdr_payload(skb)))
		goto err;

	set_mpls_ttl(skb, ttl);
	MPLSCB(skb)->hdr.ttl = ttl;

	return nhlfe_send(nf_mpls_nhlfe(nf_mpls), skb);
err:
	return -ENOBUFS;
}

static struct dst_entry *get_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct flowi4 fl4 = {
		.flowi4_oif = nhlfe->dev ? nhlfe->dev->ifindex : 0,
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


static bool frag_allowed(const struct sk_buff *skb, const void *hdr)
{
	struct iphdr *iph = (struct iphdr *)hdr;
	if (iph->frag_off & htons(IP_DF))
		return false;
	return true;
}

static int set_nh_addr(struct nhlfe *nhlfe, const struct sockaddr *addr, int len)
{
	if (len < sizeof(struct sockaddr_in))
		return -EINVAL;
	nhlfe->nh.ipv4 = ((struct sockaddr_in *)addr)->sin_addr;
	if (nhlfe->nh.ipv4.s_addr == 0)
		return -EINVAL;
	return 0;
}

static void put_nh_addr(struct sockaddr *addr, const struct nhlfe *nhlfe)
{
	((struct sockaddr_in *)addr)->sin_addr = nhlfe->nh.ipv4;
}

static int set_dscp(struct sk_buff *skb, u8 tos)
{
	struct iphdr *iphdr;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		return -ENOBUFS;
	iphdr = ip_hdr(skb);
	ipv4_change_dsfield(iphdr, (u8)~IPTOS_PREC_MASK, IPTOS_PREC(tos));
	return 0;
}

static u8 get_tos(const struct sk_buff *skb)
{
	return __dscp_to_tc(ip_hdr(skb)->tos);
}

static void set_ttl(void *hdr, u8 ttl)
{
	struct iphdr *ip_hdr = (struct iphdr *)hdr;
	csum_replace2(&ip_hdr->check, htons(ip_hdr->ttl << 8), htons(ttl << 8));
	ip_hdr->ttl = ttl;
}

static u8 get_ttl(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ttl;
}

static void icmp_pkt2big_send(struct sk_buff *skb, __u32 info)
{
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, info);
}

static void icmp_ext_send(struct sk_buff *skb_in, int type, int code, __be32 info,
				u16 ext_length, u8 ext_class, u8 ext_c_type, void *ext_data)
{
	__icmp_ext_send(skb_in, type, code, info, ext_length, ext_class,
			ext_c_type, ext_data, mpls_send_mpls_ipv4);
}

static const struct mpls_afinfo mpls_ipv4_afinfo __read_mostly = {
	.family = AF_INET,
	.header_len = sizeof(struct iphdr),
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
	.icmp_ext_send = icmp_ext_send,
};

void __init mpls_init(void)
{
	if (mpls_register_afinfo(&mpls_ipv4_afinfo))
		pr_crit("%s: Cannot init mpls ipv4 extension\n", __func__);
}
