/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls4.c:
 *      - IPv4 MPLS protocol driver.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 ****************************************************************************/

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <net/dsfield.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/mpls.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/arp.h>

MODULE_LICENSE("GPL");

static inline void mpls4_cache_flush(struct net *net)
{
	MPLS_ENTER;
	rt_cache_flush(net, -1);
	MPLS_EXIT;
}

static inline void mpls4_set_ttl(struct sk_buff *skb, int ttl)
{
	MPLS_ENTER;
	ip_hdr(skb)->ttl = ttl;
	ip_send_check(ip_hdr(skb));
	MPLS_EXIT;
}

static inline int mpls4_get_ttl(struct sk_buff *skb)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return ip_hdr(skb)->ttl;
}

static inline void mpls4_change_dsfield(struct sk_buff *skb, int ds)
{
	MPLS_ENTER;
	MPLS_EXIT;
	ipv4_change_dsfield(ip_hdr(skb), 0x3, ds << 2);
}

static inline int mpls4_get_dsfield(struct sk_buff *skb)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return ipv4_get_dsfield(ip_hdr(skb)) >> 2;
}

struct mpls_icmp_common {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    res1:4, version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    version:4, res1:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8	res2;
	__u16	check;
};

struct mpls_icmp_object {
	__u16	length;
	__u8	class;
	__u8	type;
};

/* we can probably used a modified ip_append_data to build this */
//should be fixed
static struct sk_buff *mpls4_build_icmp(struct sk_buff *skb, int type, unsigned int icmp_data,	int mpls)
{
	unsigned char buf[576]; /* JBO: too much use on stack? */

	struct icmphdr *icmph;
	struct sk_buff *nskb;
	unsigned char *data;
	struct rtable *rt;
	struct iphdr *iph;

	unsigned int icmp_start = 0;
	unsigned int len = 0;
	unsigned int real;
	unsigned int max;
	unsigned int height;
	int pull;
	MPLS_ENTER;
	/* find the distance to the bottom of the MPLS stack */
	pull = mpls_find_payload(skb);
	if (pull < 0)
		goto error_0;

	if (!skb_pull(skb, pull))
		goto error_0;

	height = skb->data - MPLSCB(skb)->top_of_stack;

	/* now where at the payload, for now we're
	 * assuming this is IPv4
	 */
	skb_reset_network_header(skb);

	/* build a new skb, that will be big enough to hold
	 * a maximum of 576 bytes (RFC792)
	 */
	if ((skb->len + skb_tailroom(skb)) < 576) {
		nskb = skb_copy_expand(skb, skb_headroom(skb),
			(576 + 16) - skb->len, GFP_ATOMIC);
	} else {
		nskb = skb_copy(skb, GFP_ATOMIC);
	}

	if (!nskb)
		goto error_0;

	/* I don't handle IP options */
	if (ip_hdr(nskb)->ihl > 5) {
		printk(KERN_ERR "IP options!!!!\n");
		goto error_1;
	}

	memset(buf, 0, sizeof(buf));

	/* point to the buf, we'll build our ICMP message there
	 * then copy to nskb when we're done
	 */
	iph = (struct iphdr*)&buf[len];
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = ip_hdr(nskb)->tos;
	iph->tot_len = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = sysctl_mpls_default_ttl;
	iph->protocol = IPPROTO_ICMP;
	iph->check = 0;
	iph->saddr = ip_hdr(nskb)->daddr;
	iph->daddr = ip_hdr(nskb)->saddr;
	len += sizeof(struct iphdr);

	icmp_start = len;
	icmph = (struct icmphdr*)&buf[len];
	icmph->checksum = 0;
	icmph->un.gateway = icmp_data;

	switch (type) {
	case ICMP_TIME_EXCEEDED:
		icmph->type = ICMP_TIME_EXCEEDED;
		icmph->code = ICMP_EXC_TTL;
		break;
	case ICMP_DEST_UNREACH:
		icmph->type = ICMP_DEST_UNREACH;
		icmph->code = ICMP_FRAG_NEEDED;
		break;
	default:
		BUG_ON(1);
		break;
	}
	len += sizeof(struct icmphdr);

	data = &buf[len];
	if (mpls)
		max = 128;
	else
		max = 576 - len;
	//ako je ovo ovakvo ovde ,koja je poenta upsivanja svih onih podataka iznad?
	real = (nskb->len > max) ? max : skb->len;
	memcpy(data, nskb->data, real);

	if (!mpls) {
		len += real;
	} else {
		struct mpls_icmp_common *common;
		struct mpls_icmp_object *object;
		unsigned char *mpls_data = NULL;
		unsigned int obj_start = 0;
		unsigned int mpls_start = 0;

		len += 128;

		mpls_start = len;
		common = (struct mpls_icmp_common*)&buf[len];
		common->version = 2;
		common->res1 = 0;
		common->res2 = 0;
		common->check = 0;
		len += sizeof(struct mpls_icmp_common);

		obj_start = len;
		object = (struct mpls_icmp_object*)&buf[len];
		object->length = 0;
		object->class = 1;
		object->type = 1;
		len += sizeof(struct mpls_icmp_object);

		mpls_data = &buf[len];
		memcpy(mpls_data, MPLSCB(skb)->top_of_stack, height);
		len += height;

		object->length = htons(len - obj_start);
		common->check = csum_fold (csum_partial ((char*)common,
				len - mpls_start, 0));
	}

	iph->tot_len = htons(len);
	ip_send_check(iph);
	icmph->checksum = csum_fold (csum_partial ((char*)icmph,
			len - icmp_start, 0));
	//TODO check this
	kfree_skb(nskb);
	nskb = alloc_skb(len, GFP_ATOMIC);
	memcpy(skb_put(nskb,len),buf, len);
	/*
	nskb->len = len;
	memcpy(nskb->data, buf, nskb->len);
	nskb->tail = nskb->data + nskb->len;
	*/
	nskb->ip_summed = CHECKSUM_NONE;
	nskb->csum = 0;

	{
		struct flowi4 fl4 = {
			.daddr = iph->daddr,
			.saddr = iph->saddr,
			.flowi4_tos = RT_TOS(iph->tos),
			.flowi4_proto = IPPROTO_ICMP,
		};

		rt = ip_route_output_key(&init_net, &fl4);
		if (IS_ERR(rt))
			goto error_1;
	}

	skb_dst_drop(nskb);

	skb_dst_set(nskb, &rt->dst);
	MPLS_EXIT;
	return nskb;

error_1:
	kfree_skb(nskb);
error_0:
	MPLS_EXIT;
	return NULL;
}

/* Policy decision, several options:
 *
 * 1) Silently discard
 * 2) Pops all MPLS headers, use resulting upper-layer
 *    protocol packet to generate ICMP.
 * 3) Walk down MPLS headers to upper-layer header,
 *    generate ICMP using that and then prepend
 *    IDENTICAL MPLS header stack to ICMP packet.
 *
 * Problem with #2 is that there may be no route to
 * upper-level packet source for us to use.  (f.e. we
 * are switching VPN packets that we have no routes to).
 *
 * Option #3 should work even in those cases, because it
 * is more likely that egress of this MPLS path knows how
 * to route such packets back to source.  It should also
 * not be susceptible to loops in MPLS fabric, since one
 * never responds to ICMP with ICMP.  It is deliberate
 * assumption made about upper-layer protocol.
 */
static int mpls4_ttl_expired(struct sk_buff **skb)
{
	struct sk_buff *nskb;
	MPLS_ENTER;
	if ((nskb = mpls4_build_icmp(*skb, ICMP_TIME_EXCEEDED, 0, 1)))
		if (dst_output(nskb))
			kfree_skb(nskb);

	/* make sure the MPLS stack frees the original skb! */
	MPLS_EXIT;
	return NET_RX_DROP;
}

static int mpls4_mtu_exceeded(struct sk_buff **skb, int mtu)
{
	struct sk_buff *nskb;
	MPLS_ENTER;
	if ((nskb = mpls4_build_icmp(*skb, ICMP_DEST_UNREACH, htonl(mtu), 0)))
		if (dst_output(nskb))
			kfree_skb(nskb);

	/* make sure the MPLS stack frees the original skb! */
	MPLS_EXIT;
	return MPLS_RESULT_DROP;
}

static int mpls4_local_deliver(struct sk_buff *skb)
{
	MPLS_ENTER;
	skb->protocol = htons(ETH_P_IP);
	memset(skb->cb, 0, sizeof(skb->cb));
	skb_dst_drop(skb);
	netif_receive_skb(skb);
	MPLS_EXIT;
	return 0;
}

#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
#include <net/atmclip.h>
#endif

static inline int mpls4_nexthop_resolve(struct dst_entry *dst, struct sockaddr *sock_addr, struct net_device *dev)
{
	struct sockaddr_in *addr = (struct sockaddr_in *) sock_addr;
	struct neighbour *n;
	u32 nexthop;
	MPLS_ENTER;
	if (addr->sin_family == AF_INET)
		nexthop = addr->sin_addr.s_addr;
	else if (!addr->sin_family)
		nexthop = 0;
	else {
		MPLS_EXIT;
		return -EINVAL;
	}

	n = __neigh_lookup_errno(
#if defined(CONFIG_ATM_CLIP) || defined(CONFIG_ATM_CLIP_MODULE)
		dev->type == ARPHRD_ATM ? clip_tbl_hook :
#endif
		&arp_tbl, &nexthop, dev);

	if (IS_ERR(n)){
		MPLS_EXIT;
		return PTR_ERR(n);
	}

	dst_set_neighbour(dst, n);
	MPLS_EXIT;
	return 0;
}

static struct mpls_prot_driver mpls4_driver = {
	.__refcnt 				=		ATOMIC_INIT(0),
	.name					=		"ipv4",
	.family                 =       AF_INET,
	.ethertype              =       htons(ETH_P_IP),
	.cache_flush            =       mpls4_cache_flush,
	.set_ttl                =       mpls4_set_ttl,
	.get_ttl                =       mpls4_get_ttl,
	.change_dsfield         =       mpls4_change_dsfield,
	.get_dsfield            =       mpls4_get_dsfield,
	.ttl_expired            =       mpls4_ttl_expired,
	.mtu_exceeded			=		mpls4_mtu_exceeded,
	.local_deliver			=		mpls4_local_deliver,
	.nexthop_resolve        =       mpls4_nexthop_resolve,
	.owner                  =       THIS_MODULE,
};

static int __init mpls4_init(void)
{
	struct mpls_instr_elem instr[2];
	struct mpls_label ml;
	struct mpls_ilm *ilm;
	int result = mpls_proto_add(&mpls4_driver);
	MPLS_ENTER;
	printk(KERN_INFO "MPLS: IPv4 over MPLS support\n");

	if (result)
		return result;

	ml.ml_type = MPLS_LABEL_GEN;
	ml.u.ml_gen = MPLS_IPV4_EXPLICIT_NULL;

	instr[0].mir_direction = MPLS_IN;
	instr[0].mir_opcode    = MPLS_OP_POP;
	instr[1].mir_direction = MPLS_IN;
	instr[1].mir_opcode    = MPLS_OP_PEEK;

	ilm = mpls_ilm_alloc(0, &ml, instr, 2);
	if (!ilm){
		MPLS_EXIT;
		return -ENOMEM;
	}

	result = mpls_add_reserved_label(MPLS_IPV4_EXPLICIT_NULL, ilm);
	if (result) {
		mpls_ilm_release(ilm);
		MPLS_EXIT;
		return result;
	}
	MPLS_EXIT;
	return 0;
}

static void __exit mpls4_fini(void)
{
	struct mpls_ilm *ilm = mpls_del_reserved_label(MPLS_IPV4_EXPLICIT_NULL);
	MPLS_ENTER;
	mpls_ilm_release(ilm);
	mpls_proto_remove(&mpls4_driver);

	printk(KERN_INFO "MPLS: IPv4 over MPLS support exiting\n");
	MPLS_EXIT;
}

module_init(mpls4_init);
module_exit(mpls4_fini);
