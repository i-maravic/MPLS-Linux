/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls6.c:
 *      - IPv6 MPLS protocol driver.
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
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <net/dsfield.h>
#include <net/neighbour.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/dst.h>
#include <net/mpls.h>

MODULE_LICENSE("GPL");

static inline void mpls6_cache_flush(struct net *net)
{
	fib6_run_gc((unsigned long)0, net);
}

static inline void mpls6_set_ttl(struct sk_buff *skb, int ttl)
{
	/*ipv6_hdr(skb)->hop_limit; RCAS*/
	ipv6_hdr(skb)->hop_limit = ttl;
}

static inline int mpls6_get_ttl(struct sk_buff *skb)
{
	return ipv6_hdr(skb)->hop_limit;
}

static inline void mpls6_change_dsfield(struct sk_buff *skb, int ds)
{
	ipv6_change_dsfield(ipv6_hdr(skb), 0x3, ds);
}

static inline int mpls6_get_dsfield(struct sk_buff *skb)
{
	return ipv6_get_dsfield(ipv6_hdr(skb));
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
 //should send ICMP here
static int mpls6_ttl_expired(struct sk_buff **skb)
{
	return NET_RX_DROP;
}

 //should send ICMP here
static int mpls6_mtu_exceeded(struct sk_buff **skb, int mtu)
{
	return MPLS_RESULT_DROP;
}

static int mpls6_local_deliver(struct sk_buff *skb)
{
	skb->protocol = htons(ETH_P_IPV6);
	memset(skb->cb, 0, sizeof(skb->cb));
	skb_dst_drop(skb);
	netif_receive_skb(skb);
	return 0;
}

static inline int mpls6_nexthop_resolve(struct dst_entry *dst, struct sockaddr *sock_addr, struct net_device *dev)
{
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sock_addr;
	struct flowi6 fl6 = {
		.daddr = addr->sin6_addr,
		.flowi6_oif = dev->ifindex,
	};
	struct dst_entry *ndst;
	int err;

	if (addr->sin6_family != AF_INET6)
		return -EINVAL;

	ndst = ip6_route_output(&init_net, NULL, &fl6);

	err = 0;
	if (ndst->error)
		err = -EINVAL;

	if (!err){
		rcu_read_lock();
		dst_set_neighbour(dst, neigh_clone(dst_get_neighbour(ndst)));
		rcu_read_unlock();
	}
	
	dst_release(ndst);

	return err;
}

static struct mpls_prot_driver mpls6_driver = {
	.__refcnt 				=		ATOMIC_INIT(0),
	.name					=		"ipv6",
	.family                 =       AF_INET6,
	.ethertype              =       cpu_to_be16(ETH_P_IPV6),
	.cache_flush            =       mpls6_cache_flush,
	.set_ttl                =       mpls6_set_ttl,
	.get_ttl                =       mpls6_get_ttl,
	.change_dsfield         =       mpls6_change_dsfield,
	.get_dsfield            =       mpls6_get_dsfield,
	.ttl_expired            =       mpls6_ttl_expired,
	.mtu_exceeded			=		mpls6_mtu_exceeded,
	.local_deliver			=		mpls6_local_deliver,
	.nexthop_resolve        =       mpls6_nexthop_resolve,
	.owner                  =       THIS_MODULE,
};

static int __init mpls6_init(void)
{
	struct mpls_instr_elem instr[2];
	struct mpls_label ml;
	struct mpls_ilm *ilm;
	int result = mpls_proto_add(&mpls6_driver);

	printk(KERN_INFO "MPLS: IPv6 over MPLS support\n");

	if (result)
		return result;

	ml.ml_type = MPLS_LABEL_GEN;
	ml.u.ml_gen = MPLS_IPV6_EXPLICIT_NULL;

	instr[0].mir_direction = MPLS_IN;
	instr[0].mir_opcode    = MPLS_OP_POP;
	instr[1].mir_direction = MPLS_IN;
	instr[1].mir_opcode    = MPLS_OP_PEEK;

	ilm = mpls_ilm_dst_alloc(0, &ml, &mpls6_driver, instr, 2);
	if (!ilm)
		return -ENOMEM;

	result = mpls_add_reserved_label(MPLS_IPV6_EXPLICIT_NULL, ilm);
	if (result) {
		mpls_ilm_release(ilm);
		return result;
	}

	return 0;
}

static void __exit mpls6_fini(void)
{
	struct mpls_ilm *ilm = mpls_del_reserved_label(MPLS_IPV6_EXPLICIT_NULL);
	mpls_ilm_drop(ilm);

	mpls_proto_remove(&mpls6_driver);

	printk(KERN_INFO "MPLS: IPv6 over MPLS support exiting\n");
}

module_init(mpls6_init);
module_exit(mpls6_fini);
