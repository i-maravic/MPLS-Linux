/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS virtual interface for Linux.
 *      MPLS virtual interfaces are used as entry points for LSPs
 *
 * Authors:
 *   (c) 1999-2005   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  *****************************************************************************/

#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/mpls.h>
#include <linux/etherdevice.h>
#include "mpls_cmd.h"

static void mpls_tunnel_setup(struct net_device *dev);

static struct rtnl_link_ops mpls_link_ops __read_mostly;

static int mpls_dev_net_id __read_mostly;
struct mpls_dev_net {
	struct net_device *master_dev;
};

struct pcpu_tstats {
	unsigned long	rx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_packets;
	unsigned long	tx_bytes;
} __attribute__((aligned(4*sizeof(unsigned long))));

static int
__mpls_finish_xmit(struct sk_buff *skb, const void *data)
{
	u32 packet_length = 0;
	struct net_device *tdev = skb->dev;
	struct dst_entry *dst = skb_dst(skb);
	struct mpls_tunnel *tunnel = netdev_priv(tdev);
	const struct nhlfe *nhlfe = rcu_dereference(tunnel->nhlfe);
	const struct __instr *mi;
	struct pcpu_tstats *tstats = this_cpu_ptr(tdev->tstats);
	int ret = -NET_RX_DROP;

	mi = get_first_instruction(nhlfe);

	if (mi->cmd == MPLS_ATTR_DSCP) {
		ret = mpls_dscp(skb, mi++);
		if (unlikely(ret))
			goto abort;
	}

	if (mi->cmd == MPLS_ATTR_TC_INDEX) {
		ret = mpls_tc_index(skb, mi++);
		if (unlikely(ret))
			goto abort;
	}

	if (mi->cmd == MPLS_ATTR_PUSH) {
		ret = mpls_push(skb, mi);
		if (unlikely(ret))
			goto abort;
	}

	packet_length = skb->len;

	if (unlikely(skb->len > dst->dev->mtu)) {
		WARN_ON_ONCE(skb->len > dst->dev->mtu);
		goto abort;
	}

	ret = mpls_send(skb, NULL);
	goto end;

abort:
	tdev->stats.tx_aborted_errors++;
	tdev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return -NET_XMIT_DROP;

end:
	if (likely(!ret)) {
		tstats->tx_packets++;
		tstats->tx_bytes += packet_length;
	} else
		tdev->stats.tx_dropped++;

	return ret;
}

static netdev_tx_t
mpls_tunnel_xmit(struct sk_buff *skb, struct net_device *tdev)
{
	struct mpls_tunnel *tunnel = netdev_priv(tdev);
	const struct mpls_dev_net *mdn = net_generic(dev_net(tdev), mpls_dev_net_id);
	const struct nhlfe *nhlfe = NULL;
	struct dst_entry *dst = NULL;
	const struct __instr *mi;
	u32 mtu;
	int ret = -NET_XMIT_DROP;

	rcu_read_lock();
	if (tdev == mdn->master_dev)
		// TODO
		goto discard;

	if (skb_cow_head(skb, tunnel->hlen) < 0)
		goto discard;

	nhlfe = rcu_dereference(tunnel->nhlfe);

	mi = get_last_instruction(nhlfe);
	if (mi->cmd == MPLS_ATTR_SEND_IPv4) {
		dst = mpls_get_dst_ipv4(skb, mi);
#if IS_ENABLED(CONFIG_IPV6)
send_common:
#endif
		if (!dst)
			goto link_failure;

		if (unlikely(dst->dev == tdev)) {
			tdev->stats.collisions++;
			goto drop;
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (mi->cmd == MPLS_ATTR_SEND_IPv6) {
		dst = mpls_get_dst_ipv6(skb, mi);
		goto send_common;
	}
#endif
	else
		goto discard;

	mtu = dst->dev->mtu - tdev->hard_header_len - tunnel->hlen;

	if (likely(skb_dst(skb)))
		skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);

		if (mtu < ntohs(iph->tot_len)) {
			if (iph->frag_off & htons(IP_DF)) {
				icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
				goto err;
			} else {
				/* Avoid icmp_send in ip_fragment */
				skb->local_df = 1;
				__mpls_set_dst(skb, dst);
				ret = mpls_update_pmtu(skb, mi, mtu);
				if (unlikely(ret)) {
					dst = NULL;
					goto err;
				}

				__ip_fragment(skb, NULL, __mpls_finish_xmit);
				goto exit;
			}
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (mtu < skb->len - tunnel->hlen) {
			if (mtu >= IPV6_MIN_MTU ||
				  !ipv6_has_fragment_hdr(skb)) {
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
				goto err;
			} else {
				/* Avoid icmp_send in ip6_fragment */
				skb->local_df = 1;
				__mpls_set_dst(skb, dst);
				ret = mpls_update_pmtu(skb, mi, mtu);
				if (unlikely(ret)) {
					dst = NULL;
					goto err;
				}

				__ip6_fragment(skb, NULL, __mpls_finish_xmit);
				goto exit;
			}
		}
	}
#endif
	else
		goto discard;

	__mpls_set_dst(skb, dst);
	__mpls_finish_xmit(skb, NULL);
	goto exit;

discard:
	MPLS_INC_STATS_BH(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
	tdev->stats.tx_aborted_errors++;
	goto err;

link_failure:
	tdev->stats.tx_carrier_errors++;
	dst_link_failure(skb);

err:
	tdev->stats.tx_errors++;
	dst_release(dst);
	goto free_skb;

drop:
	tdev->stats.tx_dropped++;

	dst_release(dst);

free_skb:
	dev_kfree_skb(skb);

exit:
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static void mpls_dev_free(struct net_device *dev)
{
	struct mpls_tunnel *t = netdev_priv(dev);
	struct mpls_dev_net *mdn = net_generic(dev_net(dev), mpls_dev_net_id);

	if (unlikely(dev == mdn->master_dev))
		mdn->master_dev = NULL;

	rtnl_lock();
	__nhlfe_free(t->nhlfe);
	rtnl_unlock();

	free_percpu(dev->tstats);
	free_netdev(dev);
}

static int mpls_tunnel_init(struct net_device *dev)
{
	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void
mpls_tunnel_uninit(struct net_device *dev)
{
	dev_put(dev);
}

static int
mpls_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	struct mpls_tunnel *tunnel = netdev_priv(dev);
	if (new_mtu < 68 ||
	    new_mtu > 0xFFF8 - dev->hard_header_len - tunnel->hlen)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static struct net_device_stats *
mpls_tunnel_get_stats(struct net_device *dev)
{
	struct pcpu_tstats sum = { 0 };
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_tstats *tstats = per_cpu_ptr(dev->tstats, i);
		sum.tx_packets += tstats->tx_packets;
		sum.tx_bytes   += tstats->tx_bytes;
	}
	dev->stats.tx_packets = sum.tx_packets;
	dev->stats.tx_bytes   = sum.tx_bytes;
	return &dev->stats;
}

static const struct net_device_ops mpls_netdev_ops = {
	.ndo_init = mpls_tunnel_init,
	.ndo_uninit = mpls_tunnel_uninit,
	.ndo_start_xmit = mpls_tunnel_xmit,
	.ndo_do_ioctl = NULL,
	.ndo_change_mtu = mpls_tunnel_change_mtu,
	.ndo_get_stats = mpls_tunnel_get_stats,
};

static int __net_init mpls_dev_init_net(struct net *net)
{
	struct mpls_dev_net *mdn = net_generic(net, mpls_dev_net_id);
	struct mpls_tunnel *t;
	int err;

	mdn->master_dev = alloc_netdev(sizeof(struct mpls_tunnel),
					MPLS_MASTER_DEV, mpls_tunnel_setup);
	if (!mdn->master_dev) {
		err = -ENOMEM;
		goto err_alloc_dev;
	}
	dev_net_set(mdn->master_dev, net);

	dev_hold(mdn->master_dev);
	mdn->master_dev->rtnl_link_ops = &mpls_link_ops;

	t = netdev_priv(mdn->master_dev);
	memset(t, 0, sizeof(struct mpls_tunnel));

	if ((err = register_netdev(mdn->master_dev)))
		goto err_reg_dev;

	return 0;

err_reg_dev:
	mpls_dev_free(mdn->master_dev);
err_alloc_dev:
	return err;
}

static void __net_exit mpls_dev_exit_net(struct net *net)
{
	struct mpls_dev_net *mdn = net_generic(net, mpls_dev_net_id);

	if (likely(mdn->master_dev))
		unregister_netdev(mdn->master_dev);
}

static struct pernet_operations mpls_dev_net_ops = {
	.init = mpls_dev_init_net,
	.exit = mpls_dev_exit_net,
	.id   = &mpls_dev_net_id,
	.size = sizeof(struct mpls_dev_net),
};

static int mpls_tunnel_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (!data)
		return 0;

	if (data[MPLS_ATTR_POP] ||
		  data[MPLS_ATTR_SWAP] ||
		  data[MPLS_ATTR_PEEK])
		return -EINVAL;

	return 0;
}

static int
mpls_tunnel_bind_dev(struct net_device *dev)
{
	struct mpls_tunnel *tunnel;
	const struct nhlfe *nhlfe;
	const struct __instr *last_instr;
	const struct __mpls_nh *nh = NULL;
	struct net_device *tdev = NULL;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int addend = 0;
	int link = 0;

	tunnel = netdev_priv(dev);
	nhlfe = rcu_dereference_rtnl(tunnel->nhlfe);
	addend = nhlfe->no_push * MPLS_HDR_LEN;
	last_instr = get_last_instruction(nhlfe);
	nh = (struct __mpls_nh *)rtnl_dereference_ulong(last_instr->data);

	if (nh) {
		link = nh->iface;
		if (last_instr->cmd == MPLS_ATTR_SEND_IPv4) {
			struct rtable *rt;

			rt = ip_route_output(dev_net(dev),
					nh->ipv4.sin_addr.s_addr, 0, 0, nh->iface);

			if (!IS_ERR(rt)) {
				tdev = rt->dst.dev;
				ip_rt_put(rt);
			}
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (last_instr->cmd == MPLS_ATTR_SEND_IPv6) {
			struct dst_entry *dst;
			struct flowi6 fl6;

			memset(&fl6, 0, sizeof(fl6));
			fl6.flowi6_oif = nh->iface;
			fl6.daddr = nh->ipv6.sin6_addr;

			dst = ip6_route_output(dev_net(dev), NULL, &fl6);
			if (!(!dst || dst->error))
				tdev = dst->dev;

			dst_release(dst);
		}
#endif
	}

	if (!tdev && link)
		tdev = __dev_get_by_index(dev_net(dev), link);

	if (tdev) {
		hlen = tdev->hard_header_len + tdev->needed_headroom;
		mtu = tdev->mtu;
	}

	dev->iflink = link;
	dev->needed_headroom = addend + hlen;
	mtu -= dev->hard_header_len + addend;
	tunnel->hlen = addend;

	if (mtu < 68)
		mtu = 68;

	return mtu;
}

static int
mpls_tunnel_change(struct net_device *dev, struct nlattr *tb[],
						struct nlattr *data[])
{
	struct mpls_tunnel *nt;
	struct mpls_dev_net *mdn = net_generic(dev_net(dev), mpls_dev_net_id);
	struct nhlfe *old_nhlfe, *nhlfe;
	int mtu;

	if (dev == mdn->master_dev)
		return -EINVAL;

	nhlfe = __nhlfe_build(data);
	if (unlikely(IS_ERR(nhlfe)))
		return PTR_ERR(nhlfe);

	nt = netdev_priv(dev);
	old_nhlfe = rtnl_dereference(nt->nhlfe);
	__nhlfe_free(old_nhlfe);

	rcu_assign_pointer(nt->nhlfe, nhlfe);

	mtu = mpls_tunnel_bind_dev(dev);
	if (!tb[IFLA_MTU])
		dev->mtu = mtu;

	netdev_state_change(dev);

	return 0;
}

static int
mpls_tunnel_new(struct net *src_net, struct net_device *dev, struct nlattr *tb[],
			 struct nlattr *data[])
{
	struct mpls_tunnel *nt;
	struct nhlfe *nhlfe;
	int mtu;
	int err;

	nhlfe = __nhlfe_build(data);
	if (unlikely(IS_ERR(nhlfe)))
		return PTR_ERR(nhlfe);

	nt = netdev_priv(dev);
	rcu_assign_pointer(nt->nhlfe, nhlfe);

	if (!tb[IFLA_ADDRESS])
		random_ether_addr(dev->dev_addr);

	mtu = mpls_tunnel_bind_dev(dev);
	if (!tb[IFLA_MTU])
		dev->mtu = mtu;

	err = register_netdevice(dev);
	if (err)
		goto err;

	dev_hold(dev);
	return err;

err:
	__nhlfe_free(nhlfe);
	rcu_assign_pointer(nt->nhlfe, NULL);
	return err;
}

static void
mpls_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops = &mpls_netdev_ops;
	dev->destructor = mpls_dev_free;

	dev->type = ARPHRD_MPLS;
	dev->needed_headroom = LL_MAX_HEADER;
	dev->mtu = ETH_DATA_LEN;
	dev->flags = IFF_NOARP | IFF_POINTOPOINT;
	dev->iflink = 0;
	dev->addr_len = ETH_ALEN;
	dev->features |= NETIF_F_NETNS_LOCAL;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

static size_t
mpls_get_size(const struct net_device *dev)
{
	return
		/* MPLS_ATTR_POP */
		nla_total_size(1) +
		/* MPLS_ATTR_DSCP */
		nla_total_size(1) +
		/* MPLS_ATTR_TC_INDEX */
		nla_total_size(2) +
		/* MPLS_ATTR_SWAP */
		nla_total_size(4) +
		/* MPLS_ATTR_PUSH */
		nla_total_size(sizeof(struct nlattr)) +
		(MPLS_PUSH_MAX - 1) * nla_total_size(4) +
		/* MPLS_NO_PUSHES */
		nla_total_size(1) +
		/* MPLS_ATTR_PEEK || MPLS_ATTR_SEND_IPv4 || MPLS_ATTR_SEND_IPv6 */
		nla_total_size(sizeof(struct mpls_nh)) +
		/* MPLS_ATTR_INSTR_COUNT */
		nla_total_size(1) +
		0;
}

static int
mpls_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct mpls_tunnel *t = netdev_priv(dev);
	return __nhlfe_dump(rcu_dereference_rtnl(t->nhlfe), skb);
}

static struct rtnl_link_ops mpls_link_ops __read_mostly = {
	.kind		= "mpls",
	.maxtype	= MPLS_ATTR_MAX,
	.policy		= __nhlfe_policy,
	.priv_size	= sizeof(struct mpls_tunnel),
	.setup		= mpls_tunnel_setup,
	.validate	= mpls_tunnel_validate,
	.newlink	= mpls_tunnel_new,
	.changelink	= mpls_tunnel_change,
	.get_size	= mpls_get_size,
	.fill_info	= mpls_fill_info,
};

int __init mpls_dev_init(void)
{
	int err;
	err = register_pernet_device(&mpls_dev_net_ops);
	if (err < 0)
		return err;

	err = rtnl_link_register(&mpls_link_ops);
	return err;
}

void mpls_dev_exit(void)
{
	struct net_device *dev;
	struct net_device *ndev;
	struct net *net;
	rtnl_link_unregister(&mpls_link_ops);

	for_each_net(net)
		for_each_netdev_safe(net, dev, ndev)
			if (dev->type == ARPHRD_MPLS)
				unregister_netdevice(dev);
	unregister_pernet_device(&mpls_dev_net_ops);
}
