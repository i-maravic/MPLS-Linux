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

struct net_device *
__mpls_master_dev(const struct net* net)
{
	struct mpls_dev_net *mdn = net_generic(net, mpls_dev_net_id);
	return mdn->master_dev;
}

struct pcpu_tstats {
	unsigned long	rx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_packets;
	unsigned long	tx_bytes;
} __attribute__((aligned(4*sizeof(unsigned long))));

static netdev_tx_t
mpls_tunnel_xmit(struct sk_buff *skb, struct net_device *tdev)
{
	struct mpls_tunnel *tunnel = netdev_priv(tdev);
	const struct mpls_dev_net *mdn = net_generic(dev_net(tdev), mpls_dev_net_id);
	const struct nhlfe *nhlfe = NULL;
	struct pcpu_tstats *tstats = this_cpu_ptr(tdev->tstats);
	struct dst_entry *tdst = skb_dst(skb);
	struct net *net = dev_net(skb->dev);
	int ret;

	rcu_read_lock();
	if (tdev == mdn->master_dev) {
		if (unlikely(tdst == NULL))
			goto unlock_and_free;

		nhlfe = rcu_dereference(tdst->nhlfe);
		if (unlikely(nhlfe == NULL))
			goto unlock_and_free;

		if (unlikely(nhlfe->dead)) {
			tdst->obsolete = DST_OBSOLETE_KILL;
			goto unlock_and_free;
		}
	} else
		nhlfe = rcu_dereference(tunnel->nhlfe);

	skb->dev = tdev;
	ret = nhlfe_send(nhlfe, skb);
	rcu_read_unlock();

	switch (ret) {
	case NET_XMIT_SUCCESS:
		tstats->tx_packets++;
		tstats->tx_bytes += skb->len;
		return NET_XMIT_SUCCESS;
	case -ELOOP:
		tdev->stats.collisions++;
		tdev->stats.tx_dropped++;
		return NET_XMIT_DROP;
	case -ENETUNREACH:
		tdev->stats.tx_carrier_errors++;
		goto err;
	case -EPFNOSUPPORT:
	default:
		goto discard;
	}

unlock_and_free:
	rcu_read_unlock();
	dev_kfree_skb(skb);
discard:
	MPLS_INC_STATS_BH(net, MPLS_MIB_OUTDISCARDS);
	tdev->stats.tx_aborted_errors++;
err:
	tdev->stats.tx_errors++;
	return NET_XMIT_DROP;
}

static void mpls_dev_free(struct net_device *dev)
{
	struct mpls_tunnel *t = netdev_priv(dev);
	struct mpls_dev_net *mdn = net_generic(dev_net(dev), mpls_dev_net_id);

	if (unlikely(dev == mdn->master_dev))
		mdn->master_dev = NULL;

	rtnl_lock();
	__nhlfe_free_rcu(t->nhlfe);
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
	if (!data || !data[MPLSA_NEXTHOP_ADDR])
		return -EINVAL;

	return 0;
}

static int
mpls_tunnel_bind_dev(struct net_device *dev)
{
	const struct nhlfe *nhlfe;
	struct mpls_tunnel *tunnel;
	struct net_device *tdev = NULL;
	struct net *net;
	struct dst_entry *dst;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int addend = 0;
	int link = 0;

	tunnel = netdev_priv(dev);
	nhlfe = rcu_dereference_rtnl(tunnel->nhlfe);
	addend = nhlfe->num_push * MPLS_HDR_LEN;

	link = nhlfe->ifindex;
	net = (nhlfe->flags & MPLS_NH_GLOBAL) ? &init_net : dev_net(dev);
	dst = nhlfe_get_nexthop_dst(nhlfe, net, NULL);
	if (!IS_ERR(dst)) {
		tdev = dst->dev;
		dst_release(dst);
	}

	if (!tdev && link)
		tdev = __dev_get_by_index(net, link);

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

	nhlfe = __nhlfe_build(dev_net(dev), NULL, NULL, data);

	if (unlikely(IS_ERR(nhlfe)))
		return PTR_ERR(nhlfe);

	nt = netdev_priv(dev);
	old_nhlfe = rtnl_dereference(nt->nhlfe);
	__nhlfe_free_rcu(old_nhlfe);

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

	nhlfe = __nhlfe_build(src_net, NULL, NULL, data);

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
	dev->flags = IFF_NOARP | IFF_POINTOPOINT | IFF_MPLS;
	dev->iflink = 0;
	dev->addr_len = ETH_ALEN;
	dev->features |= NETIF_F_NETNS_LOCAL;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}

static size_t
mpls_get_size(const struct net_device *dev)
{
	return mpls_nla_size();
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
