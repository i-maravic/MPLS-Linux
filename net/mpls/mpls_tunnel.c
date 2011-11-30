/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_tunnel.c
 *         * Management of MPLS tunnels, virtual devices named by default
 *           mpls%d and that can be managed using userspace tools like
 *           ip route, ifconfig, etc. As per RFC, LSPs are unidirectional.
 *  Usage:
 *         Creation    : mpls_tunnel_create
 *         Destruction : mpls_tunnel_destroy
 *         EXPORT_SYMBOL(mpls_tunnel_create);
 *         EXPORT_SYMBOL(mpls_tunnel_destroy);
 *
 * Authors:
 *   (c) 1999-2005   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *   (c) 2011        Igor Maravić     <igorm@etf.rs>
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
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/mpls.h>

/**
 * MODULE Information and attributes
 **/

static struct net_device *mpls_tunnel_dev;
static void mpls_tunnel_setup(struct net_device *dev);
static int mpls_tunnel_key;

MODULE_AUTHOR("James R. Leu <jleu@mindspring.com>, Ramon Casellas <casellas@infres.enst.fr>");
MODULE_DESCRIPTION("MultiProtocol Label Switching Tunnel Module");
MODULE_LICENSE("GPL");

/*  Obtain private MPLS extension for a netdevice */
#define mpls_dev2mtp(MPLSDEV) \
	((struct mpls_tunnel_private *)(netdev_priv(MPLSDEV)))

/* Obtain mentor netdevice for a given (private) tunnel */
#define mpls_mtp2dev(MPLSMTP) \
	((struct net_device *)((MPLSMTP)->mtp_dev))

/**
 *	mpls_tunnel_set_nhlfe - sets the nhlfe for this virtual device.
 *	@dev: netdevice "mpls%d"
 *	@key: nhlfe key.
 *
 *	Sets the NHLFE for this mpls net_device according to the key: if the
 *	key is zero, this function releases and resets the tunnel's nhlfe.
 *	Otherwise, it holds a reference to the new nhlfe (as per key),
 *	updates the MTU
 *
 *	The mtp_nhlfe member of the tunnel private structure holds a
 *	reference to the new NHLFE object.
 *	Returns 0 if ok.
 *
 *	Remarks:
 *	     o This function increases the reference count of the NHLFE
 *	       determined by the key if the key is non zero, since the
 *	       NHLFE will be held by the device private part.
 **/

static int mpls_tunnel_set_nhlfe(
	struct net_device *dev,	unsigned int key)
{
	struct mpls_nhlfe *nhlfe = NULL;
	struct mpls_nhlfe *newnhlfe = NULL;

	MPLS_ENTER;

	/* Get previous NHLFE (it is held by mtp)  */
	nhlfe = mpls_dev2mtp(dev)->mtp_nhlfe;

	/* If key is zero, the nhlfe for tunnel is reset, we are done */
	if (!key) {
		if (nhlfe) {
			MPLS_DEBUG("dropping old nhlfe %x\n", nhlfe->nhlfe_key);
			mpls_nhlfe_release(nhlfe);
		}
		MPLS_DEBUG("reset nhlfe %x\n", key);
		mpls_dev2mtp(dev)->mtp_nhlfe = NULL;
		dev->iflink = 0;
		MPLS_EXIT;
		return 0;
	}

	/* Get a reference for new NHLFE */
	newnhlfe = mpls_get_nhlfe(key);
	if (unlikely(!newnhlfe)) {
		MPLS_DEBUG("error fetching new nhlfe with key %u\n", key);
		MPLS_DEBUG("keeping old nhlfe %x\n", nhlfe->nhlfe_key);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* Drop old NHLFE */
	if (nhlfe) {
		dev_close(dev);
		MPLS_DEBUG("dropping old nhlfe %x\n", nhlfe->nhlfe_key);
		mpls_nhlfe_release(nhlfe);
	}

	/* Commit Set new NHLFE (it is held by mtp)  */
	mpls_dev2mtp(dev)->mtp_nhlfe = newnhlfe;

	if (newnhlfe) {
		/* Set new MTU for the tunnel device */
		dev_set_mtu(dev, dst_mtu(&newnhlfe->dst));
		dev_open(dev);
	}

	MPLS_EXIT;
	return 0;
}

/**
 *	mpls_tunnel_destructor - say tunnel goodbye.
 *	@dev: mpls tunnel
 *
 *	This callback gets called when the core system destroys the net_device.
 *	Remember that it was allocated with  alloc_netdev(netdev + privdata),
 *	and dev->priv points to the "extension" (privdata). So we just reset to
 *	NULL. cf. dev.c "It must be the very last action, after this 'dev' may
 *	point to freed up memory.". the refcount of the object at this point is
 *	zero.
 **/

static void mpls_tunnel_destructor(struct net_device *dev)
{
	MPLS_ENTER;
	mpls_tunnel_set_nhlfe(dev, 0);
	free_netdev(dev);
	MPLS_EXIT;
}

/**
 *	mpls_tunnel_xmit - transmit a socket buffer via the device.
 *	@skb: data
 *	@dev: mpls tunnel
 *
 *	This callback gets called when the core system wants to send a socket
 *	buffer. The buffer is sent only if someone set a valid
 *	NHLFE (e.g. PUSH/.../SET) for the device
 **/

static int mpls_tunnel_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	int result = 0;
	struct mpls_nhlfe *nhlfe = mpls_dev2mtp(dev)->mtp_nhlfe;

	MPLS_ENTER;

	if (nhlfe) {
		MPLS_DEBUG(
				"Skb to Send\n"
				"Device %s\n"
				"DST %p\n"
				"Protocol ID %04x\n",
				skb->dev ? skb->dev->name : "<>",
				skb_dst(skb) ? skb_dst(skb) : NULL,
				ntohs(skb->protocol)
		);

		MPLS_DEBUG("Using NHLFE %08x\n", nhlfe->nhlfe_key);
		mpls_dev2mtp(dev)->stat.tx_packets++;
		mpls_dev2mtp(dev)->stat.tx_bytes += skb->len;

		skb_dst_drop(skb);
		mpls_nhlfe_hold(nhlfe);
		skb_dst_set(skb, &nhlfe->dst);

		result = dst_output(skb);
		MPLS_EXIT;
		return result;
	}

	dev_kfree_skb(skb);
	mpls_dev2mtp(dev)->stat.tx_errors++;
	MPLS_DEBUG("exit - NHLFE was invalid\n");
	MPLS_EXIT;
	return 0;
}

/**
 *	mpls_tunnel_get_stats - get sender statistics for this tunnel
 *	@dev: virtual "mpls%d" device.
 **/

static struct net_device_stats *mpls_tunnel_get_stats(
		struct net_device *dev)
{
	return &((mpls_dev2mtp(dev))->stat);
}

/**
 *	mpls_tunnel_change_mtu - Grant new MTU value for device.
 *	@dev: virtual "mpls%d" device.
 *	@new_mtu: new value
 *
 *	Called by dev_set_mtu (see net/code/dev.c). May veto the new value.
 *	Returns 0 if Ok. -EINVAL otherwise.
 *  IMAR:
 *		MTU assigment is done here because
 *		function dev_set_mtu doesn't do mtu assigment!!!
 **/

static int mpls_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	struct dst_entry *dst = &mpls_dev2mtp(dev)->mtp_nhlfe->dst;
	MPLS_ENTER;
	if ((new_mtu < MPLS_HDR_LEN) || (new_mtu > dst_mtu(dst))) {
			MPLS_EXIT;
			return -EINVAL;
	}

	dev->mtu = new_mtu;
	MPLS_EXIT;
	return 0;
}

static int mpls_tunnel_alloc(struct mpls_tunnel_req *mtr)
{
	struct mpls_nhlfe *nhlfe = NULL;
	struct net_device *dev;
	int retval;

	MPLS_ENTER;
	retval = -ESRCH;
	nhlfe = mpls_get_nhlfe(mtr->mt_nhlfe_key);
	if (mtr->mt_nhlfe_key && !nhlfe)
		goto error;

	retval = -ENOMEM;
	snprintf(mtr->mt_ifname, IFNAMSIZ, "mpls%d", mpls_tunnel_key++);
	dev = alloc_netdev(sizeof(struct mpls_tunnel_private),
			mtr->mt_ifname, mpls_tunnel_setup);
	if (!dev) {
		mpls_nhlfe_release(nhlfe);
		goto error;
	}

	retval = -ENOBUFS;
	if (register_netdevice(dev)) {
		mpls_nhlfe_release(nhlfe);
		free_netdev(dev);
		goto error;
	}

	mpls_dev2mtp(dev)->mtp_nhlfe = nhlfe;
	/* Set new MTU for the tunnel device */
	dev_set_mtu(dev, dst_mtu(&nhlfe->dst));
	dev_hold(dev);
	retval = 0;
error:
	MPLS_DEBUG("Retval: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static struct net_device *mpls_tunnel_lookup(
	struct mpls_tunnel_req *mtr)
{
	struct net_device *dev;
	MPLS_ENTER;
	dev = __dev_get_by_name(&init_net, mtr->mt_ifname);
	MPLS_EXIT;
	return dev;
}

/**
 *	mpls_tunnel_ioctl - callback for device private IOCTL calls
 *	@dev: virtual "mpls%d" device.
 *	@ifr: IOCTL request data
 *	@cmd: IOCTL command
 *
 *	Called in response to a userland IOCTL call for configuring
 *	this tunnel interface
 *	Returns 0 if Ok. < 0 on error
 **/

static int
mpls_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct mpls_tunnel_private *mtp = NULL;
	struct mpls_tunnel_req mtr;
	int retval = 0;

	MPLS_ENTER;
	switch (cmd) {
	case SIOCGETTUNNEL:
		if (dev == mpls_tunnel_dev) {
			retval = -EFAULT;
			if (copy_from_user(&mtr, ifr->ifr_data, sizeof(mtr)))
				break;

			retval = -ENOENT;
			dev = mpls_tunnel_lookup(&mtr);
			if (!dev)
				break;

			retval = -EINVAL;
			if (strncmp(mtr.mt_ifname, "mpls0", 5) == 0)
				break;
		}

		mtp = mpls_dev2mtp(dev);
		mtr.mt_nhlfe_key =
				mtp->mtp_nhlfe ? mtp->mtp_nhlfe->nhlfe_key : 0;
		retval = 0;
		break;

	case SIOCCHGTUNNEL:
		retval = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;

		if (mtr.mt_nhlfe_key == 0)
			break;

		if (dev == mpls_tunnel_dev) {
			retval = -EFAULT;
			if (copy_from_user(&mtr, ifr->ifr_data, sizeof(mtr)))
				break;

			retval = -ENOENT;
			dev = mpls_tunnel_lookup(&mtr);
			if (!dev)
				break;

			retval = -EINVAL;
			if (strncmp(mtr.mt_ifname, "mpls0", 5) == 0)
				break;
		}

		retval = mpls_tunnel_set_nhlfe(dev, mtr.mt_nhlfe_key);
		break;

	case SIOCADDTUNNEL:
		retval = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;

		retval = -EFAULT;
		if (copy_from_user(&mtr, ifr->ifr_data, sizeof(mtr)))
			break;

		retval = -EINVAL;
		if (mtr.mt_nhlfe_key == 0)
			break;

		if (dev == mpls_tunnel_dev) {
			retval = mpls_tunnel_alloc(&mtr);
			break;
		}

		retval = mpls_tunnel_set_nhlfe(mpls_mtp2dev(mtp),
				mtr.mt_nhlfe_key);
		break;

	case SIOCDELTUNNEL:
		retval = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			break;

		if (dev == mpls_tunnel_dev) {
			retval = -EFAULT;
			if (copy_from_user(&mtr, ifr->ifr_data, sizeof(mtr)))
				break;

			retval = -ENOENT;
			dev = mpls_tunnel_lookup(&mtr);
			if (!dev)
				break;

			retval = -EINVAL;
			if (strncmp(mtr.mt_ifname, "mpls0", 5) == 0)
				break;
		}

		unregister_netdevice(dev);
		retval = 0;
		break;

	default:
		retval = -EINVAL;
	}

	if (copy_to_user(ifr->ifr_data, &mtr, sizeof(mtr)))
		retval = -EFAULT;

	MPLS_EXIT;
	return retval;
}

static int mpls_tunnel_init(struct net_device *dev)
{
	struct mpls_tunnel_private *mtp =  mpls_dev2mtp(dev);
	MPLS_ENTER;
	mtp->mtp_dev = dev;
	MPLS_EXIT;
	return 0;
}

static void mpls_tunnel_uninit(struct net_device *dev)
{
	MPLS_ENTER;
	dev_put(dev);
	MPLS_EXIT;
}

static const struct net_device_ops mpls_tunnel_ndo = {
	.ndo_init = mpls_tunnel_init,
	.ndo_uninit = mpls_tunnel_uninit,
	.ndo_do_ioctl = mpls_tunnel_ioctl,
	.ndo_start_xmit = mpls_tunnel_xmit,
	.ndo_get_stats = mpls_tunnel_get_stats,
	.ndo_change_mtu = mpls_tunnel_change_mtu,
};

/**
 *	mpls_tunnel_setup - main setup callback
 *	@dev - mpls%d
 *
 *	Main setup function. Called by net/core/dev.c after a successful
 *	netdev_alloc. We just set the function pointer table, device type and
 *	flags. Initial MTU value is arbitrary, since the tunnel hasn't a valid
 *	NHLFE object (NHLFE objects know the number of pushes and the MTU of the
 *	real physical device).
 **/

static void mpls_tunnel_setup(struct net_device *dev)
{
	MPLS_ENTER;

	/* Callbacks */
	dev->destructor	     = mpls_tunnel_destructor;
	dev->netdev_ops	     = &mpls_tunnel_ndo;

	/* Properties of mpls%d devices */
	dev->type = ARPHRD_MPLS_TUNNEL;
	dev->hard_header_len = MPLS_HDR_LEN;
	dev->mtu = 1500;
	dev->flags = IFF_NOARP|IFF_POINTOPOINT;
	dev->iflink = 0;
	dev->addr_len = MPLS_HDR_LEN;
	MPLS_EXIT;
}

/**
 *	mpls_tunnel_init_module - main tunnel init routine.
 *
 *	Init method called when the module is loaded, initiliazes the
 *	list of created tunnels to zero, initializes and registers the
 *	mpls_tunnel kset (which depends on the mpls subsystem)
 *	and creates /proc/net/mpls/tunnel entry.
 **/

static int __init mpls_tunnel_init_module(void)
{
	struct mpls_tunnel_private *mtp;
	int retval = -EINVAL;
	MPLS_ENTER;
	mpls_tunnel_dev =
		alloc_netdev(sizeof(struct mpls_tunnel_private),
			"mpls0", mpls_tunnel_setup);
	if (unlikely(!mpls_tunnel_dev)) {
		retval = -ENOMEM;
		goto err;
	}
	retval = register_netdev(mpls_tunnel_dev);
	if (unlikely(retval)) {
		free_netdev(mpls_tunnel_dev);
		goto err;
	}

	mtp = mpls_dev2mtp(mpls_tunnel_dev);
	mtp->mtp_dev = mpls_tunnel_dev;
	mpls_tunnel_key = 1;

	retval = 0;
err:
	MPLS_EXIT;
	return retval;
}

static void __exit mpls_destroy_tunnels(void)
{
	struct net_device *dev;
	struct net_device *ndev;

	MPLS_ENTER;
	for_each_netdev_safe(&init_net, dev, ndev) {
		if (dev->type == ARPHRD_MPLS_TUNNEL)
			unregister_netdev(dev);
	}
	MPLS_EXIT;
}

/**
 *	mpls_tunnel_exit_module - Module unload exit method.
 *
 **/

static void __exit mpls_tunnel_exit_module(void)
{
	MPLS_ENTER;
	mpls_destroy_tunnels();
	MPLS_EXIT;
	return;
}

module_init(mpls_tunnel_init_module);
module_exit(mpls_tunnel_exit_module);
