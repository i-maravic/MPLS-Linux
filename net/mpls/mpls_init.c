/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
****************************************************************************/
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <net/dst.h>
#include <net/mpls.h>
#include <net/ip.h>

/**
 * variables controled via sysctl
 **/
#ifdef CONFIG_MPLS_DEBUG
#define MPLS_DEBUG_SYS 1
#else
#define MPLS_DEBUG_SYS 0
#endif

int sysctl_mpls_debug = MPLS_DEBUG_SYS;
EXPORT_SYMBOL(sysctl_mpls_debug);

int sysctl_mpls_default_ttl = 255;
EXPORT_SYMBOL(sysctl_mpls_default_ttl);

/**
 * MODULE Information and attributes
 **/

MODULE_AUTHOR("James R. Leu <jleu@mindspring.com>, Ramon Casellas <casellas@infres.enst.fr>");
MODULE_DESCRIPTION("MultiProtocol Label Switching protocol");
MODULE_LICENSE("GPL");

/*****
 * Packet Type for MPLS Unicast Traffic register info.
 *
 **/

static struct packet_type mpls_uc_packet_type = {
	.type = cpu_to_be16(ETH_P_MPLS_UC), /* MPLS Unicast PID */
	.func = mpls_skb_recv,
};

/**
 *	mpls_release_netdev_in_nhlfe - Release the held device if it goes down.
 *	@dev: network device (for which the notification is sent).
 *
 *	NHLFE objects hold a reference to the used outgoing device in the SET op
 *	data. When the MPLS subsystem is notified that a device is going down
 *	or unregistered, this function destroys the instructions for those NHLFE
 **/

static int mpls_release_netdev_in_nhlfe(struct net_device *dev)
{
	struct mpls_interface *mif = dev->mpls_ptr;
	struct list_head *pos = NULL;
	struct list_head *tmp = NULL;
	struct mpls_nhlfe *holder;
	MPLS_ENTER;
	BUG_ON(!mif);
	/* Iterate all NHLFE objects present in the list_out of the interface.*/
	list_for_each_safe(pos, tmp, &mif->list_out) {

		/* Get the holder / owner NHLFE */
		holder = list_entry(pos, struct mpls_nhlfe , dev_entry);

		/* Destroy the nhlfe entry */
		mpls_del_nhlfe(holder, 0, 0);
		list_del(pos);
	}

	MPLS_EXIT;
	return NOTIFY_DONE;
}



/**
 *	mpls_change_mtu_nhlfe - Changes nhlfe's mtu dev's changed mtu
 *	@dev: network device (for which the notification is sent).
 *
 *
 **/

static int mpls_change_mtu_nhlfe(struct net_device *dev)
{
	struct mpls_interface *mif = dev->mpls_ptr;
	struct list_head *pos = NULL;
	struct list_head *tmp = NULL;
	struct mpls_nhlfe *holder;
	MPLS_ENTER;
	BUG_ON(!mif);
	/* Iterate all NHLFE objects present in the list_out of the interface.*/
	list_for_each_safe(pos, tmp, &mif->list_out) {

		/* Get the holder / owner NHLFE */
		holder = list_entry(pos, struct mpls_nhlfe , dev_entry);

		/* Change the mtu for nhlfe*/
		mpls_nhlfe_update_mtu(holder, dev->mtu);
	}

	MPLS_EXIT;
	return NOTIFY_DONE;
}


/**
 *	mpls_netdev_event - Netdevice notifier callback.
 *	@this: block notifier used.
 *	@event:  UP/DOWN, REGISTER/UNREGISTER...
 *	@ptr: (struct net_device*)
 *	Receives events for the interfaces
 *
 **/

static int mpls_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	MPLS_ENTER;

	/*
	 * Only continue for MPLS enabled interfaces
	 */

	switch (event) {
	case NETDEV_REGISTER:
		mpls_initialize_dev(dev);
		if (!dev->mpls_ptr)
			return notifier_from_errno(-ENOMEM);
		break;
	case NETDEV_UNREGISTER:
		mpls_release_netdev_in_nhlfe(dev);
		mpls_clear_dev(dev);
		break;
	case NETDEV_DOWN:
		mpls_release_netdev_in_nhlfe(dev);
		break;
	case NETDEV_CHANGEMTU:
		mpls_change_mtu_nhlfe(dev);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		break;
	}
	MPLS_EXIT;
	return NOTIFY_DONE;
}

/**
 * Netdevice notifier callback register info
 *
 **/
static struct notifier_block mpls_netdev_notifier = {
	.notifier_call = mpls_netdev_event,
};

static int __net_init mpls_mib_init_net(struct net *net)
{
	int rv = 0;
	if (snmp_mib_init((void __percpu **)net->mib.mpls_statistics,
		sizeof(struct mpls_mib), __alignof__(struct mpls_mib)) < 0)
			return -ENOMEM;

#ifdef CONFIG_PROC_FS
	rv = mpls_proc_init(net);
	if (rv < 0)
		snmp_mib_free((void __percpu **)net->mib.mpls_statistics);
#endif
	return rv;
}

static __net_exit void mpls_mib_exit_net(struct net *net)
{
#ifdef CONFIG_PROC_FS
	mpls_proc_exit(net);
#endif
	snmp_mib_free((void __percpu **)net->mib.mpls_statistics);
}

static struct pernet_operations __net_initdata mpls_mib_ops = {
	.init = mpls_mib_init_net,
	.exit = mpls_mib_exit_net,
};

static int __init init_mpls_mibs(void)
{
	return register_pernet_subsys(&mpls_mib_ops);
}

static void exit_mpls_mibs(void)
{
	unregister_pernet_subsys(&mpls_mib_ops);
}

/**
 * MPLS Module entry point.
 **/

static int __init mpls_init_module(void)
{
	int err;
	MPLS_ENTER;
	printk(KERN_INFO "MPLS: version %d.%d%d%d\n",
		(MPLS_LINUX_VERSION >> 24) & 0xFF,
		(MPLS_LINUX_VERSION >> 16) & 0xFF,
		(MPLS_LINUX_VERSION >> 8) & 0xFF,
		(MPLS_LINUX_VERSION) & 0xFF);
	
	mpls_shim_init();
	/* Init instruction cache */
	err = mpls_instr_init();
	if (err)
		return err;

	/* Init Input Radix Tree */
	err = mpls_ilm_init();
	if (err)
		goto cleanup_instr;

	/* Init Output Radix Tree */
	err = mpls_nhlfe_init();
	if (err)
		goto cleanup_ilm;

#ifdef CONFIG_SYSCTL
	err = mpls_sysctl_init();
	if (err)
		goto cleanup_nhlfe;

#endif
	/* Netlink configuration interface */
	err = mpls_netlink_init();
	if (err)
		goto cleanup_sysctl;

	err = init_mpls_mibs();
	if (err) {
		printk(KERN_CRIT "mpls_init_module: Cannot init mpls mibs\n");
		goto cleanup_mib;
	}

	/* packet handlers, and netdev notifier */
	dev_add_pack(&mpls_uc_packet_type);
	err = register_netdevice_notifier(&mpls_netdev_notifier);
	if (err)
		goto cleanup_all;

	MPLS_EXIT;
	return 0;
cleanup_all:
	dev_remove_pack(&mpls_uc_packet_type);
	mpls_netlink_exit();
cleanup_mib:
	exit_mpls_mibs();
cleanup_sysctl:
#ifdef CONFIG_SYSCTL
	mpls_sysctl_exit();
#endif
cleanup_nhlfe:
	mpls_nhlfe_exit();
cleanup_ilm:
	mpls_ilm_exit();
cleanup_instr:
	mpls_instr_exit();
	mpls_shim_exit();
	MPLS_EXIT;
	return err;
}

/**
 *	mpls_exit_module - Module Exit Cleanup Routine
 *
 *	mpls_exit_module is called just before the module is removed
 *	from memory.
 **/

static void __exit mpls_exit_module(void)
{
	MPLS_ENTER;
	unregister_netdevice_notifier(&mpls_netdev_notifier);
	dev_remove_pack(&mpls_uc_packet_type);
	mpls_netlink_exit();
	exit_mpls_mibs();
#ifdef CONFIG_SYSCTL
	mpls_sysctl_exit();
#endif
	mpls_nhlfe_exit();
	mpls_ilm_exit();
	mpls_instr_exit();
	mpls_shim_exit();

	synchronize_net();

	printk(KERN_INFO "MPLS: version %d.%d%d%d exiting\n",
		(MPLS_LINUX_VERSION >> 24) & 0xFF,
		(MPLS_LINUX_VERSION >> 16) & 0xFF,
		(MPLS_LINUX_VERSION >> 8) & 0xFF,
		(MPLS_LINUX_VERSION & 0xFF));
	MPLS_EXIT;
}

module_init(mpls_init_module);
module_exit(mpls_exit_module);
