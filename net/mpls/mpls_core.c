/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
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
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
****************************************************************************/
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <net/netns/generic.h>
#include <net/snmp.h>
#include <net/mpls.h>
#include "mpls_cmd.h"

MODULE_AUTHOR("Igor Maravic <igorm@etf.rs>, James R. Leu <jleu@mindspring.com>, Ramon Casellas <casellas@infres.enst.fr>");
MODULE_DESCRIPTION("Multi Protocol Label Switching protocol module");
MODULE_LICENSE("GPL");

int sysctl_mpls_default_ttl __read_mostly = MPLS_DEFAULT_TTL;

/**
 * PROC
 */
#if IS_ENABLED(CONFIG_PROC_FS)
static const struct snmp_mib mpls_mib_list[] = {
	SNMP_MIB_ITEM("mplsInterfacePerfInLabelLookupFailures",
		MPLS_MIB_IFINLABELLOOKUPFAILURES),
	SNMP_MIB_ITEM("mplsInterfacePerfOutFragmentedPkts",
		MPLS_MIB_IFOUTFRAGMENTEDPKTS),
	SNMP_MIB_ITEM("mplsInSegmentPerfOctets",
		MPLS_MIB_INOCTETS),
	SNMP_MIB_ITEM("mplsInSegmentPerfPackets",
		MPLS_MIB_INPACKETS),
	SNMP_MIB_ITEM("mplsInSegmentPerfErrors",
		MPLS_MIB_INERRORS),
	SNMP_MIB_ITEM("mplsInSegmentPerfDiscards",
		MPLS_MIB_INDISCARDS),
	SNMP_MIB_ITEM("mplsOutSegmentPerfOctets",
		MPLS_MIB_OUTOCTETS),
	SNMP_MIB_ITEM("mplsOutSegmentPerfPackets",
		MPLS_MIB_OUTPACKETS),
	SNMP_MIB_ITEM("mplsOutSegmentPerfErrors",
		MPLS_MIB_OUTERRORS),
	SNMP_MIB_ITEM("mplsOutSegmentPerfDiscards",
		MPLS_MIB_OUTDISCARDS),
	SNMP_MIB_SENTINEL
};

/* starting at mpls, find the next registered protocol */
static int mpls_stats_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq->private;
	int i;
	for (i = 0; mpls_mib_list[i].name; i++)
		seq_printf(seq, "%-40s\t%lu\n", mpls_mib_list[i].name,
			   snmp_fold_field((void __percpu **)
					   net->mib.mpls_statistics,
					   mpls_mib_list[i].entry));
	return 0;
}

static int mpls_seq_open(struct inode *inode, struct file *file)
{
	return single_open_net(inode, file, mpls_stats_seq_show);
}

static const struct file_operations mpls_stats_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = mpls_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release_net,
};

static int __net_init
mpls_proc_init(struct net *net)
{
	if (!proc_create("mpls_stat", S_IRUGO, net->proc_net, &mpls_stats_seq_fops))
		return -ENOMEM;
	return 0;
}

static void __net_exit
mpls_proc_exit(struct net *net)
{
	remove_proc_entry("mpls_stat", net->proc_net);
}
#endif


/**
 * Sysctl
 */
#if IS_ENABLED(CONFIG_SYSCTL)
int mpls_sysctl_net_id __read_mostly;

static int sysctl_mpls_min_ttl __read_mostly = 1;
static int sysctl_mpls_max_ttl __read_mostly = 255;
static int sysctl_mpls_bool_max __read_mostly = 1;

int sysctl_mpls_propagate_ttl __read_mostly = 1;
int sysctl_mpls_propagate_tc __read_mostly = 1;

static struct ctl_table_header *mpls_table_header;

static struct ctl_table mpls_table[] = {
	{
		.procname = "default_ttl",
		.data = &sysctl_mpls_default_ttl,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = &sysctl_mpls_min_ttl,
		.extra2 = &sysctl_mpls_max_ttl,
	},
	{ }
};

static struct ctl_table mpls_net_table[] = {
	{
		.procname = "propagate_ttl",
		.data = &sysctl_mpls_propagate_ttl,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra2 = &sysctl_mpls_bool_max,
	},
	{
		.procname = "propagate_tc",
		.data = &sysctl_mpls_propagate_tc,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra2 = &sysctl_mpls_bool_max,
	},
	{ }
};

static __net_init int
mpls_sysctl_init_net(struct net *net)
{
	struct ctl_table *table;
	struct mpls_sysctl_net *msn = net_generic(net, mpls_sysctl_net_id);

	table = mpls_net_table;
	if (!net_eq(net, &init_net)) {
		table = kmemdup(table, sizeof(mpls_net_table), GFP_KERNEL);
		if (unlikely(!table))
			return -ENOMEM;

		table[0].data =
			&msn->sysctl_mpls_propagate_ttl;
		table[1].data =
			&msn->sysctl_mpls_propagate_tc;

		msn->sysctl_mpls_propagate_ttl = sysctl_mpls_propagate_ttl;
		msn->sysctl_mpls_propagate_tc = sysctl_mpls_propagate_tc;
	}

	msn->mpls_hdr = register_net_sysctl(net, "net/mpls", table);
	if (unlikely(!msn->mpls_hdr))
		goto err;

	return 0;

err:
	if (!net_eq(net, &init_net))
		kfree(table);
	return -ENOMEM;
}

static __net_exit void
mpls_sysctl_exit_net(struct net *net)
{
	struct ctl_table *table;
	struct mpls_sysctl_net *msn = net_generic(net, mpls_sysctl_net_id);

	table = msn->mpls_hdr->ctl_table_arg;
	unregister_net_sysctl_table(msn->mpls_hdr);
	if (!net_eq(net, &init_net))
		kfree(table);
}

static struct pernet_operations mpls_sysctl_ops = {
	.init = mpls_sysctl_init_net,
	.exit = mpls_sysctl_exit_net,
	.id   = &mpls_sysctl_net_id,
	.size = sizeof(struct mpls_sysctl_net),
};

static int __init mpls_sysctl_init(void)
{
	mpls_table_header = register_net_sysctl(&init_net, "net/mpls", mpls_table);
	if (!mpls_table_header)
		return -ENOMEM;

	if (register_pernet_subsys(&mpls_sysctl_ops)) {
		unregister_sysctl_table(mpls_table_header);
		return -ENOMEM;
	}

	return 0;
}

static void mpls_sysctl_exit(void)
{
	unregister_sysctl_table(mpls_table_header);
	unregister_pernet_subsys(&mpls_sysctl_ops);
}
#else
int __init mpls_sysctl_init(void) { return 0; }
void mpls_sysctl_exit(void) {}
#endif

/**
 * SNMP
 */
static int __net_init mpls_mib_init_net(struct net *net)
{
	int rv = 0;
	if (unlikely(snmp_mib_init((void __percpu **)net->mib.mpls_statistics,
				sizeof(struct mpls_mib), __alignof__(struct mpls_mib)) < 0))
		return -ENOMEM;

#if IS_ENABLED(CONFIG_PROC_FS)
	rv = mpls_proc_init(net);
	if (unlikely(rv < 0))
		snmp_mib_free((void __percpu **)net->mib.mpls_statistics);
#endif
	return rv;
}

static __net_exit void mpls_mib_exit_net(struct net *net)
{
#if IS_ENABLED(CONFIG_PROC_FS)
	mpls_proc_exit(net);
#endif
	snmp_mib_free((void __percpu **)net->mib.mpls_statistics);
}

static struct pernet_operations __net_initdata mpls_mib_ops = {
	.init = mpls_mib_init_net,
	.exit = mpls_mib_exit_net,
};

static int __net_init init_mpls_mibs(void)
{
	return register_pernet_subsys(&mpls_mib_ops);
}

static void __net_exit exit_mpls_mibs(void)
{
	unregister_pernet_subsys(&mpls_mib_ops);
}

static struct packet_type mpls_uc_packet_type = {
	.type = htons(ETH_P_MPLS_UC),
	.func = mpls_recv,
};

static struct notifier_block mpls_ilm_netdev_notifier = {
	.notifier_call = mpls_ilm_netdev_event,
};

static struct mpls_ops __mpls_ops = {
	.mpls_master_dev = __mpls_master_dev,
	.mpls_finish_send = __mpls_finish_send,
	.nhlfe_build	= __nhlfe_build,
	.nhlfe_free_rcu	= __nhlfe_free_rcu,
	.nhlfe_free	= __nhlfe_free,
	.nhlfe_dump	= __nhlfe_dump,
	.nhlfe_send	= __nhlfe_send,
	.nhlfe_policy	= __nhlfe_policy
};

static int __init mpls_init_module(void)
{
	int err;

	/* Assert if struct mpls_skb_cb is of correct size */
	BUILD_BUG_ON(sizeof(struct mpls_skb_cb) > sizeof(((struct sk_buff *)0)->cb));

	printk(KERN_INFO "MPLS: version %d.%d%d%d\n",
			(MPLS_LINUX_VERSION >> 24) & 0xFF,
			(MPLS_LINUX_VERSION >> 16) & 0xFF,
			(MPLS_LINUX_VERSION >> 8) & 0xFF,
			(MPLS_LINUX_VERSION) & 0xFF);

	err = ilm_init();
	if (unlikely(err))
		goto err;

	err = mpls_dev_init();
	if (unlikely(err))
		goto cleanup_ilm;

	err = mpls_sysctl_init();
	if (unlikely(err))
		goto cleanup_dev;

	err = init_mpls_mibs();
	if (unlikely(err))
		goto cleanup_sysctl;

	err = register_netdevice_notifier(&mpls_ilm_netdev_notifier);
	if (unlikely(err))
		goto cleanup_mibs;

	dev_add_pack(&mpls_uc_packet_type);
	mpls_ops = &__mpls_ops;

	return 0;

cleanup_mibs:
	exit_mpls_mibs();
cleanup_sysctl:
	mpls_sysctl_exit();
cleanup_dev:
	mpls_dev_exit();
cleanup_ilm:
	ilm_exit();
err:
	return err;
}

static void __exit mpls_exit_module(void)
{
	dev_remove_pack(&mpls_uc_packet_type);
	unregister_netdevice_notifier(&mpls_ilm_netdev_notifier);
	exit_mpls_mibs();
	mpls_sysctl_exit();
	ilm_exit();
	mpls_dev_exit();
	mpls_ops = NULL;

	synchronize_net();
}

module_init(mpls_init_module);
module_exit(mpls_exit_module);
MODULE_ALIAS("mpls");
MODULE_ALIAS_RTNL_LINK("mpls");
