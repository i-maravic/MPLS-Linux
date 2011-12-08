/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 *      Network mpls interface for protocols that live below L3 and above L2
 *
 *      Heavily borrowed from dev_remove_pack/dev_add_pack
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *			Igor Maravić	 <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/mpls.h>
#include <net/snmp.h>
#include <net/ip.h>

/*
 * The following few functions build the content of /proc/net/mpls
 */

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

int __net_init mpls_proc_init(struct net *net)
{
	if (!proc_net_fops_create(net, "mpls_stat",  S_IRUGO,
			&mpls_stats_seq_fops)) {
		printk(KERN_ERR "MPLS: failed to register with procfs\n");
		return -ENOMEM;
	}
	return 0;
}

void mpls_proc_exit(struct net *net)
{
	proc_net_remove(net, "mpls_stat");
}
