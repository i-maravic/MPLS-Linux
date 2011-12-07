/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_proto.c: MPLS Proto management
 *
 * Copyright (C) David S. Miller (davem@redhat.com),
 *		 James R. Leu (jleu@mindspring.com)
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *****************************************************************************/

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <net/mpls.h>

static DEFINE_SPINLOCK(mpls_proto_lock);
LIST_HEAD(mpls_proto_list);

int mpls_proto_add(struct mpls_prot_driver *proto)
{
	MPLS_ENTER;
	spin_lock_bh(&mpls_proto_lock);

	list_add_rcu(&proto->list, &mpls_proto_list);

	spin_unlock_bh(&mpls_proto_lock);
	MPLS_EXIT;
	return 0;
}
EXPORT_SYMBOL(mpls_proto_add);

int mpls_proto_remove(struct mpls_prot_driver *proto)
{
	struct mpls_prot_driver *proto1 = NULL;
	int retval = -EPROTONOSUPPORT;
	MPLS_ENTER;
	spin_lock_bh(&mpls_proto_lock);

	list_for_each_entry(proto1, &mpls_proto_list, list) {
		if (proto == proto1) {
			if (atomic_read(&proto->__refcnt) > 0)
				retval = -EADDRINUSE;
			else {
				list_del_rcu(&proto->list);
				retval = 0;
			}
			break;
		}
	}
	spin_unlock_bh(&mpls_proto_lock);

	synchronize_net();
	MPLS_EXIT;
	return retval;
}
EXPORT_SYMBOL(mpls_proto_remove);

static int mpls_proto_hold(struct mpls_prot_driver *prot)
{
	/* Take reference on protocol module */
	if (!try_module_get(prot->owner))
		return -1;
	atomic_inc(&prot->__refcnt);
	return 0;
}

struct mpls_prot_driver *mpls_proto_find_by_family(unsigned short fam)
{
	struct mpls_prot_driver *proto = NULL;
	MPLS_ENTER;
	rcu_read_lock();
	list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
		if (fam == proto->family) {
			if (mpls_proto_hold(proto))
				proto = NULL;
			goto out;
		}
	}
	proto = NULL;
out:
	rcu_read_unlock();
	MPLS_EXIT;
	return proto;
}

struct mpls_prot_driver *mpls_proto_find_by_ethertype(unsigned short type)
{
	struct mpls_prot_driver *proto = NULL;
	MPLS_ENTER;
	rcu_read_lock();
	list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
		if (type == proto->ethertype) {
			if (mpls_proto_hold(proto))
				proto = NULL;
			goto out;
		}
	}
	proto = NULL;
out:
	rcu_read_unlock();
	MPLS_EXIT;
	return proto;
}
EXPORT_SYMBOL(mpls_proto_find_by_ethertype);

void mpls_proto_cache_flush_all(struct net *net)
{
	struct mpls_prot_driver *proto = NULL;
	MPLS_ENTER;
	rcu_read_lock();
	list_for_each_entry_rcu(proto, &mpls_proto_list, list) {
		proto->cache_flush(net);
	}
	rcu_read_unlock();
	MPLS_EXIT;
}
EXPORT_SYMBOL(mpls_proto_cache_flush_all);
