/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_export.c
 *      - It implements: structures and functions that
 *                       are exported to other modules
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

#include <net/mpls.h>
#include <linux/export.h>
#include <linux/mutex.h>

const struct mpls_ops *mpls_ops __read_mostly = NULL;
EXPORT_SYMBOL(mpls_ops);

static DEFINE_MUTEX(mpls_afinfo_mutex);

const struct mpls_afinfo __rcu *mpls_afinfo[MPLSPROTO_MAX] __read_mostly;
EXPORT_SYMBOL(mpls_afinfo);

int mpls_register_afinfo(const struct mpls_afinfo *afinfo)
{
	int err;

	err = mutex_lock_interruptible(&mpls_afinfo_mutex);
	if (err < 0)
		return err;
	RCU_INIT_POINTER(mpls_afinfo[afinfo->family], afinfo);
	mutex_unlock(&mpls_afinfo_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(mpls_register_afinfo);

void mpls_unregister_afinfo(const struct mpls_afinfo *afinfo)
{
	mutex_lock(&mpls_afinfo_mutex);
	RCU_INIT_POINTER(mpls_afinfo[afinfo->family], NULL);
	mutex_unlock(&mpls_afinfo_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(mpls_unregister_afinfo);
