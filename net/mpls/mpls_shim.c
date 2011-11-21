/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *			Igor Maravić     <igorm@etf.rs> 
 *
 *   (c) 1999-2005   James Leu        <jleu@mindspring.com>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 ****************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <net/shim.h>
#include <net/mpls.h>

/**
 *	mpls_set_nexthop2
 *	@nhlfe: the nhlfe object to apply to the dst
 *	@dst: dst_entry
 *
 *	Called from outside the MPLS subsystem.
 **/
inline int mpls_set_nexthop2(struct mpls_nhlfe *nhlfe, struct dst_entry *dst)
{
	MPLS_ENTER;

	dst_metric_set(dst, RTAX_MTU, dst_mtu(&nhlfe->dst));
	dst->child = dst_clone(&nhlfe->dst);
	dst->header_len = nhlfe->dst.header_len;

	MPLS_DEBUG("nhlfe: %p mtu: %d dst: %p\n", nhlfe, dst_mtu(&nhlfe->dst),
			dst);

	MPLS_EXIT;
	return 0;
}
EXPORT_SYMBOL(mpls_set_nexthop2);

/**
 *	mpls_set_nexthop
 *	@shim:holds the key to look up the NHLFE object to apply.
 *	@dst: dst_entry
 *
 *	Called from outside the MPLS subsystem.
 **/
inline int mpls_set_nexthop(struct shim_blk *sblk, struct dst_entry *dst)
{
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key;
	int ret;

	MPLS_ENTER;

	memcpy(&key, sblk->data, sizeof(key));
	nhlfe = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_EXIT;
		return -ENXIO;
	}

	ret = mpls_set_nexthop2(nhlfe, dst);
	mpls_nhlfe_release(nhlfe);
	MPLS_EXIT;
	return ret;
}
EXPORT_SYMBOL(mpls_set_nexthop);

/**
 *	mpls_uc_shim - "SPECIAL" next hop Management for MPLS UC traffic.
 *	@name: name of the struct.
 *	@build: Callback used to build
 *
 *	e.g. for a MPLS enabled iproute2:
 *	ip route add a.b.c.d/n via x.y.z.w shim mpls 0x2
 *	The key (0x2) is the "data" for NHLFE lookup.
 **/
struct shim mpls_uc_shim = {
	.name = "mpls",
	.build = mpls_set_nexthop,
};
EXPORT_SYMBOL(mpls_uc_shim);
