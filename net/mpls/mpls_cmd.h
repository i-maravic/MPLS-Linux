/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *******************************************************************************/
#ifndef __NET_MPLS_MPLS_CMD_H__
#define __NET_MPLS_MPLS_CMD_H__

#include <net/xfrm.h>
#include <net/dst.h>
#include <net/icmp.h>

#define MPLS_LABEL_EXPLICIT_NULL_IPV4	(0)
#define MPLS_LABEL_ROUTER_ALERT		(1)
#define MPLS_LABEL_EXPLICIT_NULL_IPV6	(2)
#define MPLS_LABEL_IMPLICIT_NULL	(3)
#define MPLS_LABEL_MAX_RESERVED		(15)
#define MPLS_LABEL_MAX_VALID		(0xfffff)

static inline int mpls_is_reserved_label(u32 label)
{
	return label <= MPLS_LABEL_MAX_RESERVED;
}

static inline int mpls_is_valid_label(u32 label)
{
	return label <= MPLS_LABEL_MAX_VALID;
}

static inline struct dst_entry *
nhlfe_get_nexthop_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb)
{
	if (!(nhlfe->flags & MPLS_HAS_NH))
		return NULL;

	return get_route_af(nhlfe->family, nhlfe, net, skb);
}

int strip_mpls_headers(struct sk_buff *skb);
int mpls_ilm_netdev_event(struct notifier_block *this, unsigned long event, void *ptr);
void mpls_dev_sync_net_down(struct net *net);

#endif /* __NET_MPLS_MPLS_CMD_H__ */
