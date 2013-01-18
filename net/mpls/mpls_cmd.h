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
#include <net/dsfield.h>
#include <net/route.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/dst.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/icmpv6.h>
#include <net/ip6_route.h>
#endif

#define MPLS_LABEL_EXPLICIT_NULL_IPV4	0
#define MPLS_LABEL_ROUTER_ALERT		1
#define MPLS_LABEL_EXPLICIT_NULL_IPV6	2
#define MPLS_LABEL_IMPLICIT_NULL	3
#define MPLS_LABEL_MAX_RESERVED		15
#define MPLS_LABEL_MAX_VALID		0xfffff

static inline int mpls_is_reserved_label(u32 label)
{
	return label <= MPLS_LABEL_MAX_RESERVED;
}

static inline int mpls_is_valid_label(u32 label)
{
	return label <= MPLS_LABEL_MAX_VALID;
}

#define MAX_HDR_ARRAY_SIZE (10 * MPLS_HDR_LEN)

struct mpls_hdr_payload {
	u8 data[MAX_HDR_ARRAY_SIZE]; /* data must be first */
	__be32 daddr[4];
	const struct nhlfe *nhlfe;
	struct net_device *dev;
	u8 data_len;
};

#define __dscp_to_tc(_tos) ((_tos) >> 5)
#define __tc_to_dscp(_tc) ((_tc) << 5)

struct dst_entry *nhlfe_get_nexthop_dst(const struct nhlfe *nhlfe, struct net *net, struct sk_buff *skb);
bool __push_mpls_hdr_payload(struct sk_buff *skb, const struct mpls_hdr_payload *payload);
int strip_mpls_headers(struct sk_buff *skb, struct mpls_hdr_payload *payload);
int mpls_send_mpls_ipv4(struct sock *sk, struct flowi4 *fl4, void *extra);
int nhlfe_send(const struct nhlfe *nhlfe, struct sk_buff *skb);

#endif /* __NET_MPLS_MPLS_CMD_H__ */
