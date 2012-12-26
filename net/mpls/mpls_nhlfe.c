/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_instr.c
 *      - It implements: instruction maintainace
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
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/
#include <linux/skbuff.h>
#include <linux/mpls.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/dst.h>
#include <net/mpls.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/arp.h>
#include <linux/rtnetlink.h>
#include <net/ip_fib.h>
#include <linux/inet.h>
#include <net/net_namespace.h>
#include "mpls_cmd.h"

struct __rcu_object {
	struct rcu_head rcu;
	char data[0];
};

static MPLS_CLEAN_CMD(generic)
{
	struct __rcu_object *ptr =
			(struct __rcu_object *)rtnl_dereference_ulong(elem->data);
	kfree_rcu(ptr, rcu);
}

static MPLS_COMP_CMD(generic)
{
	return lhs->data == rhs->data;
}

/*********************************************************************
 * MPLS_CMD_POP
 *********************************************************************/
static MPLS_BUILD_CMD(pop)
{
	u8 pops = nla_get_u8(instr);
	if (pops < 1)
		return -EINVAL;

	elem->data = *no_pop = pops;
	return 0;
}

static MPLS_DUMP_CMD(pop)
{
	return nla_put_u8(skb, MPLS_ATTR_POP, elem->data);
}

/*********************************************************************
 * MPLS_CMD_PEEK
 *********************************************************************/
static MPLS_BUILD_CMD(peek)
{
	*last_able = 1;
	elem->data = 0;
	return 0;
}

/**
 * MPLS_ATTR_SWAP
 */
static MPLS_BUILD_CMD(swap)
{
	struct mpls_key *tmp = nla_data(instr);
	struct mpls_hdr *push = (struct mpls_hdr *)&elem->data;

	if (tmp->label == 0 || tmp->tc > TC_MAX)
		return -EINVAL;

	push->label_l = htons(tmp->label_l);
	push->label_u = tmp->label_u;
	push->tc = tmp->tc;
	push->ttl = 0;
	push->s = 0;

	return 0;
}


static MPLS_DUMP_CMD(swap)
{
	struct mpls_hdr *push = (struct mpls_hdr *)&elem->data;
	struct mpls_key tmp;

	tmp.label_l = ntohs(push->label_l);
	tmp.label_u = push->label_u;
	tmp.tc = push->tc;

	return nla_put_u32(skb, MPLS_ATTR_SWAP, *(u32 *)&tmp);
}
/*********************************************************************
 * MPLS_CMD_PUSH
 *********************************************************************/
static struct nla_policy push_policy[__MPLS_ATTR_PUSH_MAX] __read_mostly = {
	[MPLS_PUSH_1] = { .type = NLA_U32, },
	[MPLS_PUSH_2] = { .type = NLA_U32, },
	[MPLS_PUSH_3] = { .type = NLA_U32, },
	[MPLS_PUSH_4] = { .type = NLA_U32, },
	[MPLS_PUSH_5] = { .type = NLA_U32, },
	[MPLS_PUSH_6] = { .type = NLA_U32, },
	[MPLS_NO_PUSHES] = { .type = NLA_U8, },
};

static MPLS_BUILD_CMD(push)
{
	u8 pushes = 0;
	struct __push *__push;
	struct nlattr *tb[__MPLS_ATTR_PUSH_MAX];
	int ret;

	ret = nla_parse_nested(tb, MPLS_ATTR_PUSH_MAX, instr, push_policy);
	if (unlikely(ret))
		return ret;

	if (unlikely(!tb[MPLS_NO_PUSHES]))
		return -EINVAL;

	pushes = nla_get_u8(tb[MPLS_NO_PUSHES]);
	if (unlikely(pushes < 1 || pushes > (MPLS_PUSH_MAX - 1)))
		return -EINVAL;

	__push = kzalloc(sizeof(struct __push) +
			pushes * sizeof(struct mpls_hdr), GFP_KERNEL);
	if (unlikely(!__push))
		return -ENOMEM;

	__push->no_push = *no_push = pushes;

	ret = -EINVAL;
	do {
		struct mpls_hdr *push = __push->push;
		struct mpls_key *tmp;
		int i;
		for (i = 0; i < MPLS_PUSH_MAX; i++) {
			if (!tb[i])
				continue;

			tmp = nla_data(tb[i]);

			push->label_l = htons(tmp->label_l);
			push->label_u = tmp->label_u;
			push->tc = tmp->tc;
			push->s = 0;
			push->ttl = 0;

			++push;
			if (unlikely(--pushes < 0))
				goto cleanup;
		}

		if (unlikely(pushes))
			goto cleanup;
	} while(0);

	smp_wmb();
	elem->data = (unsigned long)__push;
	return 0;

cleanup:
	kfree(__push);
	return ret;
}

static MPLS_COMP_CMD(push)
{
	struct __push *__push_lhs =
			(struct __push *)rtnl_dereference_rcu_ulong(lhs->data);
	struct __push *__push_rhs =
			(struct __push *)rtnl_dereference_rcu_ulong(rhs->data);
	int i;
	const u32 *push_lhs, *push_rhs;

	if (__push_lhs->no_push != __push_rhs->no_push)
		return false;

	push_lhs = (const u32 *)__push_lhs->push;
	push_rhs = (const u32 *)__push_rhs->push;
	for (i = MPLS_PUSH_1; i < (__push_lhs->no_push + MPLS_PUSH_1);
			++i, ++push_lhs, ++push_rhs) {
		if (*push_lhs != *push_rhs)
			return false;
	}
	return true;
}

static MPLS_DUMP_CMD(push)
{
	struct __push *__push =
			(struct __push *)rtnl_dereference_rcu_ulong(elem->data);
	int i;
	int ret = 0;
	const struct mpls_hdr *push;
	struct mpls_key req;
	struct nlattr *nest;

	nest = nla_nest_start(skb, MPLS_ATTR_PUSH);
	if (!nest)
		return -EMSGSIZE;

	push = __push->push;
	for (i = MPLS_PUSH_1; i < (__push->no_push + MPLS_PUSH_1); i++) {
		req.label_l = ntohs(push->label_l);
		req.label_u = push->label_u;
		req.tc = push->tc;

		ret = nla_put_u32(skb, i, *(u32 *)&req);
		if (unlikely(ret))
			goto out;

		push++;
	}
	ret = nla_put_u8(skb, MPLS_NO_PUSHES, __push->no_push);
	if (unlikely(ret))
		goto out;

	nla_nest_end(skb, nest);
out:
	return ret;
}

/*********************************************************************
 * MPLS_CMD_SEND_IPv4
 *********************************************************************/
static MPLS_BUILD_CMD(send)
{
	struct __mpls_nh *nh;
	struct mpls_nh *req = nla_data(instr);

	if (elem->cmd == MPLS_ATTR_SEND_IPv4) {
		if (req->ipv4.sin_family != AF_INET ||
				req->ipv4.sin_addr.s_addr == 0)
			return -EINVAL;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (elem->cmd == MPLS_ATTR_SEND_IPv6) {
		if (req->ipv6.sin6_family != AF_INET6 ||
			(req->ipv6.sin6_addr.s6_addr32[0] == 0 &&
				req->ipv6.sin6_addr.s6_addr32[1] == 0 &&
				req->ipv6.sin6_addr.s6_addr32[2] == 0 &&
				req->ipv6.sin6_addr.s6_addr32[3] == 0))
			return -EINVAL;
	}
#endif
	else
		return -EINVAL;

	nh = kzalloc(sizeof(*nh), GFP_KERNEL);
	if (unlikely(!nh))
		return -ENOMEM;

	nh->iface = req->iface;
	if (elem->cmd == MPLS_ATTR_SEND_IPv4)
		nh->ipv4 = req->ipv4;
#if IS_ENABLED(CONFIG_IPV6)
	else
		nh->ipv6 = req->ipv6;
#endif

	smp_wmb();
	elem->data = (unsigned long)nh;
	*last_able = 1;
	return 0;
}

static MPLS_COMP_CMD(send)
{
	struct __mpls_nh *nh_lhs =
			(struct __mpls_nh *)rtnl_dereference_rcu_ulong(lhs->data);
	struct __mpls_nh *nh_rhs =
			(struct __mpls_nh *)rtnl_dereference_rcu_ulong(rhs->data);

	if (nh_lhs->iface != nh_rhs->iface)
		return false;

	if (nh_lhs->ipv4.sin_family == AF_INET) {
		if (memcmp(&nh_lhs->ipv4, &nh_rhs->ipv4, sizeof(nh_rhs->ipv4)))
			return false;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (nh_lhs->ipv4.sin_family == AF_INET6) {
		if (memcmp(&nh_lhs->ipv6, &nh_rhs->ipv6, sizeof(nh_rhs->ipv6)))
			return false;
	}
#endif

	return true;
}

static MPLS_DUMP_CMD(send)
{
	struct __mpls_nh *nh =
			(struct __mpls_nh *)rtnl_dereference_rcu_ulong(elem->data);
	struct mpls_nh req;
	int attrtype;

	req.iface = nh->iface;

	if (nh->ipv4.sin_family == AF_INET) {
		req.ipv4 = nh->ipv4;
		attrtype = MPLS_ATTR_SEND_IPv4;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (nh->ipv4.sin_family == AF_INET6) {
		req.ipv6 = nh->ipv6;
		attrtype = MPLS_ATTR_SEND_IPv6;
	}
#endif
	else
		return -EINVAL;

	return nla_put(skb, attrtype, sizeof(struct mpls_nh), &req);
}

/*********************************************************************
 * MPLS_CMD_SET_TC
 *********************************************************************/
static MPLS_BUILD_CMD(tc_index)
{
#if IS_ENABLED(CONFIG_NET_SCHED)
	elem->data = nla_get_u16(instr);
	return 0;
#else
	return -EINVAL;
#endif
}

static MPLS_DUMP_CMD(tc_index)
{
#if IS_ENABLED(CONFIG_NET_SCHED)
	return nla_put_u16(skb, MPLS_ATTR_TC_INDEX, elem->data);
#else
	return -EINVAL;
#endif
}
/*********************************************************************
 * MPLS_CMD_SET_DS
 *********************************************************************/
static MPLS_BUILD_CMD(dscp)
{
	elem->data = nla_get_u8(instr);
	if (elem->data > DSCP_MAX)
		return -EINVAL;
	return 0;
}

static MPLS_DUMP_CMD(dscp)
{
	return nla_put_u8(skb, MPLS_ATTR_DSCP, elem->data);
}

struct mpls_cmd mpls_cmd[] = {
	[MPLS_ATTR_POP] = {
			.compare = mpls_comp_generic,
			.build = mpls_build_pop,
			.dump = mpls_dump_pop,
	},
	[MPLS_ATTR_DSCP] = {
			.compare = mpls_comp_generic,
			.build = mpls_build_dscp,
			.dump = mpls_dump_dscp,
	},
	[MPLS_ATTR_TC_INDEX] = {
			.compare = mpls_comp_generic,
			.build = mpls_build_tc_index,
			.dump = mpls_dump_tc_index,
	},
	[MPLS_ATTR_PUSH] = {
			.compare = mpls_comp_push,
			.build = mpls_build_push,
			.dump = mpls_dump_push,
			.cleanup = mpls_clean_generic,
	},
	[MPLS_ATTR_SWAP] = {
			.compare = mpls_comp_generic,
			.build = mpls_build_swap,
			.dump = mpls_dump_swap,
	},
	[MPLS_ATTR_PEEK] = {
			.compare = mpls_comp_generic,
			.build = mpls_build_peek,
	},
	[MPLS_ATTR_SEND_IPv4] = {
			.compare = mpls_comp_send,
			.build = mpls_build_send,
			.dump = mpls_dump_send,
			.cleanup = mpls_clean_generic,
	},
	[MPLS_ATTR_SEND_IPv6] = {
			.compare = mpls_comp_send,
			.build = mpls_build_send,
			.dump = mpls_dump_send,
			.cleanup = mpls_clean_generic,
	},
};

static struct nhlfe *
nhlfe_alloc(int length)
{
	struct nhlfe *nhlfe;

	nhlfe = kzalloc(sizeof(struct nhlfe) +
			length * sizeof(struct __instr), GFP_KERNEL);

	if(unlikely(!nhlfe))
		return NULL;

	nhlfe->no_instr = length;
	atomic_set(&nhlfe->refcnt, 1);
	return nhlfe;
}

static inline void
__nhlfe_release(struct __instr *mi)
{
	u16 op = mi->cmd;
	if (mpls_cmd[op].cleanup)
		mpls_cmd[op].cleanup(mi);
}


static void
nhlfe_release(struct nhlfe *nhlfe)
{
	struct __instr *mi;
	int cntr;

	for_each_instr(nhlfe, mi, cntr)
		__nhlfe_release(mi);
}

void
__nhlfe_free(struct nhlfe *nhlfe)
{
	if (likely(nhlfe)) {
		WARN_ON(nhlfe->dead);
		nhlfe->dead = 1;
		nhlfe_release(nhlfe);
		if (likely(atomic_dec_and_test(&nhlfe->refcnt)))
			kfree_rcu(nhlfe, rcu);
	}
}

struct nhlfe *
__nhlfe_build(struct nlattr **instr)
{
	struct nhlfe *nhlfe;
	struct __instr *mi;
	int length = 0;
	u8 last_able = 0;
	int i = 0;
	int ret = -EINVAL;

	/* sanity check */
	if (instr[MPLS_ATTR_PEEK] &&
			(instr[MPLS_ATTR_SWAP] || instr[MPLS_ATTR_PUSH]))
		return ERR_PTR(-EINVAL);

	if (!instr[MPLS_ATTR_INSTR_COUNT])
		return ERR_PTR(-EINVAL);

	length = nla_get_u8(instr[MPLS_ATTR_INSTR_COUNT]);

	nhlfe = nhlfe_alloc(length);
	if (unlikely(!nhlfe))
		return ERR_PTR(-ENOMEM);

	mi = get_instruction(nhlfe, 0);

	for (i = 0; i < MPLS_ATTR_INSTR_MAX; i++) {
		if (!instr[i])
			continue;

		if (unlikely(last_able)) {
			ret = -EINVAL;
			goto rollback;
		}

		mi->cmd = i;
		ret = mpls_cmd[i].build(instr[i], mi, &last_able,
				&nhlfe->no_pop, &nhlfe->no_push);
		if (unlikely(ret)) {
			mi->cmd = 0;
			goto rollback;
		}

		mi++;
		if (unlikely(--length < 0))
			goto rollback;
	}

	/* Make sure the last one was valid */
	if (unlikely(!last_able || length)) {
		ret = -EINVAL;
		goto rollback;
	}

	return nhlfe;

rollback:
	nhlfe->no_instr -= length;
	nhlfe_release(nhlfe);
	kfree(nhlfe);
	return ERR_PTR(ret);
}

bool
nhlfe_instr_eq(const struct nhlfe *lhs, const struct nhlfe *rhs)
{
	const struct __instr *i_lhs, *i_rhs;
	int cntr;

	if (lhs->no_instr != rhs->no_instr)
		return false;

	for (i_lhs = lhs->data, i_rhs = rhs->data, cntr = 0;
			cntr < lhs->no_instr; ++i_rhs, ++i_lhs, ++cntr) {

		if (i_rhs->cmd != i_lhs->cmd)
			return false;

		if (!mpls_cmd[i_rhs->cmd].compare(i_lhs, i_rhs))
			return false;
	}

	return true;
}

int
__nhlfe_dump(const struct nhlfe *nhlfe, struct sk_buff* skb)
{
	int ret = 0;
	if (likely(nhlfe)) {
		struct __instr *mi;
		int cntr = 0;

		for_each_instr(nhlfe, mi, cntr) {
			if (likely(mpls_cmd[mi->cmd].dump))
				ret = mpls_cmd[mi->cmd].dump(skb, mi);
			else
				ret = nla_put_flag(skb, mi->cmd);
			if (unlikely(ret))
				return ret;
		}
		ret = nla_put_u8(skb, MPLS_ATTR_INSTR_COUNT, nhlfe->no_instr);
	} else
		ret = nla_put_u8(skb, MPLS_ATTR_INSTR_COUNT, 0);

	return ret;
}
