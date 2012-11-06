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
 * ****************************************************************************/

#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/in.h>		/* must be before route.h */
#include <linux/ip.h>		/* must be before route.h */
#include <linux/inetdevice.h>	/* must be before route.h */
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/mpls.h>
#include "mpls_cmd.h"

static int ilm_net_id __read_mostly;
struct ilm_net {
	struct radix_tree_root ilm_tree;
	struct hlist_head ilm_list;
};

struct ilm_head {
	struct rcu_head rcu;
	struct hlist_head list;
};

const struct {
	struct nhlfe nhlfe;
	struct __instr instr[2];
} pop_peek_nhlfe = {
	.nhlfe = {
		.no_instr = 2,
		.no_push = 0,
		.no_pop = 1,
	},
	.instr = {
		{
			.data = 1,
			.cmd = MPLS_ATTR_POP,
		},
		{
			.data = 0,
			.cmd = MPLS_ATTR_PEEK,
		},
	},
};

const static struct ilm
ipv4_explicit_null =
{
		.key = {
			.label = 0x0,
		},
		.owner = RTPROT_BOOT,
		.nhlfe = (struct nhlfe *)&pop_peek_nhlfe.nhlfe,
};

const static struct ilm
ipv6_explicit_null =
{
		.key = {
			.label = 0x2,
		},
		.owner = RTPROT_BOOT,
		.nhlfe = (struct nhlfe *)&pop_peek_nhlfe.nhlfe,
};

const struct ilm *
mpls_reserved[MAX_RES_LABEL] = {
	&ipv4_explicit_null,	/* IPv4 EXPLICIT NULL */
	NULL,			/* ROUTER ALERT - unimplemented */
	&ipv6_explicit_null,	/* IPv6 EXPLICIT NULL */
	NULL,			/* IMPLICIT NULL */
};

#define __is_reserved_label(key) ((key)->label <= MAX_RES_LABEL)

static const struct ilm *
get_ilm_input(const struct mpls_key *key, u8 tc, const struct net *net);

static int
mpls_forward(struct sk_buff *skb, const struct nhlfe *nhlfe)
{
	const struct __instr *mi;
	struct dst_entry *dst = NULL;
	int ret;
	unsigned int mpls_headroom =
			(nhlfe->no_push > nhlfe->no_pop) ? (nhlfe->no_push - nhlfe->no_pop) * MPLS_HDR_LEN : 0;

	if (skb_cow_head(skb, mpls_headroom) < 0)
		goto out_discard;

	mi = get_first_instruction(nhlfe);

	if (mi->cmd == MPLS_ATTR_POP) {
		ret = mpls_pop(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_DSCP) {
		ret = mpls_dscp(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_TC_INDEX) {
		ret = mpls_tc_index(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
	}

	if (mi->cmd == MPLS_ATTR_SWAP) {
		ret = mpls_swap(skb, mi++);
		if (unlikely(ret))
			goto free_skb;

		if (mi->cmd != MPLS_ATTR_PUSH)
			goto send;
		else
			goto push;
	}

	if (mi->cmd == MPLS_ATTR_PUSH) {
push:
		ret = mpls_push(skb, mi++);
		if (unlikely(ret))
			goto free_skb;
		goto send;
	}

	if (mi->cmd == MPLS_ATTR_PEEK) {
		ret = mpls_peek(skb, mi);
		goto free_skb;
	}

send:
	if (mi->cmd == MPLS_ATTR_SEND_IPv4) {
		dst = mpls_get_dst_ipv4(skb, mi);
		if (!dst)
			goto free_skb;

send_common:
		__mpls_set_dst(skb, dst);

		ret = decrement_ttl(skb);
		if (unlikely(ret))
			goto free_skb;

		ret = mpls_send(skb, mi);
		goto end;
	}

	if (mi->cmd == MPLS_ATTR_SEND_IPv6) {
		dst = mpls_get_dst_ipv6(skb, mi);
		if (!dst)
			goto free_skb;

		goto send_common;
	}

out_discard:
	ret = -NET_XMIT_DROP;
	MPLS_INC_STATS(dev_net(skb->dev), MPLS_MIB_OUTDISCARDS);
free_skb:
	if (unlikely(ret))
		dev_kfree_skb(skb);
end:
	return ret;
}

static inline int
mpls_input(struct sk_buff *skb, struct net_device *dev, const struct mpls_key *key)
{
	const struct ilm *ilm;
	int ret = NET_RX_DROP;
	struct mpls_skb_cb *cb = MPLSCB(skb);

	rcu_read_lock();
	ilm = get_ilm_input(key, cb->hdr.tc, dev_net(skb->dev));
	if (unlikely(!(ilm && ilm->nhlfe))) {
		rcu_read_unlock();
		MPLS_INC_STATS_BH(dev_net(dev),
			MPLS_MIB_IFINLABELLOOKUPFAILURES);
		goto mpls_input_drop;
	}

	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INPACKETS);
	MPLS_ADD_STATS_BH(dev_net(dev), MPLS_MIB_INOCTETS, skb->len);

	ret = mpls_forward(skb, ilm->nhlfe);
	rcu_read_unlock();
	return ret;

mpls_input_drop:
	kfree_skb(skb);

	return ret;
}

/* Main receiving function */
int
mpls_recv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig)
{
	struct mpls_skb_cb *cb;
	struct mpls_key key;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto mpls_rcv_drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto mpls_rcv_err;

	if (!pskb_may_pull(skb, MPLS_HDR_LEN))
		goto mpls_rcv_err;

	cb = MPLSCB(skb);

	label_entry_peek(skb);

	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_TUNNEL:
	case ARPHRD_TUNNEL6:
	case ARPHRD_IEEE802:
	case ARPHRD_PPP:
	case ARPHRD_LOOPBACK:
	case ARPHRD_HDLC:
	case ARPHRD_IPGRE:
		key.label_l = ntohs(cb->hdr.label_l);
		key.label_u = cb->hdr.label_u;
		break;
	default:
		goto mpls_rcv_err;
	}

	return mpls_input(skb, dev, &key);

mpls_rcv_out:
	kfree_skb(skb);
	return NET_RX_DROP;

mpls_rcv_err:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INDISCARDS);
	goto mpls_rcv_out;

mpls_rcv_drop:
	MPLS_INC_STATS_BH(dev_net(dev), MPLS_MIB_INERRORS);
	goto mpls_rcv_out;
}

static inline void
__destroy_ilm_instrs(struct ilm *ilm)
{
	nhlfe_free(ilm->nhlfe);
	rcu_assign_pointer(ilm->nhlfe, NULL);
}

static struct ilm *
ilm_alloc(const struct mpls_key *key, u8 tc, u8 owner, struct nhlfe *nhlfe)
{
	struct ilm *ilm;

	ilm = kzalloc(sizeof(struct ilm), GFP_KERNEL);

	if (unlikely(!ilm))
		return NULL;

	INIT_HLIST_NODE(&ilm->global);
	INIT_HLIST_NODE(&ilm->tc_list);

	ilm->key = *key;
	ilm->tc = tc;
	ilm->owner = owner;
	rcu_assign_pointer(ilm->nhlfe, nhlfe);

	return ilm;
}

static int
ilm_set_nhlfe(struct ilm *ilm, struct nlattr **instr)
{
	struct nhlfe *nhlfe = NULL;
	struct nhlfe *old_nhlfe = NULL;

	old_nhlfe = rtnl_dereference(ilm->nhlfe);

	nhlfe = nhlfe_build(instr);
	if (IS_ERR(nhlfe))
		return PTR_ERR(nhlfe);

	rcu_assign_pointer(ilm->nhlfe, nhlfe);
	nhlfe_free(old_nhlfe);

	return 0;
}

static int
insert_ilm(const struct mpls_key *key, struct ilm *new_ilm, const struct net* net)
{
	int retval = 0;
	struct ilm_head *tc_head;
	struct hlist_node *node;
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
#ifdef CONFIG_PROVE_RCU
	WARN_ON_ONCE(!(lockdep_rtnl_is_held()));
#endif
	tc_head = radix_tree_lookup(&ilmn->ilm_tree, *(u32 *)key);
	if (likely(!tc_head)) {
		tc_head = kzalloc(sizeof(struct ilm_head), GFP_KERNEL);
		if (unlikely(!tc_head))
			return -ENOMEM;

		retval = radix_tree_insert(&ilmn->ilm_tree, *(u32 *)key, tc_head);
		if (unlikely(retval)) {
			kfree(tc_head);
			goto out;
		}
	}

	if (likely(hlist_empty(&tc_head->list)))
		hlist_add_head_rcu(&new_ilm->tc_list, &tc_head->list);
	else {
		struct ilm* ilm = NULL, *last = NULL;

		hlist_for_each_entry_rcu(ilm, node, &tc_head->list, tc_list) {
			if (ilm->tc < new_ilm->tc)
				break;
			last = ilm;
		}
		if (last)
			hlist_add_after_rcu(&last->tc_list, &new_ilm->tc_list);
		else
			hlist_add_before_rcu(&new_ilm->tc_list, &ilm->tc_list);
	}

	if (hlist_empty(&ilmn->ilm_list))
		hlist_add_head_rcu(&new_ilm->global, &ilmn->ilm_list);
	else {
		struct ilm* ilm = NULL, *last = NULL;

		hlist_for_each_entry_rcu(ilm, node, &ilmn->ilm_list, global) {
			if (*(u32 *)(&ilm->key) < *(u32 *)(&new_ilm->key))
				break;
			if (*(u32 *)(&ilm->key) == *(u32 *)(&new_ilm->key) &&
					ilm->tc < new_ilm->tc)
				break;
			last = ilm;
		}
		if (last)
			hlist_add_after_rcu(&last->global, &new_ilm->global);
		else
			hlist_add_before_rcu(&new_ilm->global, &ilm->global);
	}

out:
	return retval;
}

static void
remove_ilm(struct ilm *ilm, const struct net *net)
{
	struct ilm_head *tc_head;
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
#ifdef CONFIG_PROVE_RCU
	WARN_ON_ONCE(!(lockdep_rtnl_is_held()));
#endif
	hlist_del_rcu(&ilm->global);
	hlist_del_rcu(&ilm->tc_list);

	tc_head = radix_tree_lookup(&ilmn->ilm_tree, *(u32 *)&ilm->key);
	if (unlikely(!tc_head)) {
		WARN_ON(!tc_head);
		return;
	}

	if (hlist_empty(&tc_head->list)) {
		radix_tree_delete(&ilmn->ilm_tree, *(u32 *)&ilm->key);
		kfree_rcu(tc_head, rcu);
	}
}

static struct ilm *
get_ilm(const struct mpls_key *key, u8 tc, const struct net *net)
{
	struct ilm *ilm = NULL;
	struct ilm_head *tc_head;
	struct hlist_node *node;
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
#ifdef CONFIG_PROVE_RCU
	WARN_ON_ONCE(!(lockdep_rtnl_is_held() || rcu_read_lock_held()));
#endif
	tc_head = radix_tree_lookup(&ilmn->ilm_tree, *(u32 *)key);
	if (unlikely(!tc_head))
		return NULL;

	hlist_for_each_entry_rcu(ilm, node, &tc_head->list, tc_list) {
		if (ilm->tc == tc)
			return ilm;
	}
	return NULL;
}

static inline const struct ilm *
__get_ilm(const struct mpls_key *key, u8 tc, const struct net *net)
{
	struct ilm *ilm = NULL;
	struct ilm_head *tc_head;
	struct hlist_node *node;
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
#ifdef CONFIG_PROVE_RCU
	WARN_ON_ONCE(!(lockdep_rtnl_is_held() || rcu_read_lock_held()));
#endif
	tc_head = radix_tree_lookup(&ilmn->ilm_tree, *(u32 *)key);
	if (unlikely(!tc_head))
		return NULL;

	hlist_for_each_entry_rcu(ilm, node, &tc_head->list, tc_list) {
		if (!ilm->tc || ilm->tc == tc)
			return ilm;
	}
	return NULL;
}

static const struct ilm *
get_ilm_input(const struct mpls_key *key, u8 tc, const struct net *net)
{
	const struct ilm *ilm = NULL;

	/* handle the reserved label range */
	if (__is_reserved_label(key)) {
		ilm = mpls_reserved[key->label];

		if (unlikely(!ilm))
			return NULL;
	} else
		ilm = __get_ilm(key, tc, net);

	return ilm;
}

static struct ilm *
add_ilm(struct ilmsg *ilm_msg, struct nlattr **instr, const struct net *net)
{
	struct ilm *ilm;
	struct nhlfe *nhlfe;
	const struct mpls_key *key = &ilm_msg->key;
	u8 tc = ilm_msg->tc;
	u8 owner = ilm_msg->owner;
	int ret;

	if (__is_reserved_label(key))
		return ERR_PTR(-EINVAL);

	ilm = get_ilm(key, tc, net);
	if (unlikely(ilm))
		return ERR_PTR(-EEXIST);

	nhlfe = nhlfe_build(instr);
	if (IS_ERR(nhlfe))
		return (struct ilm *)nhlfe;

	ilm = ilm_alloc(key, tc, owner, nhlfe);
	if (unlikely(!ilm))
		return ERR_PTR(-ENOMEM);

	ret = insert_ilm(key, ilm, net);
	if (unlikely(ret)) {
		kfree(ilm);
		return ERR_PTR(ret);
	}

	return ilm;
}

static void
destroy_ilm(struct ilm *ilm, const struct net *net)
{
	remove_ilm(ilm, net);
	__destroy_ilm_instrs(ilm);
	kfree_rcu(ilm, rcu);
}

static int
del_ilm(struct ilmsg *in, const struct net *net)
{
	struct ilm *ilm;

	ilm = get_ilm(&in->key, in->tc, net);
	if (unlikely(!ilm))
		return -ESRCH;

	destroy_ilm(ilm, net);
	return 0;
}

static struct nla_policy ilm_policy[__MPLS_ATTR_MAX] __read_mostly = {
	[MPLS_ATTR_POP] = { .type = NLA_U8, },
	[MPLS_ATTR_DSCP] = { .type = NLA_U8 },
	[MPLS_ATTR_TC_INDEX] = { .type = NLA_U16, },
	[MPLS_ATTR_SWAP] = { .type = NLA_U32, },
	[MPLS_ATTR_PUSH] = { .type = NLA_NESTED, },
	[MPLS_ATTR_PEEK] = { .type = NLA_FLAG, },
	[MPLS_ATTR_SEND_IPv4] = { .len = sizeof(struct mpls_nh), },
	[MPLS_ATTR_SEND_IPv6] = { .len = sizeof(struct mpls_nh), },
	[MPLS_ATTR_INSTR_COUNT] = { .type = NLA_U8, },
};

static int
ilm_event(int event, const struct ilmsg *req, struct net *net, int pid, int seq)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct ilmsg *ilm_msg;
	int err;

	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	err = -EMSGSIZE;
	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ilm_msg), 0);
	if (!nlh)
		goto nlmsg_failure;

	ilm_msg = nlmsg_data(nlh);
	ilm_msg->family = PF_MPLS;
	ilm_msg->key = req->key;
	ilm_msg->tc = req->tc;
	ilm_msg->owner = req->owner;

	nlmsg_end(skb, nlh);

	rtnl_notify(skb, net, 0, RTNLGRP_MPLS, NULL, GFP_KERNEL);
	return 0;

nlmsg_failure:
	nlmsg_free(skb);
	rtnl_set_sk_err(net, RTNLGRP_MPLS, err);
	return err;
}

static int
fill_ilm(struct sk_buff *skb, const struct ilm *ilm,
					int seq, int pid, int event, int flags)
{
	struct ilmsg *ilm_msg;
	struct nlmsghdr *nlh;
	int ret = 0;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ilm_msg), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ilm_msg = nlmsg_data(nlh);
	ilm_msg->family = PF_MPLS;
	ilm_msg->key = ilm->key;
	ilm_msg->tc = ilm->tc;
	ilm_msg->owner = ilm->owner;

	ret = nhlfe_dump(rcu_dereference(ilm->nhlfe), skb);
	if (unlikely(ret < 0)) {
		nlmsg_free(skb);
		goto err;
	}

	return nlmsg_end(skb, nlh);
err:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int
mpls_ilm_new(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ilmsg *ilm_msg;
	struct nlattr *tb[MPLS_ATTR_MAX + 1];
	struct ilm *ilm;
	struct net *net = sock_net(skb->sk);
	int retval = 0;

	retval = nlmsg_parse(nlh, sizeof(*ilm_msg), tb, MPLS_ATTR_MAX, ilm_policy);
	if (retval < 0)
		return retval;

	ilm_msg = nlmsg_data(nlh);
	if (unlikely(!ilm_msg))
		return -EINVAL;

	if (ilm_msg->tc > TC_MAX)
		return -EINVAL;

	if (nlh->nlmsg_flags & NLM_F_CREATE) {
		ilm = add_ilm(ilm_msg, tb, net);
		if (unlikely(IS_ERR(ilm)))
			return PTR_ERR(ilm);
	} else if (nlh->nlmsg_flags & NLM_F_REPLACE) {
		ilm = get_ilm(&ilm_msg->key, ilm_msg->tc, net);
		if (unlikely(!ilm))
			return -ESRCH;
		retval = ilm_set_nhlfe(ilm, tb);
	} else
		return -EINVAL;

	if (likely(!retval))
		ilm_event(RTM_NEWROUTE, ilm_msg, net, nlh->nlmsg_pid, nlh->nlmsg_seq);
	else if (nlh->nlmsg_flags & NLM_F_CREATE)
		del_ilm(ilm_msg, net);

	return retval;
}

static int
mpls_ilm_del(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct ilmsg *ilm_msg;
	struct net *net = sock_net(skb->sk);
	int retval;

	retval = nlmsg_validate(nlh, sizeof(*ilm_msg), MPLS_ATTR_MAX, ilm_policy);
	if (unlikely(retval < 0))
		return retval;

	ilm_msg = nlmsg_data(nlh);

	retval = del_ilm(ilm_msg, net);
	if (likely(!retval))
		ilm_event(RTM_DELROUTE, ilm_msg, net, nlh->nlmsg_pid, nlh->nlmsg_seq);

	return retval;
}

static int
mpls_ilm_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ilm *ilm;
	struct hlist_node *tmp;
	int entries_to_skip = cb->args[0];
	int entry_count = 0;
	struct net *net = sock_net(skb->sk);
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);
	int i = 0;

	rcu_read_lock();
	for (i = 0; i < MAX_RES_LABEL; ++i) {
		if (entry_count >= entries_to_skip) {
			if (likely(mpls_reserved[i])) {
				if (fill_ilm(skb, mpls_reserved[i], cb->nlh->nlmsg_seq,
						NETLINK_CREDS(cb->skb)->pid, RTM_NEWROUTE, NLM_F_MULTI) < 0)
					goto out;
			}
		}
		entry_count++;
	}

	hlist_for_each_entry_rcu(ilm, tmp, &ilmn->ilm_list, global) {
		if (entry_count >= entries_to_skip) {
			if (fill_ilm(skb, ilm, cb->nlh->nlmsg_seq, NETLINK_CREDS(cb->skb)->pid,
						RTM_NEWROUTE, NLM_F_MULTI) < 0)
				break;
		}
		entry_count++;
	}

out:
	rcu_read_unlock();
	cb->args[0] = entry_count;

	return skb->len;
}

static int __net_init ilm_init_net(struct net *net)
{
	struct ilm_net *ilmn = net_generic(net, ilm_net_id);

	INIT_RADIX_TREE(&ilmn->ilm_tree, GFP_KERNEL);
	INIT_HLIST_HEAD(&ilmn->ilm_list);

	return 0;
}

static void __net_exit ilm_exit_net(struct net *net)
{
	struct ilm *ilm;
	struct hlist_node *n, *pos;
	struct ilm_net *ilmn;
	LIST_HEAD(list);

	ilmn = net_generic(net, ilm_net_id);
	rtnl_lock();
	hlist_for_each_entry_safe(ilm, n, pos, &ilmn->ilm_list, global)
		destroy_ilm(ilm, net);
	rtnl_unlock();
}

static struct pernet_operations ilm_net_ops = {
	.init = ilm_init_net,
	.exit = ilm_exit_net,
	.id   = &ilm_net_id,
	.size = sizeof(struct ilm_net),
};

int __init ilm_init(void)
{
	int err;
	err = register_pernet_subsys(&ilm_net_ops);
	if (unlikely(err))
		return err;

	err = __rtnl_register(PF_MPLS, RTM_NEWROUTE, mpls_ilm_new, NULL, NULL);
	if (unlikely(err))
		goto error;

	err = __rtnl_register(PF_MPLS, RTM_DELROUTE, mpls_ilm_del, NULL, NULL);
	if (unlikely(err))
		goto error;

	err = __rtnl_register(PF_MPLS, RTM_GETROUTE, NULL, mpls_ilm_dump, NULL);
	if (unlikely(err))
		goto error;

	return 0;

error:
	rtnl_unregister_all(PF_MPLS);
	return err;
}

void ilm_exit(void)
{
	rtnl_unregister_all(PF_MPLS);
	unregister_pernet_subsys(&ilm_net_ops);
}
