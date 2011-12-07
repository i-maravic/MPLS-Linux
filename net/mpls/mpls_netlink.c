/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_netlink.c
 *      - NetLink interface for MPLS subsystem.
 *
 * Authors:
 *      Ramon Casellas   <casellas@infres.enst.fr>
 *      Igor Maravić     <igorm@etf.rs> - Innovational Centre of School of Electrical Engineering, Belgrade
 *
 *   (c) 1999-2005   James Leu      <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *****************************************************************************/

#include <linux/netdevice.h>
#include <net/arp.h>
#include <net/sock.h>
#include <net/mpls.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>

static struct genl_family genl_mpls = {
	.id = GENL_ID_GENERATE,
	.name = MPLS_NETLINK_NAME,
	.version = 0x2,
	.maxattr = MPLS_ATTR_MAX,
};

/*Netlink multicast groups*/
static struct genl_multicast_group genl_mpls_ilm_mcast_grp = {
		.name = MPLS_GRP_ILM_NAME,
};
static struct genl_multicast_group genl_mpls_nhlfe_mcast_grp = {
		.name = MPLS_GRP_NHLFE_NAME,
};
static struct genl_multicast_group genl_mpls_xc_mcast_grp = {
		.name = MPLS_GRP_XC_NAME,
};
static struct genl_multicast_group genl_mpls_lspace_mcast_grp = {
		.name = MPLS_GRP_LABELSPACE_NAME,
};
static struct genl_multicast_group genl_mpls_get_mcast_grp = {
		.name = MPLS_GRP_GET_NAME,
};

/* ILM netlink support */

static int mpls_fill_ilm(struct sk_buff *skb, struct mpls_ilm *ilm,
	u32 pid, u32 seq, int flag, int event)
{
	struct mpls_in_label_req mil;
	struct mpls_instr_req *instr;
	int no_instr = 0;
	void *hdr;

	MPLS_ENTER;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);
	if (IS_ERR(hdr)) {
		MPLS_EXIT;
		return PTR_ERR(hdr);
	}

	no_instr = mpls_no_instrs(ilm->ilm_instr);
	instr = kmalloc(sizeof(*instr) +
		no_instr * sizeof(struct mpls_instr_elem), GFP_ATOMIC);
	if (unlikely(!instr))
		goto nla_put_failure;

	memcpy(&mil.mil_label, &ilm->ilm_label, sizeof(struct mpls_label));
	mpls_instrs_unbuild(ilm->ilm_instr, instr);
	instr->mir_direction = MPLS_IN;
	/* need to add drops here some how */
	mil.mil_owner = ilm->ilm_owner;

	NLA_PUT(skb, MPLS_ATTR_ILM, sizeof(mil), &mil);
	NLA_PUT(skb, MPLS_ATTR_INSTR, sizeof(*instr) +
		instr->mir_instr_length *
		sizeof(struct mpls_instr_elem), instr);

	kfree(instr);

	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	kfree(instr);
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	MPLS_EXIT;
	return -ENOMEM;
}

int mpls_ilm_event(char *grp_name, int event,
	struct mpls_ilm *ilm, int seq, int pid)
{
	struct sk_buff *skb;
	unsigned int group;
	int err;
	MPLS_ENTER;

	if (strncmp(genl_mpls_ilm_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_ilm_mcast_grp.id;
	} else if (strncmp(genl_mpls_get_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_get_mcast_grp.id;
	} else {
		MPLS_EXIT;
		return -EINVAL;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		MPLS_DEBUG("Exit: ENOMEM\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	err = mpls_fill_ilm(skb, ilm, pid, seq, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return err;
	}
	/*err =*/genlmsg_multicast(skb, 0, group, GFP_KERNEL);
	err = 0;
	MPLS_EXIT;
	return err;
}

/**
 * mpls_dump_ilm_event - Dumps ilm with all informations
 * @out: request
 **/
static int mpls_dump_ilm_event(
	const struct mpls_in_label_req *in,
	int seq, int pid)
{
	struct mpls_ilm *ilm     = NULL; /* New ILM to insert */
	struct mpls_label *ml    = NULL; /* Requested Label */
	unsigned int key         = 0;    /* Key to use */
	int retval               = 0;
	MPLS_ENTER;
	ml = (struct mpls_label *)&in->mil_label;

	/* Obtain key */
	key = mpls_label2key(ml->ml_labelspace, ml);

	ilm = mpls_get_ilm(key);

	if (unlikely(!ilm)) {
		MPLS_DEBUG("Node %u was not in tree\n", key);
		MPLS_EXIT;
		return  -ESRCH;
	}

	/* we have hold a refcnt to the ilm across mpls_ilm_event()
	 * to make sure it can't disappear
	 */
	retval = mpls_ilm_event(MPLS_GRP_ILM_NAME,
		MPLS_CMD_NEWILM, ilm, seq, pid);
	mpls_ilm_release(ilm);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_ilm_new(struct sk_buff *skb,
	struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	struct mpls_instr_req *instr = NULL;
	struct mpls_ilm *ilm;
	int retval = 0;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_ILM]) {
		MPLS_EXIT;
		return -EINVAL;
	}

	if (info->attrs[MPLS_ATTR_INSTR])
		instr = nla_data(info->attrs[MPLS_ATTR_INSTR]);

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);

	if (info->nlhdr->nlmsg_flags & NLM_F_CREATE) {
		ilm = mpls_add_in_label(mil);
		if (IS_ERR(ilm)) {
			MPLS_EXIT;
			return PTR_ERR(ilm);
		}
	}

	if (instr && mil->mil_change_flag&MPLS_CHANGE_INSTR)
		retval = mpls_ilm_set_instrs(mil, instr->mir_instr,
			instr->mir_instr_length);
		/* JLEU: should revert to old instr on failure */

	if (!retval)
		mpls_dump_ilm_event(mil, info->snd_seq, info->snd_pid);
	else {
		/*IMAR:
		 *	If user can't initialy set ilm with
		 *	desired instructions or protocol,
		 *	than the ilm won't exist.
		 *	But if the user wants to change ilm,
		 *	and instructions are bad, the ilm entry
		 *	won't be deleted!
		 */
		if (info->nlhdr->nlmsg_flags & NLM_F_CREATE)
			mpls_del_in_label(mil, 0, 0);
	}
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_ilm_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	int retval;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_ILM]) {
		MPLS_EXIT;
		return -EINVAL;
	}

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);
	retval = mpls_del_in_label(mil, info->snd_seq, info->snd_pid);
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_ilm_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_in_label_req *mil;
	struct mpls_ilm *ilm;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_ILM])
		goto err;

	mil = nla_data(info->attrs[MPLS_ATTR_ILM]);

	if (mil->mil_label.ml_type == MPLS_LABEL_KEY)
		goto err;

	ilm = mpls_get_ilm_label(mil);
	if (!ilm) {
		retval = -ESRCH;
		goto err;
	} else {
		retval = mpls_ilm_event(MPLS_GRP_GET_NAME,
			MPLS_CMD_NEWILM, ilm,
			info->snd_seq, info->snd_pid);
		mpls_ilm_release(ilm);
	}
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_ilm_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct mpls_ilm *ilm;
	int entries_to_skip = cb->args[0];
	int entry_count = 0;
	MPLS_ENTER;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(ilm, &mpls_ilm_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_ilm(skb, ilm, NETLINK_CB(cb->skb).pid,
				cb->nlh->nlmsg_seq, NLM_F_MULTI,
				MPLS_CMD_NEWILM) < 0) {
				break;
			}
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	MPLS_EXIT;
	return skb->len;
}

/* NHLFE netlink support */

static int mpls_fill_nhlfe(struct sk_buff *skb,
	struct mpls_nhlfe *nhlfe, u32 pid, u32 seq,
	int flag, int event)
{
	struct mpls_out_label_req mol;
	struct mpls_instr_req *instr;
	int no_instr = 0; /*number of instructions*/
	void *hdr;

	MPLS_ENTER;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);
	if (IS_ERR(hdr)) {
		MPLS_EXIT;
		return PTR_ERR(hdr);
	}

	no_instr = mpls_no_instrs(nhlfe->nhlfe_instr);
	instr = kmalloc(sizeof(*instr) +
		no_instr*sizeof(struct mpls_instr_elem), GFP_ATOMIC);
	if (unlikely(!instr))
		goto nla_put_failure;

	mol.mol_label.ml_type = MPLS_LABEL_KEY;
	mol.mol_label.u.ml_key = nhlfe->nhlfe_key;
	mol.mol_mtu = dst_mtu(&nhlfe->dst);
	mol.mol_propagate_ttl = nhlfe->nhlfe_propagate_ttl;
	mpls_instrs_unbuild(nhlfe->nhlfe_instr, instr);
	instr->mir_direction = MPLS_OUT;
	/* need to get drops added here some how */
	mol.mol_owner = nhlfe->nhlfe_owner;

	NLA_PUT(skb, MPLS_ATTR_NHLFE, sizeof(mol), &mol);
	NLA_PUT(skb, MPLS_ATTR_INSTR,
		sizeof(*instr) + instr->mir_instr_length *
		sizeof(struct mpls_instr_elem), instr);

	kfree(instr);

	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	kfree(instr);
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	MPLS_EXIT;
	return -ENOMEM;
}

int mpls_nhlfe_event(char *grp_name, int event,
	struct mpls_nhlfe *nhlfe, int seq, int pid)
{
	struct sk_buff *skb;
	unsigned int group;
	int err;

	MPLS_ENTER;
	if (strncmp(genl_mpls_nhlfe_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_nhlfe_mcast_grp.id;
	} else if (strncmp(genl_mpls_get_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_get_mcast_grp.id;
	} else {
		MPLS_EXIT;
		return -EINVAL;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	err = mpls_fill_nhlfe(skb, nhlfe, pid, seq, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return err;
	}
	/*err = */genlmsg_multicast(skb, 0, group, GFP_KERNEL);
	err = 0;
	MPLS_EXIT;
	return err;
}

/**
 * mpls_dump_nhlfe_event - Dumps nhlfe with all informations
 * @out: request
 **/
static int mpls_dump_nhlfe_event(struct mpls_out_label_req *out,
		int seq, int pid)
{
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key;
	int retval = 0;

	key = mpls_label2key(0, &out->mol_label);
	nhlfe = mpls_get_nhlfe(key);

	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("Node %u was not in tree\n", key);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* we need to hold a ref to the nhlfe while calling
	 * mpls_nhlfe_event so it can't disappear
	 */
	retval = mpls_nhlfe_event(MPLS_GRP_NHLFE_NAME,
		MPLS_CMD_NEWNHLFE, nhlfe, seq, pid);
	mpls_nhlfe_release(nhlfe);
	return retval;
}

static int genl_mpls_nhlfe_new(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	struct mpls_instr_req *instr = NULL;
	struct mpls_nhlfe *nhlfe;
	int retval = 0;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_NHLFE] ||
		(!info->attrs[MPLS_ATTR_INSTR] &&
		info->nlhdr->nlmsg_flags&NLM_F_CREATE)){
		MPLS_EXIT;
		return -EINVAL;
	}

	if (info->attrs[MPLS_ATTR_INSTR])
		instr = nla_data(info->attrs[MPLS_ATTR_INSTR]);

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);

	if (mol->mol_label.ml_type != MPLS_LABEL_KEY) {
		MPLS_EXIT;
		return -EINVAL;
	}

	if (info->nlhdr->nlmsg_flags&NLM_F_CREATE) {
		nhlfe = mpls_add_out_label(mol);
		if (IS_ERR(nhlfe)) {
			MPLS_EXIT;
			return PTR_ERR(nhlfe);
		}
	}

	if (instr && mol->mol_change_flag & MPLS_CHANGE_INSTR) {
		retval = mpls_nhlfe_set_instrs(mol,
			instr->mir_instr, instr->mir_instr_length);
		/* JLEU: should revert to old instr on failure */
	}

	if ((!retval) &&  mol->mol_change_flag & MPLS_CHANGE_MTU)
		retval = mpls_set_out_label_mtu(mol);

	if ((!retval) && mol->mol_change_flag & MPLS_CHANGE_PROP_TTL)
		retval = mpls_set_out_label_propagate_ttl(mol);

	if (!retval) {
		mpls_dump_nhlfe_event(mol,
			info->snd_seq, info->snd_pid);
	} else {
		/*IMAR:
		 *	If user can't initialy set nhlfe
		 *	with desired instructions or mtu,
		 *	than the nhlfe entry won't exist.
		 *
		 *	But if the user wants to change nhlfe,
		 *	and instructions, or mtu, are bad,
		 *	the nhlfe entry won't be deleted!
		*/
		if (info->nlhdr->nlmsg_flags&NLM_F_CREATE)
			mpls_del_out_label(mol, 0, 0);
	}

	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_nhlfe_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_NHLFE]) {
		MPLS_EXIT;
		return -EINVAL;
	}

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);
	retval = mpls_del_out_label(mol, info->snd_seq, info->snd_pid);
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_nhlfe_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_out_label_req *mol;
	struct mpls_nhlfe *nhlfe;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_NHLFE])
		goto err;

	mol = nla_data(info->attrs[MPLS_ATTR_NHLFE]);

	if (mol->mol_label.ml_type != MPLS_LABEL_KEY)
		goto err;

	nhlfe = mpls_get_nhlfe_label(mol);
	if (!nhlfe) {
		retval = -ESRCH;
	} else {
		retval = mpls_nhlfe_event(MPLS_GRP_GET_NAME,
			MPLS_CMD_NEWNHLFE, nhlfe,
			info->snd_seq, info->snd_pid);
		mpls_nhlfe_release(nhlfe);
	}
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_nhlfe_dump(struct sk_buff *skb,
		struct netlink_callback *cb)
{
	struct mpls_nhlfe *nhlfe;
	int entries_to_skip;
	int entry_count;
	MPLS_ENTER;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(nhlfe, &mpls_nhlfe_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_nhlfe(skb, nhlfe, NETLINK_CB(cb->skb).pid,
				cb->nlh->nlmsg_seq, NLM_F_MULTI,
				MPLS_CMD_NEWNHLFE) <= 0) {
				break;
			}
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	MPLS_EXIT;
	return skb->len;
}

/* XC netlink support */

static int mpls_fill_xc(struct sk_buff *skb,
	struct mpls_ilm *ilm, struct mpls_nhlfe *nhlfe,
	u32 pid, u32 seq, int flag, int event)
{
	struct mpls_xconnect_req xc;
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);
	if (IS_ERR(hdr)) {
		MPLS_EXIT;
		return PTR_ERR(hdr);
	}

	memcpy(&xc.mx_in, &ilm->ilm_label, sizeof(struct mpls_label));
	xc.mx_out.ml_type = MPLS_LABEL_KEY;
	xc.mx_out.u.ml_key = nhlfe->nhlfe_key;
	xc.mx_owner = ilm->ilm_owner; /* JBO: Use the ILM owner */

	NLA_PUT(skb, MPLS_ATTR_XC, sizeof(xc), &xc);

	MPLS_DEBUG("Exit: length\n");
	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	MPLS_EXIT;
	return -ENOMEM;
}

int mpls_xc_event(char *grp_name, int event,
	struct mpls_ilm *ilm, struct mpls_nhlfe *nhlfe,
	int seq, int pid)
{
	struct sk_buff *skb;
	int err;
	unsigned int group;

	MPLS_ENTER;

	if (strncmp(genl_mpls_xc_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_xc_mcast_grp.id;
	} else if (strncmp(genl_mpls_get_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_get_mcast_grp.id;
	} else {
		MPLS_EXIT;
		return -EINVAL;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	err = mpls_fill_xc(skb, ilm, nhlfe, pid, seq, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return err;
	}
	/*err = */genlmsg_multicast(skb, 0, group, GFP_KERNEL);
	err = 0;
	MPLS_EXIT;
	return err;
}

static int genl_mpls_xc_new(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_XC]) {
		MPLS_EXIT;
		return -EINVAL;
	}

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);

	retval = mpls_attach_in2out(xc,
		info->snd_seq, info->snd_pid);
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_xc_del(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_XC]) {
		MPLS_EXIT;
		return -EINVAL;
	}

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);
	retval = mpls_detach_in2out(xc,
		info->snd_seq, info->snd_pid);
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_xc_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_xconnect_req *xc;
	struct mpls_ilm *ilm;
	struct mpls_nhlfe *nhlfe;
	struct mpls_instr *mi;
	int retval = -EINVAL;

	MPLS_ENTER;

	if (!info->attrs[MPLS_ATTR_XC])
		goto err;

	xc = nla_data(info->attrs[MPLS_ATTR_XC]);

	if (xc->mx_in.ml_type == MPLS_LABEL_KEY)
		goto err;

	ilm = mpls_get_ilm(mpls_label2key(xc->mx_in.ml_labelspace,
			&xc->mx_in));
	if (!ilm) {
		retval = -ESRCH;
	} else {
		/* Fetch the last instr, make sure it is FWD */
		mi = mpls_instr_getlast(ilm->ilm_instr);

		if (!mi || mi->mi_opcode != MPLS_OP_FWD) {
			retval = -ENXIO;
		} else {
			nhlfe = mi->mi_data;

			retval = mpls_xc_event(MPLS_GRP_GET_NAME,
			MPLS_CMD_NEWXC, ilm, nhlfe,
			info->snd_seq, info->snd_pid);
		}
		mpls_ilm_release(ilm);
	}
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_xc_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct mpls_ilm *ilm;
	struct mpls_nhlfe *nhlfe;
	struct mpls_instr *mi;
	int entries_to_skip;
	int entry_count;
	MPLS_ENTER;

	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	rcu_read_lock();
	list_for_each_entry_rcu(ilm, &mpls_ilm_list, global) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			/* Fetch the last instr, make sure it is FWD */
			mi = mpls_instr_getlast(ilm->ilm_instr);

			if (!mi || mi->mi_opcode != MPLS_OP_FWD)
				continue;

			nhlfe = mi->mi_data;

			if (mpls_fill_xc(skb, ilm, nhlfe,
					NETLINK_CB(cb->skb).pid,
					cb->nlh->nlmsg_seq,
					NLM_F_MULTI, MPLS_CMD_NEWXC) < 0)
				break;
		}
		entry_count++;
	}
	rcu_read_unlock();
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	MPLS_EXIT;
	return skb->len;

}

/* LABELSPACE netlink support */

static int mpls_fill_labelspace(struct sk_buff *skb,
	struct net_device *dev, u32 pid,
	u32 seq, int flag, int event)
{
	struct mpls_labelspace_req ls;
	struct mpls_interface *mif = dev->mpls_ptr;
	void *hdr;
	MPLS_ENTER;
	hdr = genlmsg_put(skb, pid, seq, &genl_mpls, flag, event);
	if (IS_ERR(hdr)) {
		MPLS_EXIT;
		return PTR_ERR(hdr);
	}

	ls.mls_ifindex = dev->ifindex;
	if (mif)
		ls.mls_labelspace = mif->labelspace;
	else
		ls.mls_labelspace = -1;

	NLA_PUT(skb, MPLS_ATTR_LABELSPACE, sizeof(ls), &ls);

	MPLS_DEBUG("Exit: length\n");
	MPLS_EXIT;
	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	MPLS_DEBUG("Exit: -1\n");
	MPLS_EXIT;
	return -ENOMEM;
}

int mpls_labelspace_event(char *grp_name,
	int event, struct net_device *dev,
	int seq, int pid)
{
	struct sk_buff *skb;
	unsigned int group;
	int err;

	MPLS_ENTER;
	if (strncmp(genl_mpls_lspace_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_lspace_mcast_grp.id;
	} else if (strncmp(genl_mpls_get_mcast_grp.name,
		grp_name, strlen(grp_name)) == 0) {
		group = genl_mpls_get_mcast_grp.id;
	} else {
		MPLS_EXIT;
		return -EINVAL;
	}
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	err = mpls_fill_labelspace(skb, dev, pid, seq, 0, event);
	if (err < 0) {
		nlmsg_free(skb);
		MPLS_DEBUG("Exit: EINVAL\n");
		MPLS_EXIT;
		return err;
	}
	/*err = */genlmsg_multicast(skb, 0, group, GFP_KERNEL);
	err = 0;
	MPLS_EXIT;
	return err;
}

static int genl_mpls_labelspace_set(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_labelspace_req *ls;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_LABELSPACE]) {
		MPLS_EXIT;
		return -EINVAL;
	}
	ls = nla_data(info->attrs[MPLS_ATTR_LABELSPACE]);
	retval = mpls_set_labelspace(ls,
		info->snd_seq, info->snd_pid);
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_labelspace_get(struct sk_buff *skb, struct genl_info *info)
{
	struct mpls_labelspace_req *ls;
	struct net_device *dev;
	int retval = -EINVAL;

	MPLS_ENTER;
	if (!info->attrs[MPLS_ATTR_LABELSPACE])
		goto err;

	ls = nla_data(info->attrs[MPLS_ATTR_LABELSPACE]);
	dev = dev_get_by_index(&init_net, ls->mls_ifindex);
	if (!dev) {
		retval = -ESRCH;
	} else {
		retval = mpls_labelspace_event(MPLS_GRP_GET_NAME,
			MPLS_CMD_SETLABELSPACE, dev, info->snd_seq,
			info->snd_pid);
		dev_put(dev);
	}
err:
	MPLS_DEBUG("Exit: %d\n", retval);
	MPLS_EXIT;
	return retval;
}

static int genl_mpls_labelspace_dump(struct sk_buff *skb,
		struct netlink_callback *cb)
{
	struct net_device *dev;
	int entries_to_skip;
	int entry_count;

	MPLS_ENTER;
	entries_to_skip = cb->args[0];
	entry_count = 0;

	MPLS_DEBUG("Enter: entry %d\n", entries_to_skip);
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		MPLS_DEBUG("Dump: entry %d\n", entry_count);
		if (entry_count >= entries_to_skip) {
			if (mpls_fill_labelspace(skb, dev,
				NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
				NLM_F_MULTI, MPLS_CMD_SETLABELSPACE) < 0) {
				break;
			}
		}
		entry_count++;
	}
	read_unlock(&dev_base_lock);
	cb->args[0] = entry_count;

	MPLS_DEBUG("Exit: entry %d\n", entry_count);
	MPLS_EXIT;
	return skb->len;
}

static struct nla_policy genl_mpls_policy[MPLS_ATTR_MAX+1] __read_mostly = {
	[MPLS_ATTR_ILM] = { .len = sizeof(struct mpls_in_label_req) },
	[MPLS_ATTR_NHLFE] = { .len = sizeof(struct mpls_out_label_req) },
	[MPLS_ATTR_XC] = { .len = sizeof(struct mpls_xconnect_req) },
	[MPLS_ATTR_LABELSPACE] = {.len = sizeof(struct mpls_labelspace_req)},
	[MPLS_ATTR_INSTR] = { .len = sizeof(struct mpls_instr_req) },
};

static struct genl_ops genl_mpls_ilm_new_ops = {
	.cmd		= MPLS_CMD_NEWILM,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_ilm_new,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_ilm_del_ops = {
	.cmd		= MPLS_CMD_DELILM,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_ilm_del,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_ilm_get_ops = {
	.cmd		= MPLS_CMD_GETILM,
	.doit		= genl_mpls_ilm_get,
	.dumpit		= genl_mpls_ilm_dump,
	.policy		= genl_mpls_policy,
};

static struct genl_ops genl_mpls_nhlfe_new_ops = {
	.cmd		= MPLS_CMD_NEWNHLFE,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_nhlfe_new,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_nhlfe_del_ops = {
	.cmd		= MPLS_CMD_DELNHLFE,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_nhlfe_del,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_nhlfe_get_ops = {
	.cmd		= MPLS_CMD_GETNHLFE,
	.doit		= genl_mpls_nhlfe_get,
	.dumpit		= genl_mpls_nhlfe_dump,
	.policy		= genl_mpls_policy,
};

static struct genl_ops genl_mpls_xc_new_ops = {
	.cmd		= MPLS_CMD_NEWXC,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_xc_new,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_xc_del_ops = {
	.cmd		= MPLS_CMD_DELXC,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_xc_del,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_xc_get_ops = {
	.cmd		= MPLS_CMD_GETXC,
	.doit		= genl_mpls_xc_get,
	.dumpit		= genl_mpls_xc_dump,
	.policy		= genl_mpls_policy,
};

static struct genl_ops genl_mpls_labelspace_set_ops = {
	.cmd		= MPLS_CMD_SETLABELSPACE,
	.flags 		= GENL_ADMIN_PERM,
	.doit		= genl_mpls_labelspace_set,
	.policy		= genl_mpls_policy,
};
static struct genl_ops genl_mpls_labelspace_get_ops = {
	.cmd		= MPLS_CMD_GETLABELSPACE,
	.doit		= genl_mpls_labelspace_get,
	.dumpit		= genl_mpls_labelspace_dump,
	.policy		= genl_mpls_policy,
};

int __init mpls_netlink_init(void)
{
	int err;
	MPLS_ENTER;

	err = genl_register_family(&genl_mpls);

	err += genl_register_ops(&genl_mpls, &genl_mpls_ilm_new_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_ilm_del_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_ilm_get_ops);

	err += genl_register_ops(&genl_mpls, &genl_mpls_nhlfe_new_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_nhlfe_del_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_nhlfe_get_ops);

	err += genl_register_ops(&genl_mpls, &genl_mpls_xc_new_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_xc_del_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_xc_get_ops);

	err += genl_register_ops(&genl_mpls, &genl_mpls_labelspace_set_ops);
	err += genl_register_ops(&genl_mpls, &genl_mpls_labelspace_get_ops);

	/*register mcast groups*/
	err += genl_register_mc_group(&genl_mpls, &genl_mpls_ilm_mcast_grp);
	err += genl_register_mc_group(&genl_mpls, &genl_mpls_nhlfe_mcast_grp);
	err += genl_register_mc_group(&genl_mpls, &genl_mpls_xc_mcast_grp);
	err += genl_register_mc_group(&genl_mpls, &genl_mpls_lspace_mcast_grp);
	err += genl_register_mc_group(&genl_mpls, &genl_mpls_get_mcast_grp);

	if (err) {
		printk(KERN_ERR "MPLS: failed to register with genetlink\n");
		genl_unregister_family(&genl_mpls);
		MPLS_EXIT;
		return -EINVAL;
	}
	MPLS_EXIT;
	return 0;
}

void mpls_netlink_exit(void)
{
	MPLS_ENTER;
	genl_unregister_mc_group(&genl_mpls, &genl_mpls_ilm_mcast_grp);
	genl_unregister_mc_group(&genl_mpls, &genl_mpls_nhlfe_mcast_grp);
	genl_unregister_mc_group(&genl_mpls, &genl_mpls_xc_mcast_grp);
	genl_unregister_mc_group(&genl_mpls, &genl_mpls_lspace_mcast_grp);
	genl_unregister_mc_group(&genl_mpls, &genl_mpls_get_mcast_grp);

	genl_unregister_ops(&genl_mpls, &genl_mpls_labelspace_get_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_labelspace_set_ops);

	genl_unregister_ops(&genl_mpls, &genl_mpls_xc_del_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_xc_new_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_xc_get_ops);

	genl_unregister_ops(&genl_mpls, &genl_mpls_nhlfe_del_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_nhlfe_new_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_nhlfe_get_ops);

	genl_unregister_ops(&genl_mpls, &genl_mpls_ilm_del_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_ilm_new_ops);
	genl_unregister_ops(&genl_mpls, &genl_mpls_ilm_get_ops);

	genl_unregister_family(&genl_mpls);
	MPLS_EXIT;
}
