/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravić     <igorm@etf.rs> - Innovational Centre of School of Electrical Engineering, Belgrade
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/dst.h>
#include <net/mpls.h>
#include <linux/socket.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/arp.h>
#include <net/route.h>
#include <linux/rtnetlink.h>
#include <net/ip_fib.h>
#include <linux/inet.h>
#include <net/net_namespace.h>

/*
 * Helper functions
 */

static inline void mpls_list_del_init(struct list_head *entry)
{
	MPLS_ENTER;
	if (!list_empty(entry))
		list_del_init(entry);
	MPLS_EXIT;
}

/*
 * Generic function pointer to use when the opcode just
 * needs to free the data pointer
 */
MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_generic)
{
	MPLS_ENTER;
	kfree(data);
	MPLS_EXIT;
}


/*********************************************************************
 * MPLS_OP_DROP
 * DESC   : "Drop packet".
 * EXEC   : mpls_op_drop
 * INPUT  : true
 * OUTPUT : true
 * DATA   : NULL
 * LAST   : true
 *********************************************************************/

inline MPLS_OPCODE_PROTOTYPE(mpls_op_drop)
{
	MPLS_ENTER;
	MPLS_EXIT;
	return MPLS_RESULT_DROP;
}

MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_op_drop)
{
	MPLS_ENTER;
	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *nhlfe = _mpls_as_nhlfe(parent);
		nhlfe->dst.dev = init_net.loopback_dev;
		
		nhlfe->nhlfe_proto = mpls_proto_find_by_family(AF_INET);
		if (unlikely(!nhlfe->nhlfe_proto)) {
			MPLS_EXIT;
			return -ENOENT;
		}
		dev_hold(nhlfe->dst.dev);
	}
	*data = NULL;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_op_drop)
{
	MPLS_ENTER;
	if (direction == MPLS_OUT) {
		struct mpls_nhlfe *nhlfe = _mpls_as_nhlfe(parent);
		mpls_proto_release(nhlfe->nhlfe_proto);
		dev_put(nhlfe->dst.dev);
		nhlfe->dst.dev = NULL;
	}
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_POP
 * DESC   : "Pop label from stack"
 * EXEC   : mpls_in_op_pop
 * BUILD  : mpls_build_opcode_pop
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false
 * DATA   : NULL
 * LAST   : false
 *********************************************************************/

inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_pop)
{
	struct sk_buff *skb = *pskb;
	struct mpls_skb_cb *cb = MPLSCB(skb);

	MPLS_ENTER;
	/*
	 * Check that we have not popped the last label and
	 * make sure that we can pull
	 */
	if (cb->popped_bos || ((skb->data + MPLS_HDR_LEN) >=
		skb_tail_pointer(skb))) {
		MPLS_EXIT;
		return MPLS_RESULT_DROP;
	}

	/*
	 * Is this the last entry in the stack? then flag it
	 */
	if (cb->bos)
		cb->popped_bos = 1;

	skb_pull(skb, MPLS_HDR_LEN);
	skb_reset_network_header(skb);

	if (!cb->popped_bos)
		mpls_label_entry_peek(skb);

	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_pop)
{
	MPLS_ENTER;
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("POP only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}
	MPLS_EXIT;
	return 0;
}



/*********************************************************************
 * MPLS_OP_PEEK
 * DESC   : "Peek the contents of the next label entry, no popping"
 * EXEC   : mpls_in_opcode_peek
 * BUILD  : mpls_build_opcode_peek
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false
 * DATA   : NULL
 * LAST   : true
 *********************************************************************/

inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_peek)
{
	MPLS_ENTER;
	if (MPLSCB(*pskb)->popped_bos) {
		MPLS_EXIT;
		return MPLS_RESULT_DLV;
	}
	MPLS_EXIT;
	return MPLS_RESULT_RECURSE;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_peek)
{
	MPLS_ENTER;
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("PEEK only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}



/*********************************************************************
 * MPLS_OP_PUSH
 * DESC   : "Push a label entry"
 * EXEC   : mpls_op_push
 * BUILD  : mpls_build_opcode_push
 * UNBUILD: mpls_unbuild_opcode_push
 * CLEAN  : mpls_clean_opcode_push
 * INPUT  : ?
 * OUTPUT : true
 * DATA   : Reference to label to push (struct mpls_label*)
 * LAST   : false
 *********************************************************************/

inline MPLS_OPCODE_PROTOTYPE(mpls_op_push)
{
	struct sk_buff *skb = *pskb;
	struct mpls_skb_cb *cb = MPLSCB(skb);
	struct mpls_label *ml = data;
	unsigned int label;
	u32 shim;

	MPLS_ENTER;
	BUG_ON(!ml);

	skb_push(skb, MPLS_HDR_LEN);
	skb_reset_network_header(skb);

	/* Only MPLS_LABEL_GEN type rigth now */
	label = ml->u.ml_gen;

	/*
	 * no matter what layer 2 we are on, we need the shim! (mpls-encap RFC)
	 */
	shim = htonl(((label & 0xFFFFF) << 12) |
			((cb->exp & 0x7) << 9) |
			((cb->bos & 0x1) << 8) |
			(cb->ttl & 0xFF));
	memcpy(skb->data, &shim, MPLS_HDR_LEN);
	cb->label = label;
	cb->bos = 0;
	cb->popped_bos = 0;
	/*
	 * reset exp so the next shim would have it reseted
	 */
	cb->exp = 0;

	skb->protocol = htons(ETH_P_MPLS_UC);
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_push)
{
	struct mpls_nhlfe *pnhlfe = parent;
	struct mpls_label *ml = &instr->mir_push;

	MPLS_ENTER;

	if (unlikely(direction != MPLS_OUT)) {
		MPLS_DEBUG("PUSH only valid for outgoing labels\n");
		return -EINVAL;
	}
	/*
	 * gen label type is only supported for now
	 */
	if (ml->ml_type != MPLS_LABEL_GEN) {
		MPLS_DEBUG("invalid label type (%d)\n", ml->ml_type);
		return -EINVAL;
	}

	*data = kzalloc(sizeof(*ml), GFP_ATOMIC);
	if (unlikely(!(*data))) {
		MPLS_DEBUG("error building PUSH label instruction\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	ml = _mpls_as_label(*data);
	memcpy(ml, &instr->mir_push, sizeof(*ml));
	pnhlfe->dst.header_len += MPLS_HDR_LEN;

	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_push)
{
	struct mpls_label *ml = data;
	MPLS_ENTER;

	memcpy(&instr->mir_push, ml, sizeof(*ml));

	MPLS_EXIT;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_push)
{
	struct mpls_nhlfe *pnhlfe = _mpls_as_nhlfe(parent);
	MPLS_ENTER;
	pnhlfe->dst.header_len -= MPLS_HDR_LEN;
	kfree(data);
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_DLV
 * DESC   : "Deliver to the upper layers, set skb protocol to ILM's"
 *          "Incoming L3 protocol"
 * EXEC   : mpls_in_opcode_dlv
 * BUILD  : mpls_build_opcode_dlv
 * UNBUILD: NULL
 * INPUT  : true
 * OUTPUT : false
 * DATA   : NULL
 * LAST   : true
 *********************************************************************/

inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_dlv)
{
	MPLS_ENTER;
	while (!MPLSCB(*pskb)->popped_bos) {
		if (mpls_in_op_pop(pskb, ilm, nhlfe, data) !=
			MPLS_RESULT_SUCCESS) {
			MPLS_EXIT;
			return MPLS_RESULT_DROP;
		}
	}
	MPLS_EXIT;
	return MPLS_RESULT_DLV;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_dlv)
{
	MPLS_EXIT;
	*data = NULL;
	if (unlikely(direction != MPLS_IN)) {
		MPLS_DEBUG("DLV only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}



/*********************************************************************
 * MPLS_OP_FWD
 * DESC   : "Forward packet, applying a given NHLFE"
 * EXEC   : mpls_op_fwd
 * BUILD  : mpls_build_opcode_fwd
 * UNBUILD: mpls_unbuild_opcode_fwd
 * CLEAN  : mpls_clean_opcode_fwd
 * INPUT  : true
 * OUTPUT : true
 * DATA   : Reference to NHLFE object to apply
 * LAST   : true
 *********************************************************************/

inline MPLS_OPCODE_PROTOTYPE(mpls_op_fwd)
{
	MPLS_ENTER;
	BUG_ON(!data);
	*nhlfe = (struct mpls_nhlfe *)data;
	MPLS_EXIT;
	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_fwd)
{
	struct mpls_nhlfe *nhlfe = NULL;
	struct mpls_ilm *pilm;
	unsigned int key = 0;

	MPLS_ENTER;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("FWD only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	*data = NULL;
	/*
	 * Get NHLFE to apply given key
	 */
	key = mpls_label2key(0, &instr->mir_fwd);
	nhlfe = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("FWD: NHLFE key %08x not found\n", key);
		MPLS_EXIT;
		return -ESRCH;
	}

	pilm = _mpls_as_ilm(parent);
	/* Add parent ILM to this NHLFE list */
	list_add(&pilm->nhlfe_entry, &nhlfe->list_in);

	*data = nhlfe;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_fwd)
{
	struct mpls_nhlfe *nhlfe = data;

	MPLS_ENTER;

	instr->mir_fwd.ml_type = MPLS_LABEL_KEY;
	instr->mir_fwd.u.ml_key = nhlfe->nhlfe_key;

	MPLS_EXIT;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_fwd)
{
	MPLS_ENTER;
	/* Remove parent NHLFE from this NHLFE list */
	mpls_list_del_init(&_mpls_as_ilm(parent)->nhlfe_entry);
	mpls_nhlfe_release(_mpls_as_nhlfe(data));
	MPLS_EXIT;
}




/*********************************************************************
 * MPLS_OP_NF_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by skbuff mark"
 * EXEC   : mpls_op_nf_fwd
 * BUILD  : mpls_build_opcode_nf_fwd
 * UNBUILD: mpls_unbuild_opcode_nf_fwd
 * CLEAN  : mpls_clean_opcode_nf_fwd
 * INPUT  : false
 * OUTPUT : true
 * DATA   : NFI object (struct mpls_nfmark_fwd_info*)
 *	o Each nfi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

#ifdef CONFIG_NETFILTER

inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_nf_fwd)
{
	struct mpls_nfmark_fwd_info *nfi = data;
	MPLS_ENTER;
	*nhlfe = nfi->nfi_nhlfe[(*pskb)->mark & nfi->nfi_mask];
	if (unlikely(!(*nhlfe))) {
		MPLS_EXIT;
		return MPLS_RESULT_DROP;
	}
	MPLS_EXIT;
	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_nf_fwd)
{
	struct mpls_nfmark_fwd_info *nfi = NULL;
	unsigned int min_mtu = MPLS_INVALID_MTU;
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int key = 0;
	int j = 0;
	MPLS_ENTER;
	*data = NULL;

	/* Allocate NFI object to store in data */
	nfi = kzalloc(sizeof(*nfi), GFP_ATOMIC);
	if (unlikely(!nfi)) {
		MPLS_DEBUG("NF_FWD error building NFMARK info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	/* Set up NHLFE objects for each mark given the keys */
	nfi->nfi_mask = instr->mir_nf_fwd.nf_mask;
	if (nfi->nfi_mask >= MPLS_NFMARK_NUM) {
		MPLS_DEBUG("NF_FWD mask(%02x) allows too large values\n",
				nfi->nfi_mask);
		kfree(nfi);
		MPLS_EXIT;
		return -EINVAL;
	}

	for (j = 0; j < MPLS_NFMARK_NUM; j++) {
		int i;
		key = instr->mir_nf_fwd.nf_key[j];
		if (!key)
			continue;

		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("NF_FWD: NHLFE - key %08x not found\n", key);
			kfree(nfi);
			MPLS_EXIT;
			return -ESRCH;
		}
		if (dst_mtu(&nhlfe->dst) < min_mtu)
			min_mtu = dst_mtu(&nhlfe->dst);

		for (i = 0; i < MPLS_NFMARK_NUM; i++) {
			if ((i & nfi->nfi_mask) == (j & nfi->nfi_mask)
				&& !nfi->nfi_nhlfe[i])
				nfi->nfi_nhlfe[i] = nhlfe;
		}
	}

	/*
	 * Set the MTU according to the number of pushes.
	 * RCAS :If the opcode is only allowed in output the "if"  should be
	 * removed, and a check added at the beginning
	 */
	if (direction == MPLS_OUT)
		mpls_nhlfe_update_mtu(_mpls_as_nhlfe(parent), min_mtu);

	*data = (void *)nfi;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_nf_fwd)
{
	struct mpls_nfmark_fwd_info *nfi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;

	nfi = _mpls_as_nfi(data);
	instr->mir_nf_fwd.nf_mask = nfi->nfi_mask;

	for (j = 0; j < MPLS_NFMARK_NUM; j++) {
		nhlfe = nfi->nfi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_nf_fwd.nf_key[j] = key;
	}

	MPLS_EXIT;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_nf_fwd)
{
	int i;
	MPLS_ENTER;
	for (i = 0; i < MPLS_NFMARK_NUM; i++) {
		struct mpls_nhlfe *nhlfe = _mpls_as_nfi(data)->nfi_nhlfe[i];
		mpls_nhlfe_release_safe(&nhlfe);
	}

	kfree(data);
	MPLS_EXIT;
}
#endif




/*********************************************************************
 * MPLS_OP_DS_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by DS field in the"
 *          "encapsulated IPv4/IPv6 packet"
 * EXEC   : mpls_op_ds_fwd
 * BUILD  : mpls_build_opcode_ds_fwd
 * UNBUILD: mpls_unbuild_opcode_ds_fwd
 * CLEAN  : mpls_clean_opcode_ds_fwd
 * INPUT  : false
 * OUTPUT : true
 * DATA   : DFI object (struct mpls_dsmark_fwd_info*)
 *	o Each dfi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_ds_fwd)
{
	struct mpls_dsmark_fwd_info *dfi = data;
	unsigned char ds;
	MPLS_ENTER;
	ds = MPLSCB(*pskb)->prot->get_dsfield(*pskb) & dfi->dfi_mask;

	*nhlfe = dfi->dfi_nhlfe[ds];
	if (unlikely(!*nhlfe)) {
		MPLS_EXIT;
		return MPLS_RESULT_DROP;
	}
	MPLS_EXIT;
	return MPLS_RESULT_FWD;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_ds_fwd)
{
	struct mpls_dsmark_fwd_info *dfi = NULL;
	struct mpls_nhlfe *nhlfe = NULL;
	unsigned int min_mtu = MPLS_INVALID_MTU;
	unsigned int key = 0;
	int j = 0;

	MPLS_ENTER;
	*data = NULL;
	/* Allocate DFI object to store in data */
	dfi = kzalloc(sizeof(*dfi), GFP_ATOMIC);
	if (unlikely(!dfi)) {
		MPLS_DEBUG("DS_FWD error building DSMARK info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}


	/* Set up NHLFE objects for each mark given the keys */
	dfi->dfi_mask = instr->mir_ds_fwd.df_mask;
	if (dfi->dfi_mask >= MPLS_DSMARK_NUM) {
		MPLS_DEBUG("DS_FWD mask(%02x) allows too large of values\n",
				dfi->dfi_mask);
		kfree(dfi);
		MPLS_EXIT;
		return -EINVAL;
	}

	for (j = 0; j < MPLS_DSMARK_NUM; j++) {
		int i;
		key = instr->mir_ds_fwd.df_key[j];
		if (!key)
			continue;

		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("DS_FWD: NHLFE key %08x not found\n", key);
			kfree(dfi);
			MPLS_EXIT;
			return -ESRCH;
		}
		if (dst_mtu(&nhlfe->dst) < min_mtu)
			min_mtu = dst_mtu(&nhlfe->dst);

		for (i = 0; i < MPLS_DSMARK_NUM; i++) {
			if ((i & dfi->dfi_mask) == (j & dfi->dfi_mask)
				&& !dfi->dfi_nhlfe[i])
				dfi->dfi_nhlfe[i] = nhlfe;
		}
	}

	/*
	 * Set the MTU according to the number of pushes.
	 * RCAS :If the opcode is only allowed in output the "if"  should be
	 * removed, and a check added at the beginning
	 */
	if (direction == MPLS_OUT)
		mpls_nhlfe_update_mtu(_mpls_as_nhlfe(parent), min_mtu);

	*data = (void *)dfi;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_ds_fwd)
{
	struct mpls_dsmark_fwd_info *dfi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;

	dfi = _mpls_as_dfi(data);
	instr->mir_ds_fwd.df_mask = dfi->dfi_mask;

	for (j = 0; j < MPLS_DSMARK_NUM; j++) {
		nhlfe = dfi->dfi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_ds_fwd.df_key[j] = key;
	}

	MPLS_EXIT;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_ds_fwd)
{
	int i;
	MPLS_ENTER;
	for (i = 0; i < MPLS_DSMARK_NUM; i++) {
		struct mpls_nhlfe *nhlfe = _mpls_as_dfi(data)->dfi_nhlfe[i];
		mpls_nhlfe_release_safe(&nhlfe);
	}

	kfree(data);
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_EXP_FWD
 * DESC   : "Forward packet, applying the NHLFE defined by DS the 3 EXP"
 *          "bits in lable entry"
 * EXEC   : mpls_op_exp_fwd
 * BUILD  : mpls_build_opcode_exp_fwd
 * UNBUILD: mpls_unbuild_opcode_exp_fwd
 * CLEAN  : mpls_clean_opcode_exp_fwd
 * INPUT  : true
 * OUTPUT : true
 * DATA   : EFI object (struct mpls_exp_fwd_info*)
 *	o Each efi_nhlfe element holds a ref to a NHLFE object
 * LAST   : true
 *********************************************************************/

inline MPLS_OPCODE_PROTOTYPE(mpls_op_exp_fwd)
{
	struct mpls_exp_fwd_info *efi = data;
	/*
	 * Apply the NHLFE defined by the  given 3 EXP bits in label entry
	 */
	MPLS_ENTER;
	*nhlfe = efi->efi_nhlfe[MPLSCB(*pskb)->exp & 0x7];
	if (unlikely(!*nhlfe)) {
		MPLS_EXIT;
		return MPLS_RESULT_DROP;
	}
	MPLS_EXIT;
	return MPLS_RESULT_FWD;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp_fwd)
{
	struct mpls_exp_fwd_info *efi = NULL;
	struct mpls_nhlfe     *nhlfe = NULL;
	unsigned int min_mtu = MPLS_INVALID_MTU;
	unsigned int key     = 0;
	int j = 0;
	MPLS_ENTER;
	*data = NULL;
	/* Allocate EFI object to store in data */
	efi = kzalloc(sizeof(*efi), GFP_ATOMIC);
	if (unlikely(!efi)) {
		MPLS_DEBUG("EXP_FWD error building EXP info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	/* Set up NHLFE objects for each EXP value, given the keys */
	for (j = 0; j < MPLS_EXP_NUM; j++) {
		key = instr->mir_exp_fwd.ef_key[j];
		if (!key)
			continue;

		nhlfe = mpls_get_nhlfe(key);
		if (unlikely(!nhlfe)) {
			MPLS_DEBUG("EXP_FWD: NHLFE key %08x not found\n", key);
			kfree(efi);
			MPLS_EXIT;
			return -ESRCH;
		}
		if (dst_mtu(&nhlfe->dst) < min_mtu)
			min_mtu = dst_mtu(&nhlfe->dst);

		efi->efi_nhlfe[j] = nhlfe;
	}

	/*
	 * Set the MTU according to the number of pushes.
	 */
	if (direction == MPLS_OUT)
		mpls_nhlfe_update_mtu(_mpls_as_nhlfe(parent), min_mtu);

	*data = (void *)efi;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp_fwd)
{
	struct mpls_exp_fwd_info *efi;
	struct mpls_nhlfe *nhlfe;
	unsigned int key;
	int j;

	MPLS_ENTER;

	efi = _mpls_as_efi(data);

	for (j = 0; j < MPLS_EXP_NUM; j++) {
		nhlfe = efi->efi_nhlfe[j];

		key = (nhlfe) ? nhlfe->nhlfe_key : 0;
		instr->mir_exp_fwd.ef_key[j] = key;
	}

	MPLS_EXIT;
}


MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_exp_fwd)
{
	int i;
	MPLS_ENTER;

	for (i = 0; i < MPLS_EXP_NUM; i++) {
		struct mpls_nhlfe *nhlfe = _mpls_as_efi(data)->efi_nhlfe[i];
		mpls_nhlfe_release_safe(&nhlfe);
	}

	kfree(data);
	MPLS_EXIT;
}


/*********************************************************************
 * MPLS_OP_SET_RX
 * DESC   : "Artificially change the incoming network device"
 * EXEC   : mpls_in_op_set_rx
 * BUILD  : mpls_build_opcode_set_rx
 * UNBUILD: mpls_unbuild_opcode_set_rx
 * CLEAN  : mpls_clean_opcode_set_rx
 * INPUT  : true
 * OUTPUT : false
 * DATA   : Reference to a net_device (struct net_device*)
 * LAST   : false
 *
 * Remark : If the interface goes down/unregistered, mpls_netdev_event
 *          (cf. mpls_init.c) will change this opcode.
 *********************************************************************/

inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_set_rx)
{
	MPLS_ENTER;
	/*
	 * Change the incoming net_device for the socket buffer
	 */
	skb_set_dev(*pskb, (struct net_device *)data);
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}

//dodati da se povećava refcnt mpls_ptr
MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_rx)
{
	struct mpls_interface *mpls_if = NULL;
	struct mpls_ilm *pilm = NULL;
	struct net_device *dev = NULL;
	unsigned int if_index = 0; /* Incoming If Index */

	MPLS_ENTER;
	*data = NULL;
	if (direction != MPLS_IN) {
		MPLS_DEBUG("SET_RX only valid for incoming labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	pilm = _mpls_as_ilm(parent);
	/*
	 * Get a reference to the device given the interface index
	 */

	if_index = instr->mir_set_rx;
	dev = dev_get_by_index(&init_net, if_index);
	if (unlikely(!dev)) {
		MPLS_DEBUG("SET_RX if_index %d unknown\n", if_index);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* Check if interface it's MPLS enabled */
	if (__mpls_get_labelspace(dev) == -1) {
		MPLS_DEBUG("SET_RX - device %s ifindex %d MPLS disabled\n",
				dev->name, if_index);
		dev_put(dev);
		MPLS_EXIT;
		return -ESRCH;
	}
	mpls_if = dev->mpls_ptr;

	*data = (void *)dev;

	/*
	 * Add to the device list of ILMs (list_in)
	 * NOTE: we're still holding a ref to dev.
	 */
	list_add(&pilm->dev_entry, &mpls_if->list_in);
	MPLS_EXIT;
	return 0;
}

/* Get the ifIndex of the device and returns it */
MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_rx)
{
	struct net_device *dev;

	MPLS_ENTER;
	dev = _mpls_as_netdev(data);
	instr->mir_set_rx = dev->ifindex;
	MPLS_EXIT;
}

MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_set_rx)
{
	struct net_device *dev = NULL;
	/* dev is already being held */
	MPLS_ENTER;
	dev = _mpls_as_netdev(data);
	mpls_list_del_init(&_mpls_as_ilm(parent)->dev_entry);
	dev_put(dev);
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_SET
 * DESC   : "Define the outgoing interface and next hop"
 * EXEC   : mpls_out_op_set
 * BUILD  : mpls_build_opcode_set
 * UNBUILD: mpls_unbuild_opcode_set
 * CLEAN  : mpls_clean_opcode_set
 * INPUT  : false
 * OUTPUT : true
 * DATA   : Reference to NHLFE cache entry (struct mpls_nhlfe *)
 * LAST   : true
 *
 * Remark : If the interface goes down/unregistered, mpls_netdev_event
 *          (cf. mpls_init.c) will change this opcode.
 *********************************************************************/

inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_set)
{
	struct dst_entry *dst = &(_mpls_as_nhlfe(data))->dst;

	MPLS_ENTER;
	/* Don't hold the dev we place in skb->dev, the dst is already
	   holding it for us */
	skb_set_dev(*pskb, dst->dev);
	mpls_nhlfe_hold(*nhlfe); /* dst_hold */

	/*
	 * Update the dst field of the skbuff in "real time"
	 */
	skb_dst_set(*pskb, dst);

	MPLS_EXIT;

	return MPLS_RESULT_SUCCESS;
}

//TODO dodati da se poveća refcnt od mpls_ptr
MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set)
{
	struct mpls_nhlfe *nhlfe = _mpls_as_nhlfe(parent);
	struct mpls_interface *mpls_if;
	unsigned int if_index; /* Outgoing interface index */
	struct net_device *dev;
	struct dst_entry *dst;
	struct sockaddr *nh;

	MPLS_ENTER;
	BUG_ON(!nhlfe);

	dst = &nhlfe->dst;
	*data = NULL;
	if (direction != MPLS_OUT) {
		MPLS_DEBUG("SET only valid for outgoing labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	if_index = instr->mir_set.mni_if;
	dev = dev_get_by_index(&init_net, if_index);

	if (unlikely(!dev)) {
		MPLS_DEBUG("SET if_index %d unknown\n", if_index);
		MPLS_EXIT;
		return -ESRCH;
	}

	/* Check if interface it's MPLS enabled */
	if (__mpls_get_labelspace(dev) == -1) {
		MPLS_DEBUG("SET - device %s ifindex %d MPLS disabled\n",
			dev->name, if_index);
		dev_put(dev);
		MPLS_EXIT;
		return -ESRCH;
	}

	mpls_if = dev->mpls_ptr;
	dst->dev = dev;
	dst->flags = DST_HOST; /* JBO: ??Â¿? */

	/* Set nexthop MPLS attr */
	nh = &instr->mir_set.mni_addr;
	if (!nh->sa_family) {
		memset(nh, 0, sizeof(instr->mir_set.mni_nh));
		nh->sa_family = AF_INET;
	}

	nhlfe->nhlfe_proto = mpls_proto_find_by_family(nh->sa_family);
	if (unlikely(!nhlfe->nhlfe_proto)) {
		dev_put(dev);
		MPLS_EXIT;
		return -ENOENT;
	}

	memcpy(&nhlfe->nhlfe_nh, nh, sizeof(instr->mir_set.mni_nh));

	/* use the protocol driver to resolve the neighbour */
	if (nhlfe->nhlfe_proto->nexthop_resolve(dst, nh, dev)) {
		mpls_proto_release(nhlfe->nhlfe_proto);
		dev_put(dev);
		return -EHOSTUNREACH;
	}

	/*
	 * Update the NHLFE MTU according to the number of pushes.
	 */
	mpls_nhlfe_update_mtu(nhlfe, dev->mtu);

	/*
	 * Add to the device list of NHLFEs (list_out)
	 *
	 */
	list_add(&nhlfe->dev_entry, &mpls_if->list_out);
	*data = (void *)nhlfe;
	*last_able = 1;
	MPLS_EXIT;
	return 0;
}


MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set)
{
	struct mpls_nhlfe *nhlfe = data;

	MPLS_ENTER;

	memcpy(&instr->mir_set.mni_addr,
		&nhlfe->nhlfe_nh, sizeof(nhlfe->nhlfe_nexthop));
	instr->mir_set.mni_if = nhlfe->dst.dev->ifindex;

	MPLS_EXIT;
}



/*
 *	Clean tasks:
 *	- release the mpls_nhlfe (opcode data)
 *	- remove this nhlfe from the device's list.
 */
MPLS_CLEAN_OPCODE_PROTOTYPE(mpls_clean_opcode_set)
{
	struct mpls_nhlfe *nhlfe  = data;
	struct dst_entry *dst = &nhlfe->dst;

	MPLS_ENTER;

	memset(&nhlfe->nhlfe_nh, 0, sizeof(struct sockaddr));
	rcu_read_lock();
	neigh_release(dst_get_neighbour(dst));
	dst_set_neighbour(dst, NULL);
	rcu_read_unlock();

	mpls_list_del_init(&_mpls_as_nhlfe(parent)->dev_entry);

	MPLS_EXIT;
}


/*********************************************************************
 * MPLS_OP_SET_TC
 * DESC   : "Define the socket buffer (IN/OUT) tc index"
 * EXEC   : mpls_out_op_set_tc
 * BUILD  : mpls_build_opcode_set_tc
 * UNBUILD: mpls_unbuild_opcode_set_tc
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : true
 * OUTPUT : true
 * DATA   : TC index to apply to skb. (unsigned short *)
 * LAST   : false
 *********************************************************************/
#ifdef CONFIG_NET_SCHED
inline MPLS_OPCODE_PROTOTYPE(mpls_op_set_tc)
{
	unsigned short *tc = NULL;
	MPLS_ENTER;
	tc = data;
	(*pskb)->tc_index = *tc;
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_tc)
{
	unsigned short *tc = NULL;
	MPLS_ENTER;
	*data = NULL;
	tc = kzalloc(sizeof(*tc), GFP_ATOMIC);
	if (unlikely(!tc)) {
		MPLS_DEBUG("SET_TC error building TC info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	*tc   = instr->mir_set_tc;
	*data = (void *)tc;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_tc)
{
	MPLS_ENTER;
	instr->mir_set_tc = *(unsigned short *)data;
	MPLS_EXIT;
}
#endif




/*********************************************************************
 * MPLS_OP_SET_DS
 * DESC   : "Changes the DS field of the IPv4/IPv6 packet"
 * EXEC   : mpls_in_op_set_ds
 * BUILD  : mpls_build_opcode_set_ds
 * UNBUILD: mpls_unbuild_opcode_set_ds
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : true
 * OUTPUT : false
 * DATA   : DS field (unsigned short *)
 * LAST   : false
 *********************************************************************/
#ifdef CONFIG_NET_SCHED

inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_set_ds)
{
	unsigned short *ds = data;
	MPLS_ENTER;
	if (!MPLSCB(*pskb)->bos) {
		MPLS_DEBUG("SET_DS and not BOS\n");
		MPLS_EXIT;
		return MPLS_RESULT_DROP;
	}
	MPLSCB(*pskb)->prot->change_dsfield(*pskb, *ds);
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_ds)
{
	unsigned char  *ds = NULL;
	MPLS_ENTER;
	*data = NULL;
	ds = kzalloc(sizeof(*ds), GFP_ATOMIC);
	if (unlikely(!ds)) {
		MPLS_DEBUG("SET_DS error building DS info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	*ds = instr->mir_set_ds;
	if (*ds > 0x3f) {
		MPLS_DEBUG("SET_DS DS(%02x) too big\n", *ds);
		MPLS_EXIT;
		return -EINVAL;
	}
	*data = (void *)ds;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_ds)
{
	MPLS_ENTER;
	instr->mir_set_ds = *(unsigned short *)data;
	MPLS_EXIT;
}
#endif



/*********************************************************************
 * MPLS_OP_SET_EXP
 * DESC   : "Changes the 3 EXP bits of the label entry"
 * EXEC   : mpls_op_set_exp
 * BUILD  : mpls_build_opcode_set_exp
 * UNBUILD: mpls_unbuild_opcode_set_exp
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : true
 * OUTPUT : true
 * DATA   : EXP value (binary 000-111) (unsigned char *)
 * LAST   : false
 *********************************************************************/

inline MPLS_OPCODE_PROTOTYPE(mpls_op_set_exp)
{

	unsigned char *exp = data;
	MPLSCB(*pskb)->exp = *exp;
	MPLS_ENTER;
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_set_exp)
{
	unsigned char  *exp = NULL;
	MPLS_ENTER;

	if (direction != MPLS_OUT) {
		MPLS_DEBUG("SET_EXP only valid for outgoing labels\n");
		MPLS_EXIT;
		return -EINVAL;
	}

	*data = NULL;
	exp = kzalloc(sizeof(*exp), GFP_ATOMIC);
	if (unlikely(!exp)) {
		MPLS_DEBUG("SET_EXP error building EXP info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	*exp = instr->mir_set_exp;
	if (*exp >= MPLS_EXP_NUM) {
		MPLS_DEBUG("SET_EXP EXP(%d) too big\n", *exp);
		kfree(exp);
		MPLS_EXIT;
		return -EINVAL;
	}
	*data = (void *)exp;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_set_exp)
{
	MPLS_ENTER;
	instr->mir_set_exp = *(unsigned char *)data;
	MPLS_EXIT;
}



/*********************************************************************
 * MPLS_OP_EXP2TC
 * DESC   : "Changes the TC index of the socket buffer according to"
 *          "the EXP bits in label entry"
 * EXEC   : mpls_op_exp2tc
 * BUILD  : mpls_build_opcode_exp2tc
 * UNBUILD: mpls_unbuild_opcode_exp2tc
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : true
 * OUTPUT : true
 * DATA   : e2ti (struct mpls_exp2tcindex_info*) - No ILM/NHLFE are held.
 * LAST   : false
 *********************************************************************/

#ifdef CONFIG_NET_SCHED

inline MPLS_OPCODE_PROTOTYPE(mpls_op_exp2tc)
{
	struct mpls_exp2tcindex_info *e2ti = NULL;

	MPLS_ENTER;
	BUG_ON(!data);
	BUG_ON(!(*pskb));
	e2ti = data;
	if (e2ti->e2t[MPLSCB(*pskb)->exp & 0x7] != 0xffff)
		(*pskb)->tc_index = e2ti->e2t[MPLSCB(*pskb)->exp & 0x7];

	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp2tc)
{
	struct mpls_exp2tcindex_info *e2ti = NULL;
	int j;
	MPLS_ENTER;
	*data = NULL;
	/*
	 * Allocate e2ti object
	 */
	e2ti = kzalloc(sizeof(*e2ti), GFP_ATOMIC);
	if (unlikely(!e2ti)) {
		MPLS_DEBUG("EXP2TC error building TC info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	/*
	 * Define (as per instruction) how to map EXP values
	 * to TC indexes
	 */
	for (j = 0; j < MPLS_EXP_NUM; j++)
		e2ti->e2t[j] = instr->mir_exp2tc.e2t[j];


	*data = (void *)e2ti;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp2tc)
{
	struct mpls_exp2tcindex_info *e2ti = data;
	int j;

	MPLS_ENTER;

	for (j = 0; j < MPLS_EXP_NUM; j++)
		instr->mir_exp2tc.e2t[j] = e2ti->e2t[j];

	MPLS_EXIT;
}
#endif






/*********************************************************************
 * MPLS_OP_EXP2DS
 * DESC   : "Changes the DS field of the IPv4/IPv6 packet according to"
 *          "the EXP bits in label entry"
 * EXEC   : mpls_op_exp2ds
 * BUILD  : mpls_build_opcode_exp2ds
 * UNBUILD: mpls_unbuild_opcode_exp2ds
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : true
 * OUTPUT : false
 * DATA   : e2di (struct mpls_exp2dsmark_info*) - No ILM/NHLFE are held.
 * LAST   : false
 *********************************************************************/
inline MPLS_IN_OPCODE_PROTOTYPE(mpls_in_op_exp2ds)
{
	struct mpls_exp2dsmark_info *e2di = data;
	unsigned short ds = MPLSCB(*pskb)->exp & 0x7;
	MPLS_ENTER;
	if (e2di->e2d[ds] == 0xff)
		return MPLS_RESULT_SUCCESS;

	MPLSCB(*pskb)->prot->change_dsfield(*pskb, e2di->e2d[ds]);
	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}




MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_exp2ds)
{
	struct mpls_exp2dsmark_info *e2di = NULL;
	int j;
	MPLS_ENTER
	*data = NULL;
	/*
	 * Allocate e2di object
	 */
	e2di = kzalloc(sizeof(*e2di), GFP_ATOMIC);
	if (unlikely(!e2di)) {
		MPLS_DEBUG("error building DSMARK info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) how to map EXP values
	 * to DS fields.
	 */
	for (j = 0; j < MPLS_EXP_NUM; j++)
		e2di->e2d[j] = instr->mir_exp2ds.e2d[j];

	*data = (void *)e2di;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_exp2ds)
{
	struct mpls_exp2dsmark_info *e2di = data;
	int j;

	MPLS_ENTER;

	for (j = 0; j < MPLS_EXP_NUM; j++)
		instr->mir_exp2ds.e2d[j] = e2di->e2d[j];

	MPLS_EXIT;
}


/*********************************************************************
 * MPLS_OP_TC2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the TC index in skb & mask"
 * EXEC   : mpls_op_tc2exp
 * BUILD  : mpls_build_opcode_tc2exp
 * UNBUILD: mpls_unbuild_opcode_tc2exp
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : false
 * OUTPUT : true
 * DATA   : t2ei (struct mpls_tcindex2exp_info*) - No ILM/NHLFE are held.
 * LAST   : false
 *********************************************************************/
#ifdef CONFIG_NET_SCHED

inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_tc2exp)
{
	struct mpls_tcindex2exp_info *t2ei = data;
	unsigned short tc;
	MPLS_ENTER;
	tc = (*pskb)->tc_index & t2ei->t2e_mask;
	if (t2ei->t2e[tc] != 0xFF)
		MPLSCB(*pskb)->exp = t2ei->t2e[tc];

	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_tc2exp)
{
	struct mpls_tcindex2exp_info *t2ei = NULL;
	int j;
	MPLS_ENTER;
	*data = NULL;
	/*
	 * Allocate t2ei object
	 */
	t2ei = kzalloc(sizeof(*t2ei), GFP_ATOMIC);
	if (unlikely(!t2ei)) {
		MPLS_DEBUG("TC2EXP error building EXP info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) the mask to apply
	 */
	t2ei->t2e_mask = instr->mir_tc2exp.t2e_mask;
	if (t2ei->t2e_mask >= MPLS_TCINDEX_NUM) {
		MPLS_DEBUG("TC2EXP mask(%02x) too large\n", t2ei->t2e_mask);
		kfree(t2ei);
		MPLS_EXIT;
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map TC indexes
	 * to EXP bits
	 */
	for (j = 0; j < MPLS_TCINDEX_NUM; j++) {
		int i;
		for (i = j; i < MPLS_TCINDEX_NUM; i++) {
			if ((j & t2ei->t2e_mask) == (i & t2ei->t2e_mask)
				&& !t2ei->t2e[i])
				t2ei->t2e[i] = instr->mir_tc2exp.t2e[j];
		}
	}
	*data = (void *)t2ei;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_tc2exp)
{
	struct mpls_tcindex2exp_info *t2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_tc2exp.t2e_mask = t2ei->t2e_mask;

	for (j = 0; j < MPLS_TCINDEX_NUM; j++)
		instr->mir_tc2exp.t2e[j] = t2ei->t2e[j];

	MPLS_EXIT;
}
#endif



/*********************************************************************
 * MPLS_OP_DS2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the DS field of the IPv4/IPv6 packet"
 * EXEC   : mpls_op_ds2exp
 * BUILD  : mpls_build_opcode_ds2exp
 * UNBUILD: mpls_unbuild_opcode_ds2exp
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : false
 * OUTPUT : true
 * DATA   : d2ei (struct mpls_dsmark2exp_info*) - No ILM/NHLFE are held.
 * LAST   : false
 *********************************************************************/
inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_ds2exp)
{
	struct mpls_dsmark2exp_info *d2ei = data;
	unsigned char ds;
	MPLS_ENTER;
	ds = MPLSCB(*pskb)->prot->get_dsfield(*pskb) & d2ei->d2e_mask;

	if (d2ei->d2e[ds] != 0xFF)
		MPLSCB(*pskb)->exp = d2ei->d2e[ds];

	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}



MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_ds2exp)
{
	struct mpls_dsmark2exp_info *d2ei  = NULL;
	int j;
	MPLS_ENTER;
	*data = NULL;
	/*
	 * Allocate d2ei object
	 */
	d2ei = kzalloc(sizeof(*d2ei), GFP_ATOMIC);
	if (unlikely(!d2ei)) {
		MPLS_DEBUG("DS2EXP error building EXP info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	/*
	 * Define (as per instruction) the mask to apply
	 */
	d2ei->d2e_mask = instr->mir_ds2exp.d2e_mask;
	if (d2ei->d2e_mask >= MPLS_DSMARK_NUM) {
		MPLS_DEBUG("DS2EXP mask(%02x) too large\n", d2ei->d2e_mask);
		kfree(d2ei);
		MPLS_EXIT;
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map DS marks
	 * to EXP bits
	 */
	for (j = 0; j < MPLS_DSMARK_NUM; j++) {
		int i;
		for (i = j; i < MPLS_DSMARK_NUM; i++) {
			if (((j & d2ei->d2e_mask) == (i & d2ei->d2e_mask))
				&& !d2ei->d2e[j]) {
				MPLS_DEBUG("i: %d, j: %d, value: %d\n",
					i, j, instr->mir_ds2exp.d2e[j]);
				d2ei->d2e[i] = instr->mir_ds2exp.d2e[j];
			}
		}
	}
	*data = (void *)d2ei;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_ds2exp)
{
	struct mpls_dsmark2exp_info *d2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_ds2exp.d2e_mask = d2ei->d2e_mask;

	for (j = 0; j < MPLS_DSMARK_NUM; j++)
		instr->mir_ds2exp.d2e[j] = d2ei->d2e[j];

	MPLS_EXIT;
}





/*********************************************************************
 * MPLS_OP_NF2EXP
 * DESC   : "Changes the EXP bits of the topmost label entry according"
 *          "to the NF mark of the socket buffer".
 * EXEC   : mpls_op_nf2exp
 * BUILD  : mpls_build_opcode_nf2exp
 * UNBUILD: mpls_build_opcode_nf2exp
 * CLEAN  : mpls_clean_opcode_generic
 * INPUT  : false
 * OUTPUT : true
 * DATA   : n2ei (struct mpls_nfmark2exp_info*) - No ILM/NHLFE are held.
 * LAST   : false
 *********************************************************************/

#ifdef CONFIG_NETFILTER
inline MPLS_OUT_OPCODE_PROTOTYPE(mpls_out_op_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei = NULL;
	unsigned short nf = 0;
	MPLS_ENTER;
	BUG_ON(!data);
	BUG_ON(!*pskb);
	n2ei = data;
	nf   = (*pskb)->mark & n2ei->n2e_mask;
	if (n2ei->n2e[nf] != 0xFF)
		MPLSCB(*pskb)->exp = n2ei->n2e[nf];

	MPLS_EXIT;
	return MPLS_RESULT_SUCCESS;
}


MPLS_BUILD_OPCODE_PROTOTYPE(mpls_build_opcode_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei  = NULL;
	int j;
	MPLS_ENTER;
	*data = NULL;
	/*
	 * Allocate d2ei object
	 */
	n2ei = kzalloc(sizeof(*n2ei), GFP_ATOMIC);
	if (unlikely(!n2ei)) {
		MPLS_DEBUG("NF2EXP error building EXP info\n");
		MPLS_EXIT;
		return -ENOMEM;
	}

	/*
	 * Define (as per instruction) the mask to apply
	 */
	n2ei->n2e_mask = instr->mir_nf2exp.n2e_mask;
	if (n2ei->n2e_mask >= MPLS_NFMARK_NUM) {
		MPLS_DEBUG("NF2EXP mask(%02x) too large\n",
			n2ei->n2e_mask);
		kfree(n2ei);
		MPLS_EXIT;
		return -EINVAL;
	}

	/*
	 * Define (as per instruction) how to map NF marks
	 * to EXP bits
	 */
	for (j = 0; j < MPLS_NFMARK_NUM; j++) {
		int i;
		for (i = 0; i < MPLS_NFMARK_NUM; i++) {
			if ((j & n2ei->n2e_mask) == (i & n2ei->n2e_mask) &&
				!n2ei->n2e[i])
				n2ei->n2e[i] = instr->mir_nf2exp.n2e[j];
		}
	}
	*data = (void *)n2ei;
	MPLS_EXIT;
	return 0;
}

MPLS_UNBUILD_OPCODE_PROTOTYPE(mpls_unbuild_opcode_nf2exp)
{
	struct mpls_nfmark2exp_info *n2ei = data;
	int j;

	MPLS_ENTER;

	instr->mir_nf2exp.n2e_mask = n2ei->n2e_mask;

	for (j = 0; j < MPLS_NFMARK_NUM; j++)
		instr->mir_nf2exp.n2e[j] = n2ei->n2e[j];

	MPLS_EXIT;
}

#endif








/*********************************************************************
 * Main data type to hold metainformation on opcodes
 * IN      : Function pointer to execute in ILM object
 * OUT     : Function pointer to execute in NHLFE object
 * BUILD   : Function pointer to build the opcode
 * CLEANUP : Function pointer to clean the opcode
 * EXTRA   : Ready to transmit (SET)
 * MSG     : Human readable format
 *********************************************************************/

struct mpls_ops mpls_ops[MPLS_OP_MAX] = {
	[MPLS_OP_DROP] = {
			.in      = mpls_op_drop,
			.out     = mpls_op_drop,
			.build   = mpls_build_op_drop,
			.unbuild = NULL,
			.cleanup = mpls_clean_op_drop,
			.extra   = 0,
			.msg     = "DROP",
	},
	[MPLS_OP_POP] = {
			.in      = mpls_in_op_pop,
			.out     = NULL,
			.build   = mpls_build_opcode_pop,
			.unbuild = NULL,
			.cleanup = NULL,
			.extra   = 0,
			.msg     = "POP",
	},
	[MPLS_OP_PEEK] = {
			.in      = mpls_in_op_peek,
			.out     = NULL,
			.build   = mpls_build_opcode_peek,
			.unbuild = NULL,
			.cleanup = NULL,
			.extra   = 0,
			.msg     = "PEEK",
	},
	[MPLS_OP_PUSH] = {
			.in      = NULL,
			.out     = mpls_op_push,
			.build   = mpls_build_opcode_push,
			.unbuild = mpls_unbuild_opcode_push,
			.cleanup = mpls_clean_opcode_push,
			.extra   = 0,
			.msg     = "PUSH",
	},
	[MPLS_OP_DLV] = {
			.in      = mpls_in_op_dlv,
			.out     = NULL,
			.build   = mpls_build_opcode_dlv,
			.unbuild = NULL,
			.cleanup = NULL,
			.extra   = 0,
			.msg     = "DLV",
	},
	[MPLS_OP_FWD] = {
			.in      = mpls_op_fwd,
			.out     = NULL,
			.build   = mpls_build_opcode_fwd,
			.unbuild = mpls_unbuild_opcode_fwd,
			.cleanup = mpls_clean_opcode_fwd,
			.extra   = 0,
			.msg     = "FWD",
	},
#ifdef CONFIG_NETFILTER
	[MPLS_OP_NF_FWD] = {
			.in      = NULL,
			.out     = mpls_out_op_nf_fwd,
			.build   = mpls_build_opcode_nf_fwd,
			.unbuild = mpls_unbuild_opcode_nf_fwd,
			.cleanup = mpls_clean_opcode_nf_fwd,
			.extra   = 0,
			.msg     = "NF_FWD",
	},
#endif
	[MPLS_OP_DS_FWD] = {
			.in      = NULL,
			.out     = mpls_out_op_ds_fwd,
			.build   = mpls_build_opcode_ds_fwd,
			.unbuild = mpls_unbuild_opcode_ds_fwd,
			.cleanup = mpls_clean_opcode_ds_fwd,
			.extra   = 0,
			.msg     = "DS_FWD",
	},
	[MPLS_OP_EXP_FWD] = {
			.in      = mpls_op_exp_fwd,
			.out     = mpls_op_exp_fwd,
			.build   = mpls_build_opcode_exp_fwd,
			.unbuild = mpls_unbuild_opcode_exp_fwd,
			.cleanup = mpls_clean_opcode_exp_fwd,
			.extra   = 0,
			.msg     = "EXP_FWD",
	},
	[MPLS_OP_SET_RX] = {
			.in      = mpls_in_op_set_rx,
			.out     = NULL,
			.build   = mpls_build_opcode_set_rx,
			.unbuild = mpls_unbuild_opcode_set_rx,
			.cleanup = mpls_clean_opcode_set_rx,
			.extra   = 0,
			.msg     = "SET_RX",
	},
	[MPLS_OP_SET] = {
			.in      = NULL,
			.out     = mpls_out_op_set,
			.build   = mpls_build_opcode_set,
			.unbuild = mpls_unbuild_opcode_set,
			.cleanup = mpls_clean_opcode_set,
			.extra   = 1,
			.msg     = "SET",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_SET_TC] = {
			.in      = mpls_op_set_tc,
			.out     = mpls_op_set_tc,
			.build   = mpls_build_opcode_set_tc,
			.unbuild = mpls_unbuild_opcode_set_tc,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "SET_TC",
	},
	[MPLS_OP_SET_DS] = {
			.in      = mpls_in_op_set_ds,
			.out     = NULL,
			.build   = mpls_build_opcode_set_ds,
			.unbuild = mpls_unbuild_opcode_set_ds,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "SET_DS",
	},
#endif
	[MPLS_OP_SET_EXP] = {
			.in      = NULL,
			.out     = mpls_op_set_exp,
			.build   = mpls_build_opcode_set_exp,
			.unbuild = mpls_unbuild_opcode_set_exp,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "SET_EXP",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_EXP2TC] = {
			.in      = mpls_op_exp2tc,
			.out     = mpls_op_exp2tc,
			.build   = mpls_build_opcode_exp2tc,
			.unbuild = mpls_unbuild_opcode_exp2tc,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "EXP2TC",
	},
#endif
	[MPLS_OP_EXP2DS] = {
			.in      = mpls_in_op_exp2ds,
			.out     = NULL,
			.build   = mpls_build_opcode_exp2ds,
			.unbuild = mpls_unbuild_opcode_exp2ds,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "EXP2DS",
	},
#ifdef CONFIG_NET_SCHED
	[MPLS_OP_TC2EXP] = {
			.in      = NULL,
			.out     = mpls_out_op_tc2exp,
			.build   = mpls_build_opcode_tc2exp,
			.unbuild = mpls_unbuild_opcode_tc2exp,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "TC2EXP",
	},
#endif
	[MPLS_OP_DS2EXP] = {
			.in      = NULL,
			.out     = mpls_out_op_ds2exp,
			.build   = mpls_build_opcode_ds2exp,
			.unbuild = mpls_unbuild_opcode_ds2exp,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "DS2EXP",
	},
#ifdef CONFIG_NETFILTER
	[MPLS_OP_NF2EXP] = {
			.in      = NULL,
			.out     = mpls_out_op_nf2exp,
			.build   = mpls_build_opcode_nf2exp,
			.unbuild = mpls_unbuild_opcode_nf2exp,
			.cleanup = mpls_clean_opcode_generic,
			.extra   = 0,
			.msg     = "NF2EXP",
	},
#endif
};
