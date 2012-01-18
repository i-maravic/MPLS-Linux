/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
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
#include <net/route.h>
#include <net/mpls.h>
#include <linux/genetlink.h>
#include <net/net_namespace.h>

/*
 * MPLS info radix tree and corresponding lock
 */
RADIX_TREE(mpls_ilm_tree, GFP_ATOMIC);

DEFINE_SPINLOCK(mpls_ilm_lock);

LIST_HEAD(mpls_ilm_list);

static struct kmem_cache *ilm_cachep;

/**
 *	mpls_destroy_ilm_instrs - Destroy ILM opcodes.
 *	@ilm:	ILM object
 *
 *	This function completely destroys the instruction list for this
 *	ILM object: it unregisters the opcodes from sysfs. When the
 *      refcnt of the instr reaches zero (a file may be opened) they
 *      will be freed.
 *
 *	ilm_instr is set to NULL.
 **/

void mpls_destroy_ilm_instrs(struct mpls_ilm *ilm)
{
	MPLS_ENTER;
	mpls_instrs_free(ilm->ilm_instr);
	ilm->ilm_instr = NULL;
	MPLS_EXIT;
}

/**
 *	mpls_ilm_set_instrs - Set Instruction list for this ILM.
 *	@ilm:   The ILM object ('this')
 *	@mie:   Array of instruction elements set by user
 *	@lenth: Array lenght. Number of valid entries
 *
 *	Return 0 on success.
 *
 *	Called in process context only and may sleep
 **/
int mpls_ilm_set_instrs(struct mpls_in_label_req *mil,
		struct mpls_instr_elem *mie, int length)
{
	struct mpls_ilm *ilm = mpls_get_ilm_label(mil);
	int retval;
	MPLS_ENTER;
	MPLS_EXIT;
	retval = _mpls_ilm_set_instrs(ilm, mie, length);
	mpls_ilm_release(ilm);
	return retval;
}

int _mpls_ilm_set_instrs(struct mpls_ilm *ilm,
		struct mpls_instr_elem *mie, int length)
{
	/* To store (tmp) the linked list of instr. */
	struct mpls_instr *instr_list = NULL;
	struct mpls_instr_req *instr = NULL;
	int no_instr = 0;
	int retval = 0;
	MPLS_ENTER;
	BUG_ON(!ilm);


	/* Commit the new ones */
	if (ilm->ilm_instr) {
		no_instr = mpls_no_instrs(ilm->ilm_instr);
		instr = kmalloc(sizeof(*instr) +
			no_instr*sizeof(struct mpls_instr_elem), GFP_ATOMIC);

		if (unlikely(!instr)) {
			MPLS_EXIT;
			return -1;
		}

		mpls_instrs_unbuild(ilm->ilm_instr, instr);

		mpls_instrs_free(ilm->ilm_instr);
	}

	/* Build temporary opcode set from mie */
	if (!mpls_instrs_build(mie, &instr_list, length, MPLS_IN, ilm)) {
		/*replace with old instructions */
		if (instr)
			mpls_instrs_build(instr->mir_instr, &instr_list,
					instr->mir_instr_length, MPLS_IN, ilm);

		MPLS_DEBUG("Return -1\n");
		retval = -1;
	}


	ilm->ilm_instr = instr_list;
	kfree(instr);
	MPLS_EXIT;
	return retval;
}

/**
 *      mpls_ilm_alloc - construct a mpls_ilm entry.
 *
 **/

struct mpls_ilm *mpls_ilm_alloc(unsigned int key, struct mpls_label *ml,
		/*struct mpls_instr_elem *instr,*/ int instr_len)
{
	struct mpls_ilm *ilm;

	MPLS_ENTER;
	ilm = kmem_cache_alloc(ilm_cachep, GFP_ATOMIC);

	if (unlikely(!ilm)) {
		MPLS_EXIT;
		return NULL;
	}

	ilm->kmem_cachep = ilm_cachep;

	atomic_set(&ilm->refcnt, 1);
	memcpy(&ilm->ilm_label, ml, sizeof(struct mpls_label));
	INIT_LIST_HEAD(&ilm->dev_entry);
	INIT_LIST_HEAD(&ilm->nhlfe_entry);
	INIT_LIST_HEAD(&ilm->global);

	ilm->ilm_instr = NULL;
	ilm->ilm_key = key;
	ilm->ilm_labelspace = ml->ml_labelspace;
	ilm->ilm_age = jiffies;
	ilm->ilm_owner = RTPROT_UNSPEC;

	/*if (_mpls_ilm_set_instrs(ilm, instr, instr_len)) {
		mpls_ilm_release(ilm);
		MPLS_EXIT;
		return NULL;
	}*/

	MPLS_EXIT;
	return ilm;
}
EXPORT_SYMBOL(mpls_ilm_alloc);

/*
 * Some label values are reserved.
 * For incoming label values of "IPv4 EXPLICIT NULL" and "IPv6 EXPLICIT NULL",
 * the instructions to execute are well defined.
 */

/**
 * ILM objects associated to reserved labels
 * RCAS: _IMPORTANT_ reserved labels *ARE NOT* in tree!
 **/

static struct mpls_reserved_labels {
	struct mpls_ilm *ilm;  /* Pointer to the ILM object              */
	char            *msg;  /* Description of the Label               */
	int              bos;  /* 1 -> it MUST be at the bottom of stack */
} mpls_reserved[16] = {
	{ NULL,                "IPv4 EXPLICIT NULL", 1 },
	{ NULL,                "ROUTER ALERT",       0 },
	{ NULL,                "IPv6 EXPLICIT NULL", 1 },
	{ NULL,                "IMPLICIT NULL",      1 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 },
	{ NULL,                "RESERVED",           0 }
};

/**
 *	mpls_insert_ilm - Inserts the given ILM object in the MPLS Input
 *	Information Radix Tree using the given key.
 *	@key: key to use
 *	@ilm: ilm object.
 *
 *	Returns 0 on success, or:
 *		-ENOMEM : unable to allocate node in the radix tree.
 **/

int mpls_insert_ilm(unsigned int key, struct mpls_ilm *ilm)
{
	int retval = 0;
	MPLS_ENTER;
	spin_lock_bh(&mpls_ilm_lock);
	retval = radix_tree_insert(&mpls_ilm_tree, key, ilm);
	if (unlikely(retval)) {
		MPLS_DEBUG("Error create node with key "
				"%u in radix tree\n", key);
		retval = -ENOMEM;
		goto out;
	}

	list_add_rcu(&ilm->global, &mpls_ilm_list);
out:
	spin_unlock_bh(&mpls_ilm_lock);
	MPLS_EXIT;
	return retval;
}

/**
 *	mpls_remove_ilm - Remove the node given the key from the MPLS Input
 *	Information Radix Tree.
 *	@key : key to use
 *
 *	This function deletes the ILM object from the Radix Tree, but please
 *	also note that the object is not freed, and that the caller is
 *	responsible for	decreasing the refcount if necessary.
 **/

void mpls_remove_ilm(unsigned int key)
{
	struct mpls_ilm *ilm = NULL;
	MPLS_ENTER;

	spin_lock_bh(&mpls_ilm_lock);

	ilm = radix_tree_delete(&mpls_ilm_tree, key);
	if (!ilm) {
		MPLS_DEBUG("ILM key %u not found.\n", key);
		goto out;
	}

	list_del_rcu(&ilm->global);

out:
	spin_unlock_bh(&mpls_ilm_lock);
	MPLS_EXIT;
}

/**
 *	mpls_get_ilm - Get a reference to a ILM object.
 *	@key : key to look for in the ILM Radix Tree.
 *
 *	This function can be used to get a reference to a ILM object given a
 *	key.  *	Returns a pointer to the ILM object, NULL on error.
 *
 *	Remark: this function increases the refcount of the ILM object,
 *	since it calls to mpls_ilm_hold. Caller is responsible to
 *	release the object when it is no longer needed (by using
 *	"mpls_ilm_release").
 **/

inline struct mpls_ilm *mpls_get_ilm(unsigned int key)
{
	struct mpls_ilm *ilm = NULL;
	MPLS_ENTER;
	rcu_read_lock();
	ilm = radix_tree_lookup(&mpls_ilm_tree, key);
	smp_read_barrier_depends();
	if (likely(ilm))
		mpls_ilm_hold(ilm);

	rcu_read_unlock();
	MPLS_EXIT;
	return ilm;
}

/**
 *	mpls_get_ilm_by_label - Get a reference to a ILM given an incoming
 *	   label/labelspace.
 *	@label:      Incoming label from network core.
 *	@labelspace: Labelspace of the incoming interface.
 *	@bos:        Status of BOS for the current label being processed
 *
 *	Allows the caller to get a reference to the ILM object given the
 *	label value, and incoming interface/labelspace.
 *	Returns a pointer to the ILM object, NULL on error.
 *	Remark1: This function increases the refcount of the ILM object, since
 *		it calls "mpls_ilm_hold". Caller must release the object
 *		when it is no longer needed.
 *	Remark2: uses the function above.
 **/

inline struct mpls_ilm *mpls_get_ilm_by_label(struct mpls_label *label,
		int labelspace, char bos)
{
	struct mpls_ilm *ilm = NULL;
	MPLS_ENTER;
	/* handle the reserved label range */
	if (label->ml_type == MPLS_LABEL_GEN && label->u.ml_gen < 16) {
		int want_bos = mpls_reserved[label->u.ml_gen].bos;
		MPLS_DEBUG("%s\n", mpls_reserved[label->u.ml_gen].msg);
		ilm = mpls_reserved[label->u.ml_gen].ilm;
		if (unlikely(!ilm)) {
			MPLS_DEBUG("invalid incoming label, dropping\n");
			MPLS_EXIT;
			return NULL;
		}
		mpls_ilm_hold(ilm);
		if (want_bos != bos) {
			mpls_ilm_release(ilm);
			MPLS_DEBUG("invalid incoming labelstack, dropping\n");
			MPLS_EXIT;
			return NULL;
		}
	} else {
		/* not reserved label */
		ilm = mpls_get_ilm(mpls_label2key(labelspace, label));
		if (unlikely(!ilm)) {
			MPLS_DEBUG("unknown incoming label, dropping\n");
			MPLS_EXIT;
			return NULL;
		}
	}
	MPLS_EXIT;
	return ilm;
}

/*
 * mpls_get_ilm - returns existing ilm, if there is no ilm returns NULL
 */
struct mpls_ilm *mpls_get_ilm_label(const struct mpls_in_label_req *mil)
{
	unsigned int key = mpls_label2key(mil->mil_label.ml_labelspace,
		&mil->mil_label);
	struct mpls_ilm *ilm = mpls_get_ilm(key);
	MPLS_ENTER;
	MPLS_EXIT;
	return ilm;
}

/**
 *	mpls_is_reserved_label - return 1 if label is reserved.
 *	@label - label to check.
 **/

static inline int mpls_is_reserved_label(const struct mpls_label *label)
{
	BUG_ON(!label);
	MPLS_ENTER;
	if (unlikely((label->ml_type == MPLS_LABEL_GEN) &&
		     (label->u.ml_gen > MPLS_IPV6_EXPLICIT_NULL) &&
		     (label->u.ml_gen < 16))) {
		MPLS_EXIT;
		return 1;
	}
	MPLS_EXIT;
	return 0;
}




/**
 *	mpls_add_in_label - Add a label to the incoming tree.
 *	@in : mpls_in_label_req
 *
 *	Process context entry point to add an entry (ILM) in the incoming label
 *	map database. It adds new corresponding node to the Incoming Radix Tree.
 *	It sets the ILM object reference count to 1, the ilm age to jiffies,
 *	the default instruction set (POP,PEEK) and initializes
 *	both the dev_entry and nhlfe_entry lists. The node's key is set to the
 *	mapped	key from the label/labelspace in the request.
 *
 *	Returns added ilm entry on success, or err pointer.
 **/

struct mpls_ilm *mpls_add_in_label(const struct mpls_in_label_req *in)
{
	struct mpls_ilm *ilm     = NULL; /* New ILM to insert */
	struct mpls_label *ml    = NULL; /* Requested Label */
	unsigned int key         = 0;    /* Key to use */
	/*struct mpls_instr_elem instr[2];*/

	MPLS_ENTER;

	BUG_ON(!in);
	ml = (struct mpls_label *)&in->mil_label;

	if (mpls_is_reserved_label(ml)) {
		MPLS_DEBUG("Unable to add reserved label to ILM\n");
		MPLS_EXIT;
		return ERR_PTR(-EINVAL);
	}

	/* Obtain key */
	key = mpls_label2key(ml->ml_labelspace, ml);

	/* Check if the node already exists */
	ilm = mpls_get_ilm(key);
	if (unlikely(ilm)) {
		printk(KERN_INFO "MPLS: node %u already exists\n", key);
		mpls_ilm_release(ilm);
		MPLS_EXIT;
		return ERR_PTR(-EEXIST);
	}

	/*
	 * Allocate a new input Information/Label,
	 */

	/*instr[0].mir_direction = MPLS_IN;
	instr[0].mir_opcode    = MPLS_OP_POP;
	instr[1].mir_direction = MPLS_IN;
	instr[1].mir_opcode    = MPLS_OP_PEEK;*/

	ilm = mpls_ilm_alloc(key, ml, /*instr,*/ 2);
	if (unlikely(!ilm)) {
		MPLS_EXIT;
		return ERR_PTR(-ENOMEM);
	}

	ilm->ilm_owner = in->mil_owner;

	/* Insert into ILM tree */
	if (unlikely(mpls_insert_ilm(key, ilm))) {
		mpls_ilm_release(ilm);
		MPLS_EXIT;
		return ERR_PTR(-ENOMEM);
	}
	MPLS_EXIT;
	return ilm;
}

/**
 *	mpls_del_in_label - Del a label from the incoming tree (ILM)
 *	@in : mpls_in_label_req
 *
 *	User context entry point.
 *
 *	This function does the work of actually 'free'ing a ILM data structure.
 *	It first removes an incoming label from the incoming radix tree (that
 *	is, from the ILM). It constructs the associated key from the
 *	label/labelspace in the request.
 *
 *	Then sends an event notifying userland that the ILM is going a way,
 *	then finally schedules the ILM for freeing.
 **/

int mpls_del_in_label(struct mpls_in_label_req *in, int seq, int pid)
{
	struct mpls_ilm   *ilm = NULL;
	struct mpls_label *ml  = NULL;
	unsigned int       key = 0;

	MPLS_ENTER;
	BUG_ON(!in);
	ml  = &in->mil_label;
	key = mpls_label2key(ml->ml_labelspace, ml);

	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm)) {
		MPLS_DEBUG("Node %u was not in tree\n", key);
		MPLS_EXIT;
		return  -ESRCH;
	}

	/* Remove an ILM from the tree */
	mpls_remove_ilm(key);

	/* Release the refcnt taken on mpls_get_ilm() */
	mpls_ilm_release(ilm);

	/* we're still holding a ref to the ILM, so it is safe to
	 * call mpls_ilm_event */
	mpls_ilm_event(MPLS_GRP_ILM_NAME,
			MPLS_CMD_DELILM, ilm, seq, pid);
	/* remove the instructions from the ILM to release
	 * our references to NHLFE's */
	mpls_destroy_ilm_instrs(ilm);

	/*this release are going to drop ilm*/
	mpls_ilm_release(ilm);
	MPLS_EXIT;
	return 0;
}

/**
 *	mpls_del_ilm - Del a label from the incoming tree (ILM)
 *	@in : mpls_in_label_req
 *
 *	User context entry point.
 *
 *	This function does the work of actually 'free'ing a ILM data structure.
 *	It first removes an incoming label from the incoming radix tree (that
 *	is, from the ILM). It constructs the associated key from the
 *	label/labelspace in the request.
 *
 *	Then sends an event notifying userland that the ILM is going a way,
 *	then finally schedules the ILM for freeing.
 **/

int mpls_del_ilm(struct mpls_ilm *ilm, int seq, int pid)
{
	MPLS_ENTER;
	BUG_ON(!ilm);

	/* Remove an ILM from the tree */
	mpls_remove_ilm(ilm->ilm_key);

	/* remove the instructions from the ILM to release
	 * our references to NHLFE's */
	mpls_destroy_ilm_instrs(ilm);

	/* we're still holding a ref to the ILM, so it is safe to
	 * call mpls_ilm_event */
	mpls_ilm_event(MPLS_GRP_ILM_NAME,
			MPLS_CMD_DELILM, ilm, seq, pid);

	/* Release the refcnt taken on mpls_get_ilm()
	 * this release is going to drop nhlfe
	 */
	WARN_ON(atomic_read(&ilm->refcnt) != 1);
	mpls_ilm_release(ilm);

	MPLS_EXIT;
	return 0;
}

/**
 *	mpls_attach_in2out - Establish a xconnect between a ILM and a NHLFE.
 *	@req : crossconnect request.
 *
 *	Establishes a "cross-connect", a forwarding entry. The incoming label
 *	is swapped to the outgoing one. Given the incoming label and label
 *	space
 *
 *	(req), this function updates the ILM object so we change the last instr
 *	from DLV/PEEK to FWD, whose opcode data is a held ref. to the new NHLFE
 *	(as given by the key in req).
 *	Returns 0 on success. Process context only.
 *
 *	Remarks:
 *	    o Be careful when  detroying the NHLFE  object (you should dettach
 *	      the xconnect in order to release the NHLFE)
 **/

int mpls_attach_in2out(struct mpls_xconnect_req *req,
		int seq, int pid)
{
	struct mpls_instr  *mi  = NULL;
	struct mpls_nhlfe  *nhlfe = NULL;
	struct mpls_ilm    *ilm = NULL;
	int  labelspace, key, ret;

	MPLS_ENTER;
	labelspace = req->mx_in.ml_labelspace;

	/* Hold a ref to the ILM */
	key = mpls_label2key(labelspace, &req->mx_in);
	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm))  {
		MPLS_DEBUG("ILM %u does not exist "
					"in radix tree\n", key);
		ret = -ESRCH;
		goto out;
	}

	/* Check that there is an instruction set! */
	if (unlikely(!ilm->ilm_instr)) {
		MPLS_DEBUG("no instructions set!");
		ret = -ESRCH;
		goto out_release;
	}

	/* Hold a ref to the NHLFE */
	key = mpls_label2key(0, &req->mx_out);
	nhlfe = mpls_get_nhlfe(key);
	if (unlikely(!nhlfe)) {
		MPLS_DEBUG("Node %u does not exist "
					"in radix tree\n", key);
		ret = -ESRCH;
		goto out_release;
	}



	/*
	 * Update the instructions: now, instead of "DLV"/"PEEK", now
	 * we "FWD". The NHLFE is not released (is held by the opcode).
	 */

	/* Lookup the last instr */
	mi = mpls_instr_getlast(ilm->ilm_instr);

	switch (mi->mi_opcode) {
	case MPLS_OP_PEEK:
	case MPLS_OP_DROP:
		mi->mi_opcode = MPLS_OP_FWD;
		mi->mi_data   = (void *)nhlfe;
		break;
	case MPLS_OP_FWD:
		mpls_xc_event(MPLS_GRP_XC_NAME, MPLS_CMD_DELXC, ilm,
				_mpls_as_nhlfe(mi->mi_data), 0, 0);
		mpls_nhlfe_release(_mpls_as_nhlfe(mi->mi_data));
		mi->mi_data   = (void *)nhlfe;
		break;
	}
	ret = mpls_xc_event(MPLS_GRP_XC_NAME,
		MPLS_CMD_NEWXC, ilm, nhlfe, seq, pid);
out_release:
	mpls_ilm_release(ilm);
out:
	MPLS_EXIT;
	return ret;
}




/**
 *	mpls_dettach_in2out - Dettach a xconnect between a ILM and a NHLFE.
 *	@req : crossconnect request.
 *
 *	Dettaches a "cross-connect", a forwarding entry. Checks if the latest
 *	instruction is a FWD and updates it to a PEEK. Releases the
 *	corresponding NHLFE (cf. mpls_attach_in2out).
 *
 *	Returns 0 on success. Process context only.
 **/

int mpls_detach_in2out(struct mpls_xconnect_req *req,
		int seq, int pid)
{
	struct mpls_instr  *mi  = NULL;
	struct mpls_nhlfe  *nhlfe = NULL;
	struct mpls_ilm    *ilm = NULL;
	unsigned int        key = 0;
	int labelspace;
	int ret = 0;

	MPLS_ENTER;
	BUG_ON(!req);

	/* Hold a ref to the ILM, The 'in' segment */
	labelspace = req->mx_in.ml_labelspace;
	key = mpls_label2key(labelspace, &(req->mx_in));
	ilm = mpls_get_ilm(key);
	if (unlikely(!ilm)) {
		MPLS_DEBUG("ILM %u does not exist in radix tree\n", key);
		ret = -ESRCH;
		goto out;
	}

	/* Check that there is an instruction set! */
	if (unlikely(!ilm->ilm_instr)) {
		MPLS_DEBUG("No instruction Set!");
		ret = -ESRCH;
		goto out_release;
	}


	/* Fetch the last instr, make sure it is FWD*/
	mi = mpls_instr_getlast(ilm->ilm_instr);

	if (!mi || mi->mi_opcode != MPLS_OP_FWD) {
		MPLS_DEBUG("opcode FWD not found!\n");
		ret = -ENXIO;
		goto out_release;
	}

	/* Get the current held nhlfe for the last in instr */
	nhlfe = mi->mi_data;
	key = mpls_label2key(0, &req->mx_out);

	/* Make sure it is the good nhlfe */
	if (!nhlfe || key != nhlfe->nhlfe_key) {
		/* Do not release the NHLFE, it was invalid */
		MPLS_DEBUG("Invalid NHLFE  %u\n", key);
		ret = -ENXIO;
		goto out_release;
	}

	/* The new last opcode for this ILM is now drop */
	mi->mi_opcode = MPLS_OP_DROP;
	/* With no data */
	mi->mi_data = NULL;

	/* Release the NHLFE held by the Opcode (cf. mpls_attach_in2out) */

	ret = mpls_xc_event(MPLS_GRP_XC_NAME,
			MPLS_CMD_DELXC, ilm, nhlfe, seq, pid);
	mpls_nhlfe_release(nhlfe);
out_release:
	/* Release the ILM after use */
	mpls_ilm_release(ilm);
out:
	MPLS_EXIT;
	return ret;
}

/**
 *	mpls_init_reserved_label - Add an ILM object a reserved label
 *	@label - reserved generic label value
 *	@ilm - ILM object to used for reserved label
 *
 *	Returns 0 on success
 **/

int mpls_add_reserved_label(int label, struct mpls_ilm *ilm)
{
	BUG_ON(label < 0 || label > 15);
	MPLS_ENTER;
	if (mpls_reserved[label].ilm) {
		MPLS_EXIT;
		return -EEXIST;
	}

	mpls_reserved[label].ilm = ilm;

	MPLS_EXIT;
	return 0;
}
EXPORT_SYMBOL(mpls_add_reserved_label);

/**
 *	mpls_del_reserved_label - remove the ILM object for a reserved label
 *	@label - reserved generic label value
 *
 *	Return the ILM object for the user to release
 *
 **/

struct mpls_ilm *mpls_del_reserved_label(int label)
{
	struct mpls_ilm *ilm;
	MPLS_ENTER;
	BUG_ON(label < 0 || label > 15);

	ilm = mpls_reserved[label].ilm;
	mpls_reserved[label].ilm = NULL;
	MPLS_EXIT;
	return ilm;
}
EXPORT_SYMBOL(mpls_del_reserved_label);

int __init mpls_ilm_init(void)
{
	MPLS_ENTER;

	ilm_cachep = kmem_cache_create("ilm_cache",
		sizeof(struct mpls_ilm), 0,
		SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	if (!ilm_cachep) {
		printk(KERN_ERR "MPLS: failed to alloc ilm_cache\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	MPLS_EXIT;
	return 0;
}

void mpls_ilm_exit(void)
{
	MPLS_ENTER;
	if (ilm_cachep)
		kmem_cache_destroy(ilm_cachep);

	MPLS_EXIT;
}
