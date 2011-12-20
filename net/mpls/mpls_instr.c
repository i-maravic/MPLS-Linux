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
 *          Igor Maravić     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/mpls.h>

static struct kmem_cache *instr_cachep;

/**
 *	mpls_instr_alloc - Allocate a mpls_instruction object
 *	@opcode: opcode num.
 **/

struct mpls_instr *mpls_instr_alloc(unsigned short opcode)
{
	struct mpls_instr  *mi;
	MPLS_ENTER;
	mi = kmem_cache_alloc(instr_cachep, GFP_KERNEL);
	memset(mi, 0, sizeof(struct mpls_instr));
	if (likely(mi))
		mi->mi_opcode = opcode;
	else {
		printk(KERN_ERR "MPLS: Couldn't allocate mpls_instr!\n");
		return NULL;
	}
	MPLS_EXIT;
	return mi;
}

/**
 *	mpls_instr_release - destructor for mpls instruction.
 *	@mi: this instruction
 *
 **/

void mpls_instr_release(struct mpls_instr *mi)
{
	unsigned short op = mi->mi_opcode;
	void *data        = mi->mi_data;
	void *parent      = mi->mi_parent;
	enum mpls_dir dir = mi->mi_dir;

	MPLS_ENTER;
	BUG_ON(!mi);

	if (mpls_ops[op].cleanup)
		mpls_ops[op].cleanup(data, parent, dir);

	kmem_cache_free(instr_cachep, mi);
	MPLS_EXIT;
}


/**
 *	mpls_instrs_free - free an instruction set.
 *	@instr:       Instruction list
 *
 **/

void mpls_instrs_free(struct mpls_instr *list)
{
	struct mpls_instr *mi  = list;
	struct mpls_instr *tmp = NULL;

	MPLS_ENTER;
	while (mi) {
		tmp = mi->mi_next;
		mpls_instr_release(mi);
		mi = tmp;
	}
	MPLS_EXIT;
}

/**
 *	mpls_instrs_build - build up an instruction set.
 *	@mie:	 Instruction Element array
 *	@instr:       Instruction list [OUT]
 *	@length:      Number of valid entries in the array
 *	@dir:	 MPLS_IN for ILMs (ILM) or MPLS_OUT for NHLFEs (NHLFE).
 *	@parent:      ILM/NHLFE "parent object".
 *
 *	This function constructs a "instr/operation set", the set of
 *	opcodes to execute with the corresponding data for a given ILM/NHLFE
 *	object.
 *
 *	Returns the number of valid entries.
 **/

int mpls_instrs_build(struct mpls_instr_elem *mie,
		struct mpls_instr **instr, int length,
		enum mpls_dir dir, void *parent)
{

	struct mpls_instr **pmi = instr;  /* Instruction List */
	unsigned short opcode = 0;	      /* Opcode interator */
	unsigned short i = 0;             /* Element iterator */
	int last_able = 0;                /* This must be true at end */
	MPLS_BUILD_OPCODE_PROTOTYPE(*f);  /* Build Operation */
	struct mpls_instr *mi;            /* MPLS Instruction Iterator */
	void *data;
	int ret = -ENXIO;
	int push_is_next = 0;
	int ops_counter[MPLS_OP_MAX] = {0};
	MPLS_ENTER;

	BUG_ON(!mie);
	/* Iterate the instr set */
	for (i = 0; i < length; i++) {
		if (last_able) {
			printk(KERN_ERR "MPLS: No ops are allowed"
					" after op %s\n", mpls_ops[opcode].msg);
			goto rollback;
		}

		opcode  = mie[i].mir_opcode;
		if (opcode == MPLS_OP_DLV && i != 0) {
			printk(KERN_ERR "MPLS: Op %s can exist"
					" only alone\n", mpls_ops[opcode].msg);
			goto rollback;
		}

		if (push_is_next == 1 && opcode != MPLS_OP_PUSH) {
			printk(KERN_ERR "MPLS: set_exp or tc2exp or ds2exp"
					" or nf2exp must be folowed by push\n");
			goto rollback;
		} else
			push_is_next = 0;

		/*
		 * after this ops push must come next!
		 */
		if (opcode == MPLS_OP_SET_EXP ||
			opcode == MPLS_OP_TC2EXP ||
			opcode == MPLS_OP_DS2EXP ||
			opcode == MPLS_OP_NF2EXP)
			push_is_next = 1;

		ops_counter[opcode]++;
		switch (opcode) {
		case MPLS_OP_POP:
		case MPLS_OP_PUSH:
		case MPLS_OP_SET_EXP:
		case MPLS_OP_TC2EXP:
		case MPLS_OP_DS2EXP:
		case MPLS_OP_NF2EXP:
			/*This ops are only ops that can be caled more then once
				in instruction stack*/
			break;
		default:
			if (ops_counter[opcode] > 1) {
				printk(KERN_ERR "MPLS: There can be only one"
						" op of type %s\n",
						mpls_ops[opcode].msg);
				goto rollback;
			}
			break;
		}

		f  = mpls_ops[opcode].build;
		if (unlikely(!f))
			goto rollback;

		mi = mpls_instr_alloc(opcode);
		if (unlikely(!mi))
			goto rollback;

		data = NULL;
		*pmi = mi;

		/* Build the opcode.
		 * Input : parent ILM/NHLFE, elem & direcion.
		 * Output: cumul pushes for this ILM/NHLFE,last?, data */
		ret = f(&mie[i], dir, parent, &data, &last_able);
		if (ret)
			goto rollback;

		mi->mi_data = data;
		mi->mi_parent = parent;
		mi->mi_dir = dir;
		pmi = &mi->mi_next;
	}

	/* Make sure the last one was valid */
	if (!last_able) {
		printk(KERN_ERR "MPLS: invalid last op %s, len = %d(%d)\n",
				mpls_ops[opcode].msg, i, length);
		goto rollback;
	}

	BUG_ON(!(*instr));

	/*
	 * it is possible that the MTU of a NHLFE may have changed.
	 * to be paranoid, flush the layer 3 caches
	 */
	mpls_proto_cache_flush_all(&init_net);
	MPLS_EXIT;
	return i;

rollback:
	mi = *instr;
	mpls_instrs_free(mi);
	*instr = NULL;
	MPLS_EXIT;
	return 0;
}

void mpls_instrs_unbuild(struct mpls_instr *instr, struct mpls_instr_req *req)
{
	MPLS_UNBUILD_OPCODE_PROTOTYPE(*func);
	struct mpls_instr *mi;
	int c = 0;

	MPLS_ENTER;

	for_each_instr(instr, mi) {
		req->mir_instr[c].mir_opcode = mi->mi_opcode;
		func = mpls_ops[mi->mi_opcode].unbuild;

		if (func)
			func(&req->mir_instr[c], mi->mi_data);
		c++;
	}

	req->mir_instr_length = c;

	MPLS_EXIT;
}

int __init mpls_instr_init(void)
{
	MPLS_ENTER;

	instr_cachep = kmem_cache_create("instr_cache",
		sizeof(struct mpls_instr), 0,
		SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	if (!instr_cachep) {
		printk(KERN_ERR "MPLS: failed to alloc instr_cache\n");
		MPLS_EXIT;
		return -ENOMEM;
	}
	MPLS_EXIT;
	return 0;
}

void mpls_instr_exit(void)
{
	MPLS_ENTER;
	if (instr_cachep)
		kmem_cache_destroy(instr_cachep);

	MPLS_EXIT;
}

