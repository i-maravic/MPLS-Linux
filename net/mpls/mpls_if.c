/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_if.c
 *      - Allocation/deallocation of per netdevice MPLS private data
 *        (labelspace)
 *      - Query/Update netdevice label space functions.
 *
 *      Network devices (e.g. "eth0") are extended with a mpls_ptr
 *      that contain mpls related info, most notably, the per interface
 *      label space.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *****************************************************************************
 */

#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <net/mpls.h>
#include <linux/genetlink.h>
#include <net/net_namespace.h>

/**
 *	mpls_create_if_info - allocate memory for the MPLS net_device extension
 *
 *	See struct net_device and  "void *mpls_ptr; // MPLS specific data"
 *	Returns a pointer to the allocated struct.
 *	RCAS: From process context only. May sleep.
 **/

static struct mpls_interface *mpls_create_if_info(void)
{
	struct mpls_interface *mif =
		kzalloc(sizeof(struct mpls_interface), GFP_KERNEL);
	MPLS_ENTER;
	if (unlikely(!mif)) {
		MPLS_EXIT;
		return NULL;
	}

	mif->labelspace = -1;
	INIT_LIST_HEAD(&mif->list_out);
	INIT_LIST_HEAD(&mif->list_in);
	MPLS_EXIT;
	return mif;
}


/**
 *	__mpls_set_labelspace - Set a label space for the interface.
 *	@dev: device
 *	@labelspace: new labelspace
 *
 *	See mpls_set_labelspace for comments.
 *	Returns 0 on success.
 **/

static int __mpls_set_labelspace(struct net_device *dev,
		int labelspace, int seq, int pid)
{
	struct mpls_interface *mif = dev->mpls_ptr;
	int err;

	MPLS_ENTER;
	if (!mif && labelspace != -1) {
		mif = mpls_create_if_info();
		if (unlikely(!mif)) {
			MPLS_DEBUG("Err: Set labelspace for %s to %d\n",
					dev->name, labelspace);
			MPLS_EXIT;
			return -ENOMEM;
		}
		/* Actual assignment happens here */
		mif->labelspace = labelspace;

		dev->mpls_ptr = (void *)mif;
		MPLS_DEBUG("Set labelspace for %s to %d\n",
				dev->name, labelspace);
	} else {
		if (labelspace == -1) {
			MPLS_DEBUG("Resetting labelspace for %s to %d\n",
					dev->name, -1);
			kfree(dev->mpls_ptr);
			dev->mpls_ptr = NULL;
		} else {
			mif->labelspace = labelspace;
		}

	}
	err = mpls_labelspace_event(MPLS_GRP_LABELSPACE_NAME,
		MPLS_CMD_SETLABELSPACE, dev, seq, pid);
	MPLS_EXIT;
	return err;
}

/**
 *	mpls_set_labelspace - Set a label space for the interface.
 *	@req: mpls_labelspace_req struct with the update data. In particular,
 *	     contains the interface index in req->mls_ifindex, and the new
 *	     labelspace in req->mls_labelspace.
 *
 *	This function assigns a label space to a particular net device. In
 *	the current implementation, the netdev struct is extended with a
 *	mpls_ptr to hold mpls data, which is dynamically allocated here,
 *	using mpls_create_if_info().
 *	Returns 0 on success.
 **/

int mpls_set_labelspace(struct mpls_labelspace_req *req, int seq, int pid)
{
	int result = -1;
	struct net_device *dev =
		dev_get_by_index(&init_net, req->mls_ifindex);

	MPLS_ENTER;
	if (dev) {
		result = __mpls_set_labelspace(dev,
			req->mls_labelspace, seq, pid);
		dev_put(dev);
	}
	MPLS_EXIT;
	return result;
}
