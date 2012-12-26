/*****************************************************************************
 * MPLS - Multi Protocol Label Switching
 *
 *      An implementation of the MPLS architecture for Linux.
 *
 * mpls_export.c
 *      - It implements: structures and functions that
 *                       are exported to other modules
 *
 * Authors:
 *          Igor Maravic     <igorm@etf.rs>
 *
 *   (c) 2012        Igor Maravic     <igorm@etf.rs>
 *
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
  ****************************************************************************/

#include <net/mpls.h>
#include <linux/export.h>

struct mpls_ops *mpls_ops = NULL;
EXPORT_SYMBOL(mpls_ops);
