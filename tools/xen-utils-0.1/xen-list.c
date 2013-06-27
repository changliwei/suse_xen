/*
 * Copyright (C) 2010 Novell, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Wei Kong <wkong@novell.com>
 * Contributor: Jim Fehlig <jfehlig@novell.com>
 *              Chunyan Liu <cyliu@novell.com>
 */

#include <xenctrl.h>
#include <xs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "xen-utils.h"

int main(int argc, char **argv)
{
	int rcode = 1;
        rcode =	xlist(argc, argv);
        return rcode;
}
