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
#include <getopt.h>

#include "xen-utils.h"

#ifdef XENCTRL_HAS_XC_INTERFACE
#define libxc_handle xc_interface*
#else
#define libxc_handle int
#endif

static char *get_vncport(struct xs_handle *xsh, uint32_t domid)
{
	unsigned int len;
	char *path;
	char *s;

    if (asprintf(&path, "/local/domain/%u/console/vnc-port", domid) < 0)
        return NULL;
	
	s = xs_read(xsh, XBT_NULL, path, &len);
    free(path);
	
	return s;
}

static char *domid_to_domname(struct xs_handle *xsh, uint32_t domid)
{
	unsigned int len;
	char *path;
	char *s;
	
    if (asprintf(&path, "/local/domain/%u/vm", domid) < 0)
        return NULL;
    
	s = xs_read(xsh, XBT_NULL, path, &len);
    free(path);

    if (asprintf(&path, "%s/name", s) < 0) {
        free(s);
        return NULL;
    }
    
    free(s);
    s = xs_read(xsh, XBT_NULL, path, &len);
    free(path);

	return s;
}

static void print_dom_expanded(struct xs_handle *xsh,
                               xc_dominfo_t dominfo,
                               const char *name,
                               int show_long)
{
    unsigned long dommem = (dominfo.nr_pages * (XC_PAGE_SIZE / 1024UL)) / 1024UL;
    char *vncport = get_vncport(xsh, dominfo.domid);
    char *uuid = domid_to_vm_uuid(xsh, dominfo.domid);

    printf("Name:   %s\n", name);
    printf("ID:     %d\n", dominfo.domid);
    printf("Mem:    %lu\n", dommem);
    printf("VCPUs:  %d\n", dominfo.nr_online_vcpus); 
    printf("State:  %c%c%c%c%c\n",
           dominfo.running ? 'r' : '-',
           dominfo.blocked ? 'b' : '-',
           dominfo.paused ? 'p' : '-',
           dominfo.dying ? 'd' : '-',
           dominfo.crashed ? 'c' : '-');
    printf("Time:   %-8.1f\n", ((float)dominfo.cpu_time / 1e9));
    if (show_long) {
        printf("VPort:	%s\n", vncport ? vncport : "Noport");
        printf("UUID:   %s\n", uuid+4);
    }
}

static void print_dom(struct xs_handle *xsh,
                      xc_dominfo_t dominfo,
                      const char *name,
                      int show_long)
{
    unsigned long dommem = (dominfo.nr_pages * (XC_PAGE_SIZE / 1024UL)) / 1024UL;
    char *vncport = get_vncport(xsh, dominfo.domid);
    char *uuid = domid_to_vm_uuid(xsh, dominfo.domid);

    if (show_long)
        printf("%-40s %5d %5lu %5d      %c%c%c%c%c  %8.1f  %s  %s\n",
               name,
               dominfo.domid,
               dommem,
               dominfo.nr_online_vcpus,
               dominfo.running ? 'r' : '-',
               dominfo.blocked ? 'b' : '-',
               dominfo.paused ? 'p' : '-',
               dominfo.dying ? 'd' : '-',
               dominfo.crashed ? 'c' : '-',
               ((float)dominfo.cpu_time / 1e9),
               vncport ? vncport : "Noport",
               uuid + 4);
    else
        printf("%-40s %5d %5lu %5d      %c%c%c%c%c  %8.1f\n",
               name,
               dominfo.domid,
               dommem,
               dominfo.nr_online_vcpus,
               dominfo.running ? 'r' : '-',
               dominfo.blocked ? 'b' : '-',
               dominfo.paused ? 'p' : '-',
               dominfo.dying ? 'd' : '-',
               dominfo.crashed ? 'c' : '-',
               ((float)dominfo.cpu_time / 1e9));
}

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-l|--long] [domname]\n", name);

}

char *domid_to_vm_uuid(struct xs_handle *xsh, uint32_t domid)
{
	unsigned int len;
	char *path;
	char *s;
	
    if (asprintf(&path, "/local/domain/%u/vm", domid) < 0)
        return NULL;
    
	s = xs_read(xsh, XBT_NULL, path, &len);
    free(path);
    
	return s;
}

int xlist(int argc, char **argv)
{
	int rcode = 1;
	xc_dominfo_t *info = NULL;
	uint32_t first_dom = 0;
	int max_doms = 1024, nr_doms, i;
#ifdef XENCTRL_HAS_XC_INTERFACE
    libxc_handle xc_handle = NULL;
#else
    libxc_handle xc_handle = 0;
#endif
	struct xs_handle *xsh = NULL;
    char *domname;
    char *req_domname = NULL;
    int show_long = 0;
    int c;
    static struct option longopts[] = {
        {"long", no_argument, NULL, 'l'},
        {0, 0, 0, 0}
    };
    
    while ((c = getopt_long(argc, argv, "l", longopts, NULL)) != -1) {
		switch (c) {
            case 'l':
                show_long = 1;
                break;
            default:
                usage(argv[0]);
                goto out;
		}
    }

    if (optind < argc)
        req_domname = argv[optind];
    
#ifdef XENCTRL_HAS_XC_INTERFACE
	xc_handle = xc_interface_open(NULL, NULL, 0);
	if (xc_handle == NULL) {
#else
	xc_handle = xc_interface_open();
    if (xc_handle < 0) {
#endif
		perror("Unable to open libxc handle.");
		goto out;
	}

	xsh = xs_daemon_open();
	if (!xsh) {
		perror("Unable to open libxenstore handle.");
		goto out;
	}

	info = calloc(max_doms, sizeof(xc_dominfo_t));
	if (info == NULL) {
		perror("Unable to allocate memory.");
		goto out;
	}

	nr_doms = xc_domain_getinfo(xc_handle, first_dom, max_doms, info);
	if (nr_doms < 0) {
		perror("xc_domain_getinfo() failed.");
		goto out;
	}

    /* Find requested domain and print its info */
    if (req_domname) {
		for (i = 0; i < nr_doms; i++) {
			domname = domid_to_domname(xsh, info[i].domid);
            if (domname == NULL)
                continue;
            
			if (strncmp(req_domname, domname, strlen(req_domname)+1) == 0) {
                print_dom_expanded(xsh, info[i], domname, show_long);
				free(domname);
				rcode = 0;
				goto out;
			}
            free(domname);
		}
        fprintf(stderr, "Unable to find domain '%s'\n", req_domname);
        usage(argv[0]);
        goto out;
    }
    
    /* Not a specific domain requested so print info on all domains */
    if (show_long)
            printf("Name                                        ID   Mem VCPUs\tState\tTime(s)\tVnc-port\tUUID\n");
        else
            printf("Name                                        ID   Mem VCPUs\tState\tTime(s)\t\n");
    
    for (i = 0; i < nr_doms; i++) {
        domname = domid_to_domname(xsh, info[i].domid);
        if (domname == NULL)
            continue;
        print_dom(xsh, info[i], domname, show_long);
        free(domname);
    }

    rcode = 0;
    
out:
	if (xsh)
		xs_daemon_close(xsh);
	if (info)
		free(info);
	if (xc_handle)
		xc_interface_close(xc_handle);
	return rcode;
}
