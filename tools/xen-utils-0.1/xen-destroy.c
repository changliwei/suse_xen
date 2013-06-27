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
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "xen-utils.h"

#ifdef _DEBUG
#define DEBUG(_f, _a...) \
        printf("Fun:%s," "Line %d:" _f, __FUNCTION__, __LINE__,##_a)  
#else
#define DEBUG(_f, _a...) ((void)0)
#endif

//Shutdown a domain by signalling this via xenstored
void shutdown_domain(char *domname)
{
	int domid;
	char *vm_uuid = NULL;
	char vmpath[64];
	struct xs_handle *xsh = NULL;

	domid = atoi(domname);
	if (domid == 0) {
		perror("Error, dom 0 could not be shutdown\n");
		return; 
	}

	xsh = xs_daemon_open();
	if (!xsh) {
		perror("Couldn't get xsh handle.");
		return;
	}

	//if self._stateGet() in (DOM_STATE_SHUTDOWN, DOM_STATE_HALTED,):
	//    raise XendError('Domain cannot be shutdown')

	vm_uuid = domid_to_vm_uuid(xsh, domid);
	snprintf(vmpath, sizeof(vmpath), "%s/xend/previous_restart_time", vm_uuid);
	free(vm_uuid);

	xs_rm(xsh, XBT_NULL, vmpath);

	memset(vmpath, '\0', 64); 
	snprintf(vmpath, sizeof(vmpath), "/local/domain/%u/control/shutdown", domid);

	xs_write(xsh, XBT_NULL, vmpath, "poweroff", 9);

	//TODO: How about HVM domain	
	//HVM domain shuts itself down only if it has PV drivers
	//if self.info.is_hvm():
	//    hvm_pvdrv = xc.hvm_get_param(self.domid, HVM_PARAM_CALLBACK_IRQ)
	//    if not hvm_pvdrv:
	//        code = REVERSE_DOMAIN_SHUTDOWN_REASONS[reason]

	free(xsh);
	return;
}

char * device_backend(struct xs_handle *xsh, char *buf, int domid)
{
    char *backend, *resu;
    char path[256];
    char device[256];
    unsigned int len;
    int i;
    
    if(buf == NULL || xsh == NULL)
        return NULL;
    backend = malloc(256);
    if(backend == NULL)
    {
        DEBUG("error to alloc memory\n");
        return NULL;
    }
    for( i = 0; buf[i] != 0x20; i++)
    {
        device[i] = buf[i];
    }
    device[i] = '\0';
    DEBUG(" device:%s \n", device);
    sprintf(path, "/local/domain/%d/device/%s/0/backend",domid, device);
    resu = xs_read(xsh, XBT_NULL, path, &len);
    if(!resu)
    {
        return NULL;
    }
    strcpy(backend,&resu[11]);
    free(resu);
    backend[len-1] = '\0';
    DEBUG("dev:%s, backend :%s\n", device, backend);
    return backend;
}

int notify_backend(struct xs_handle *xsh, char *backend)
{
   char path[256];
   if( xsh == NULL || backend == NULL)
       return -1;
   sprintf(path, "%sonline",backend);
   xs_write(xsh, XBT_NULL, path, "0", 1);
   sprintf(path, "%sstatus",backend);
   xs_write(xsh, XBT_NULL, path, "5", 1); //closing
   return 0;
}

int getDomidByName(struct xs_handle *xsh, char *domname)
{
    int domid = 0, i;
    int __attribute__((__unused__)) ret;
    unsigned int len;
    char path[256];
    char str[256];
    FILE *f;
    char buf[256], *resu;
    if( xsh == NULL || domname == NULL)
        return domid;
    sprintf(path, "xenstore-ls /local/domain > /var/tmp/xdestroy_dom_info.%s", domname);
    ret = system(path);
    sprintf(path, "/var/tmp/xdestroy_dom_info.%s", domname);
    f = fopen(path, "r");
    if (f == NULL)
    {
        DEBUG(" error to open dom info file\n");
        return -1;
    }
    while(1)
    {
        if(fgets(buf, 256, f) == NULL)
            break;
        else
        {
            if(buf[0] != 0x20)
            {
                for( i = 0; buf[i] != 0x20; i++)
                {
                    str[i] = buf[i];
                }
                str[i] = '\0';
                sprintf(path,"/local/domain/%s/name", str);
                resu = xs_read(xsh, XBT_NULL, path, &len);
                if(resu != NULL && !strcmp(resu, domname))
                {
                    domid = atoi(str);
                    free(resu);
                    break;
                }
            }
        }
    }
    fclose(f);
    sprintf(path, "rm /var/tmp/xdestroy_dom_info.%s", domname);
    ret = system(path);
    DEBUG("domid:%d\n", domid);
    return domid;
}

int extra_call(char *domname, int DeviceModel_id)
{
    char logpath[256], buf[256],cmd[256];
    FILE *f;
    int path_len, exec_len, i;
    int __attribute__((__unused__)) ret;
    
    f = fopen("/etc/xen/xend-config.sxp", "r");
    if (f == NULL)
    {
        DEBUG(" error to open xend-config.sxp file\n");
        return -1;
    }
    path_len = strlen("xend-guest-logpath");
    exec_len = strlen("xend-guest-logexec");
    while(1)
    {
        if(fgets(buf, 256, f) == NULL)
            break;
        if(buf[0] == 10 || buf[0] == '#' )
            continue;
        if( strlen(buf) > path_len && !strncmp(buf, "(xend-guest-logpath", path_len))
        {
            strcpy(logpath, (char*)(buf + path_len + 1)); // plus '1' here due to "(" 
            logpath[strlen(logpath)-2] = '\0'; //subtract '1' due to ")" 
            for(i = 0; i < strlen(logpath); i++)
                if(logpath[i] != 32)  //space
                    break;
            if(i < strlen(logpath))     
            {
                sprintf(cmd, "echo %s stop %d `hostname` `date` >> %s", 
                        domname, DeviceModel_id, (char *)(logpath + i));
                DEBUG("%s\n",cmd);
                ret = system(cmd);
            }
            continue;
        }
        if(strlen(buf) > exec_len && !strncmp((char *)(buf+1), "xend-guest-logexec", exec_len))
        {
            strcpy(logpath,(char *)(buf + exec_len + 1)); // plus '1' here due to "(" 
            logpath[strlen(logpath)-2] = '\0'; //subtract '2' due to ")" 
            for(i = 0; i < strlen(logpath); i++)
                if(logpath[i] != 32)  //space
                    break;
            if(i < strlen(logpath))     
            {
                sprintf(cmd, "%s %s stop %d `hostname` `date`", 
                        (char *)(logpath + i), domname, DeviceModel_id);
                DEBUG("--cmd:%s\n",cmd);
                ret = system(cmd);
            }
             
            continue; 
        }
    }
    fclose(f);
    return 0;
}

int destroy_domain(char *domname)
{
	int domid, rcode, i, DMid, status;
	int __attribute__((__unused__)) ret;
#ifdef XENCTRL_HAS_XC_INTERFACE
    xc_interface *xc_handle = NULL;
#else
    int xc_handle = 0;
#endif
    unsigned int len;
	char *s;
	char path[256];
	struct xs_handle *xsh = NULL;
        FILE *f;
        char buf[256];
        char *backend;

	xsh = xs_daemon_open();
	if (!xsh) {
		perror("Couldn't get xsh handle.");
		rcode = 1;
		goto out;
	}
	domid = getDomidByName(xsh, domname);

	if (domid < 1) {
		perror("Error,Can't destroy domId, domId should > 0\n");
        rcode = 1;
        goto out;
	}


#ifdef XENCTRL_HAS_XC_INTERFACE
	xc_handle = xc_interface_open(NULL, NULL, 0);
	if (xc_handle == NULL) {
#else
	xc_handle = xc_interface_open();
    if (xc_handle < 0) {
#endif
		perror("Couldn't open xc handle.");
		rcode = 1;
		goto out;
	}

	/* TODO PCI clean
	paths = self._prepare_phantom_paths()
	if self.dompath is not None:
		self._cleanup_phantom_devs(paths)

	xc_domain_destroy_hook(xc_handle, domid);
	*/

	xc_domain_pause(xc_handle, domid);
	rcode = xc_domain_destroy(xc_handle, domid);
        
        // free Device Model
        sprintf(path,"/local/domain/%d/image/device-model-pid", domid); 
        s = xs_read(xsh, XBT_NULL, path, &len);
        if( s != NULL)
        {
            DMid = atoi(s);
            free(s);
            DEBUG("Deivce Model Id is %d\n", DMid);
        }
        else
        {
            rcode = 1;
            DEBUG("can't read Deivce Model Id\n");
            goto out;
        }
        kill(DMid, SIGHUP);
        for( i=0; i< 100; i++)
        {
            if(DMid == waitpid(DMid, &status, WNOHANG))
                break;
            sleep(0.1);
        }
        if( i == 100)
        {
            DEBUG("DeviceModel %d took more than 10s "
                                "to terminate: sending SIGKILL\n", DMid);
            kill(DMid, SIGKILL);
            waitpid(DMid, &status, 0);
        }
        sprintf(path,"/local/domain/0/device-model/%i", domid); 
        xs_rm(xsh, XBT_NULL, path);

        // unlink pipe
        sprintf(path,"/var/run/tap/qemu-read-%d", domid); 
        ret = unlink(path);
        sprintf(path,"/var/run/tap/qemu-write-%d", domid); 
        ret = unlink(path);

        //notify backend to reap the source assigned to this VM
        sprintf(path, "xenstore-ls /local/domain/%d/device > /var/tmp/xdestroy_device.%d", domid, domid); 
        ret = system(path);
        sprintf(path, "/var/tmp/xdestroy_device.%d",  domid); 
        f = fopen(path, "r");
        if ( f == NULL)
        {
            DEBUG(" error to open device file\n");
            return -1;
        }
        DEBUG("- begin to reap\n");
        while(1)
        {
            if( fgets(buf, 256, f)== NULL)
                break;
            else
            {
                if( buf[0] != 0x20)
                {
                    backend = device_backend(xsh, buf, domid);
                    if( backend != NULL)
                    {    
                        notify_backend(xsh, backend);
                        free(backend);
                    }
                }
            }
       }
       DEBUG("- end to reap\n");
       fclose(f);
       sprintf(path, "rm /var/tmp/xdestroy_device.%d",  domid); 
       ret = system(path);
       extra_call(domname, DMid);
out:
	if (xsh)
		xs_daemon_close(xsh);
	if (xc_handle)
		xc_interface_close(xc_handle);
	return rcode;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Miss destroy name\n");
		return -1;
	}
	xlist(argc, argv);
	//shutdown_domain(argv[1]);
	destroy_domain(argv[1]);

	return 0;
}
