/*
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Copyright (C) Red Hat 2007
 *
 *  Xen Console
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <xs.h>
#include <xen/io/console.h>
#include <xenctrl.h>

#include "hw.h"
#include "sysemu.h"
#include "qemu-char.h"
#include "xen_backend.h"

static int log_guest = 0;

struct buffer {
    uint8_t *data;
    size_t consumed;
    size_t size;
    size_t capacity;
    size_t max_capacity;
};

struct XenConsole {
    struct XenDevice  xendev;  /* must be first */
    struct buffer     buffer;
    char              console[XEN_BUFSIZE];
    int               ring_ref;
    void              *sring;
    CharDriverState   *chr;
    int               backlog;
    int               log_fd;
};

static int write_all(int fd, const char* buf, size_t len)
{
    while (len) {
        ssize_t ret = write(fd, buf, len);
        if (ret == -1 && errno == EINTR)
            continue;
        if (ret < 0)
            return -1;
        len -= ret;
        buf += ret;
    }

    return 0;
}

static void buffer_append(struct XenConsole *con)
{
    struct buffer *buffer = &con->buffer;
    XENCONS_RING_IDX cons, prod, size;
    struct xencons_interface *intf = con->sring;

    cons = intf->out_cons;
    prod = intf->out_prod;
    xen_mb();

    size = prod - cons;
    if ((size == 0) || (size > sizeof(intf->out)))
	return;

    if ((buffer->capacity - buffer->size) < size) {
	buffer->capacity += (size + 1024);
	buffer->data = qemu_realloc(buffer->data, buffer->capacity);
    }

    while (cons != prod)
	buffer->data[buffer->size++] = intf->out[
	    MASK_XENCONS_IDX(cons++, intf->out)];

    xen_mb();
    intf->out_cons = cons;
    xen_be_send_notify(&con->xendev);

    if (con->log_fd != -1) {
        int logret;
        logret = write_all(con->log_fd, buffer->data + buffer->size - size, size);
        if (logret < 0) {
            xen_be_printf(&con->xendev, 1, "Write to log failed on domain %d: %d (%s)\n",
                      con->xendev.dom, errno, strerror(errno));
        }
     }

    if (buffer->max_capacity &&
	buffer->size > buffer->max_capacity) {
	/* Discard the middle of the data. */

	size_t over = buffer->size - buffer->max_capacity;
	uint8_t *maxpos = buffer->data + buffer->max_capacity;

	memmove(maxpos - over, maxpos, over);
	buffer->data = qemu_realloc(buffer->data, buffer->max_capacity);
	buffer->size = buffer->capacity = buffer->max_capacity;

	if (buffer->consumed > buffer->max_capacity - over)
	    buffer->consumed = buffer->max_capacity - over;
    }
}

static void buffer_advance(struct buffer *buffer, size_t len)
{
    buffer->consumed += len;
    if (buffer->consumed == buffer->size) {
	buffer->consumed = 0;
	buffer->size = 0;
    }
}

static int ring_free_bytes(struct XenConsole *con)
{
    struct xencons_interface *intf = con->sring;
    XENCONS_RING_IDX cons, prod, space;

    cons = intf->in_cons;
    prod = intf->in_prod;
    xen_mb();

    space = prod - cons;
    if (space > sizeof(intf->in))
	return 0; /* ring is screwed: ignore it */

    return (sizeof(intf->in) - space);
}

static int xencons_can_receive(void *opaque)
{
    struct XenConsole *con = opaque;
    return ring_free_bytes(con);
}

static void xencons_receive(void *opaque, const uint8_t *buf, int len)
{
    struct XenConsole *con = opaque;
    struct xencons_interface *intf = con->sring;
    XENCONS_RING_IDX prod;
    int i, max;

    max = ring_free_bytes(con);
    /* The can_receive() func limits this, but check again anyway */
    if (max < len)
	len = max;

    prod = intf->in_prod;
    for (i = 0; i < len; i++) {
	intf->in[MASK_XENCONS_IDX(prod++, intf->in)] =
	    buf[i];
    }
    xen_wmb();
    intf->in_prod = prod;
    xen_be_send_notify(&con->xendev);
}

static void xencons_send(struct XenConsole *con)
{
    ssize_t len, size;

    size = con->buffer.size - con->buffer.consumed;
    if (con->chr)
        len = qemu_chr_write(con->chr, con->buffer.data + con->buffer.consumed,
                             size);
    else
        len = size;
    if (len < 1) {
	if (!con->backlog) {
	    con->backlog = 1;
	    xen_be_printf(&con->xendev, 1, "backlog piling up, nobody listening?\n");
	}
    } else {
	buffer_advance(&con->buffer, len);
	if (con->backlog && len == size) {
	    con->backlog = 0;
	    xen_be_printf(&con->xendev, 1, "backlog is gone\n");
	}
    }
}

static int create_domain_log(struct XenConsole *con)
{
    char *logfile;
    char *path, *domname;
    int fd;
    const char *logdir = "/var/log/xen/console";

    path = xs_get_domain_path(xenstore, con->xendev.dom);
    domname = xenstore_read_str(path, "name");
    free(path);
    if (!domname)
        return -1;

    if (mkdir(logdir, 0755) && errno != EEXIST)
    {
        xen_be_printf(&con->xendev, 1,  "Directory %s does not exist and fail to create it!", logdir);
        return -1;
    }

    asprintf(&logfile, "%s/guest-%s.log", logdir, domname);
    qemu_free(domname);

    fd = open(logfile, O_WRONLY|O_CREAT|O_APPEND, 0644);
    free(logfile);
    if (fd == -1)
        xen_be_printf(&con->xendev, 1,  "Failed to open log %s: %d (%s)", logfile, errno, strerror(errno));

    return fd;
}

/* -------------------------------------------------------------------- */

static int con_init(struct XenDevice *xendev)
{
    struct XenConsole *con = container_of(xendev, struct XenConsole, xendev);
    char *type, *dom, label[32];
    const char *output;
    char *logenv = NULL;

    /* setup */
    dom = xs_get_domain_path(xenstore, con->xendev.dom);
    if (!xendev->dev)
        snprintf(con->console, sizeof(con->console), "%s/console", dom);
    else
        snprintf(con->console, sizeof(con->console), "%s/device/console/%d", dom, xendev->dev);
    free(dom);

    type = xenstore_read_str(con->console, "type");
    if (!type || 0 != strcmp(type, "ioemu")) {
	xen_be_printf(xendev, 1, "not for me (type=%s)\n", type);
	if (type)
	    qemu_free(type);
	return -1;
    }
    qemu_free(type);

	output = xenstore_read_str(con->console, "output");
	/* output is a pty by default */
	if (output == NULL)
		output = "pty";
	snprintf(label, sizeof(label), "xencons%d", con->xendev.dev);
	con->chr = qemu_chr_open(label, output, NULL);
	xenstore_store_pv_console_info(con->xendev.dev, con->chr, output);

    logenv = getenv("XENCONSOLED_TRACE");
    if (logenv != NULL && strlen(logenv) == strlen("guest") && !strcmp(logenv, "guest")) {
        log_guest = 1;
    }
    return 0;
}

static int con_initialise(struct XenDevice *xendev)
{
    struct XenConsole *con = container_of(xendev, struct XenConsole, xendev);
    int limit;

    if (xenstore_read_int(con->console, "ring-ref", &con->ring_ref) == -1)
	return -1;
    if (xenstore_read_int(con->console, "port", &con->xendev.remote_port) == -1)
	return -1;
    if (xenstore_read_int(con->console, "limit", &limit) == 0)
	con->buffer.max_capacity = limit;

    if (!xendev->dev)
        con->sring = xc_map_foreign_range(xen_xc, con->xendev.dom,
                                          XC_PAGE_SIZE,
                                          PROT_READ|PROT_WRITE,
                                          con->ring_ref);
    else
        con->sring = xc_gnttab_map_grant_ref(xendev->gnttabdev, con->xendev.dom,
                                             con->ring_ref,
                                             PROT_READ|PROT_WRITE);
    if (!con->sring)
	return -1;

    xen_be_bind_evtchn(&con->xendev);
    if (con->chr)
        qemu_chr_add_handlers(con->chr, xencons_can_receive, xencons_receive,
                              NULL, con);

    xen_be_printf(xendev, 1, "ring mfn %d, remote port %d, local port %d, limit %zd\n",
		  con->ring_ref,
		  con->xendev.remote_port,
		  con->xendev.local_port,
		  con->buffer.max_capacity);
    con->log_fd = -1;
    if (log_guest)
         con->log_fd = create_domain_log(con);
    return 0;
}

static void con_disconnect(struct XenDevice *xendev)
{
    struct XenConsole *con = container_of(xendev, struct XenConsole, xendev);

    if (con->chr)
        qemu_chr_add_handlers(con->chr, NULL, NULL, NULL, NULL);
    xen_be_unbind_evtchn(&con->xendev);

    if (con->sring) {
        if (!xendev->dev)
	    munmap(con->sring, XC_PAGE_SIZE);
        else
            xc_gnttab_munmap(xendev->gnttabdev, con->sring, 1);
	con->sring = NULL;
    }

    if (con->log_fd != -1) {
        close(con->log_fd);
        con->log_fd = -1;
    }

}

static void con_event(struct XenDevice *xendev)
{
    struct XenConsole *con = container_of(xendev, struct XenConsole, xendev);

    buffer_append(con);
    if (con->buffer.size - con->buffer.consumed)
	xencons_send(con);
}

/* -------------------------------------------------------------------- */

struct XenDevOps xen_console_ops = {
    .size       = sizeof(struct XenConsole),
    .flags      = DEVOPS_FLAG_IGNORE_STATE|DEVOPS_FLAG_NEED_GNTDEV,
    .init       = con_init,
    .initialise = con_initialise,
    .event      = con_event,
    .disconnect = con_disconnect,
};

