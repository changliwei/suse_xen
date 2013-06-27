/* block-cdrom.c
 *
 * simple slow synchronous cdrom disk implementation. Based off
 * of block-sync.c
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 * (c) 2008 Novell Inc. <plc@novell.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "tapdisk.h"
#include <xen/io/cdromif.h>

struct tdcdrom_state {
	int fd;
	int xs_fd;        /* for xen event polling */
	int media_present;
	int media_changed;
	struct xs_handle *xs_handle;
	char *dev_name;
	int dev_type;
	td_flag_t flags;
};

#define BLOCK_DEVICE   0
#define FILE_DEVICE    1
#define CDROM_DEFAULT_SECTOR_SIZE 2048
#define CDROM_DEFAULT_SIZE 2000000000

/*Get Image size, secsize*/
static void get_image_info(struct disk_driver *dd)
{
	int ret;
	long size;
	unsigned long total_size;
	struct statvfs statBuf;
	struct stat stat;
	struct td_state     *s   = dd->td_state;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;

	s->size = 0;
	s->sector_size = CDROM_DEFAULT_SECTOR_SIZE;
	s->info = (VDISK_CDROM | VDISK_REMOVABLE | VDISK_READONLY);
	prv->media_present = 0;

	ret = fstat(prv->fd, &stat);
	if (ret != 0) {
		DPRINTF("ERROR: fstat failed, Couldn't stat image");
		return;
	}

	if (S_ISBLK(stat.st_mode)) {
		/*Accessing block device directly*/
		int status;

		prv->dev_type = BLOCK_DEVICE;
		status = ioctl(prv->fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
		if (status == CDS_DISC_OK) {
			prv->media_present = 1;
			if ((ret =ioctl(prv->fd,BLKGETSIZE,&s->size))!=0) {
				DPRINTF("ERR: BLKGETSIZE failed, couldn't stat image");
				s->size = CDROM_DEFAULT_SIZE;
			}
		}
		else {
			s->size = CDROM_DEFAULT_SIZE;
		}
		/*Get the sector size*/
#if defined(BLKSSZGET)
		{
			int arg;
			s->sector_size = CDROM_DEFAULT_SECTOR_SIZE;
			ioctl(prv->fd, BLKSSZGET, &s->sector_size);

			if (s->sector_size != CDROM_DEFAULT_SECTOR_SIZE)
				DPRINTF("Note: sector size is %llu (not %d)\n",
					(long long unsigned)s->sector_size,
					CDROM_DEFAULT_SECTOR_SIZE);
		}
#else
		s->sector_size = CDROM_DEFAULT_SECTOR_SIZE;
#endif
		DPRINTF("Block Device: Image size: %llu"
			" media_present: %d sector_size: %llu\n",
			(long long unsigned)s->size, prv->media_present,
			(long long unsigned)s->sector_size);
	} else {
		/*Local file? try fstat instead*/
		prv->dev_type = FILE_DEVICE;
		prv->media_present = 1;
		s->size = (stat.st_size >> SECTOR_SHIFT);
		s->sector_size = DEFAULT_SECTOR_SIZE;
		DPRINTF("Local File: Image size: %llu\n",
				(long long unsigned)s->size);
	}
	return;
}

static inline void init_fds(struct disk_driver *dd)
{
	int i;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;

	for(i = 0; i < MAX_IOFD; i++)
		dd->io_fd[i] = 0;

	prv->xs_handle = xs_daemon_open();
	prv->xs_fd = xs_fileno(prv->xs_handle);
	dd->io_fd[0] = prv->xs_fd;
}

void open_device (struct disk_driver *dd)
{
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
	int o_flags;

	o_flags = O_NONBLOCK | O_LARGEFILE |
		((prv->flags == TD_RDONLY) ? O_RDONLY : O_RDWR);

	if (prv->fd < 0) {
		prv->fd = open(prv->dev_name, o_flags);
		if (prv->fd == -1) {
			DPRINTF("Unable tp open: (%s)\n", prv->dev_name);
			return;
		}
	}

	if (prv->fd != -1) {

		get_image_info(dd);

		if (prv->dev_type == BLOCK_DEVICE) {
			int status;
			status = ioctl(prv->fd, CDROM_DRIVE_STATUS, CDSL_CURRENT);
			switch (status) {
				case CDS_DISC_OK:
					prv->media_present = 1;
					break;
				default:
					prv->media_present = 0;
			}
		}
		else
			prv->media_present = 1;
	}
}

/*
 * Main entry point, called when first loaded
 */
int tdcdrom_open (struct disk_driver *dd, const char *name, td_flag_t flags)
{
	int ret = 0;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;

	asprintf(&prv->dev_name, "%s", name);
	prv->fd = -1;
	prv->media_changed = 0;
	prv->media_present = 0;
	prv->flags = flags;
	init_fds(dd);

	open_device(dd);

	return ret;
}

int tdcdrom_queue_read(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *private)
{
	struct td_state     *s   = dd->td_state;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	int ret;

	if (prv->fd == -1 || prv->media_present == 0) {
		ret = 0 - ENOMEDIUM;
		return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
	}
	size    = nb_sectors * 512;
	offset  = sector * (uint64_t)512;
	ret = lseek(prv->fd, offset, SEEK_SET);
	if (ret != (off_t)-1) {
		ret = read(prv->fd, buf, size);
		if (ret != size) {
			ret = 0 - errno;
		} else {
			ret = 1;
		}
	} else ret = 0 - errno;

	return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
}

int tdcdrom_queue_write(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *private)
{
	struct td_state     *s   = dd->td_state;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	int ret = 0;

	if (prv->fd == -1 || prv->media_present == 0) {
		ret = 0 - ENOMEDIUM;
		return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
	}
	ret = lseek(prv->fd, offset, SEEK_SET);
	if (ret != (off_t)-1) {
		ret = write(prv->fd, buf, size);
		if (ret != size) {
			ret = 0 - errno;
		} else {
			ret = 1;
		}
	} else ret = 0 - errno;

	return cb(dd, (ret < 0) ? ret : 0, sector, nb_sectors, id, private);
}

int tdcdrom_queue_packet(struct disk_driver *dd, uint64_t sector,
		int nb_sectors, char *buf, td_callback_t cb,
		int id, void *private)
{
	struct td_state     *s   = dd->td_state;
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	int ret = 0;

	union xen_block_packet *sp;
	struct xen_cdrom_packet *xcp;
	struct xen_cdrom_support *xcs;
	struct xen_cdrom_open *xco;
	struct xen_cdrom_media_info *xcmi;
	struct xen_cdrom_media_changed *xcmc;
	struct cdrom_generic_command cgc;
	struct vcd_generic_command * vgc;
	struct request_sense sense;

	sp = (union xen_block_packet *)buf;
	switch(sp->type) {
		case XEN_TYPE_CDROM_SUPPORT:
			xcs = &(sp->xcs);
			xcs->err = 0;
			xcs->ret = 0;
			xcs->supported = 1;
			break;
		case XEN_TYPE_CDROM_PACKET:
			xcp = &(sp->xcp);
			xcp->err = 0;
			xcp->ret = 0;
			vgc = (struct vcd_generic_command *)(buf + PACKET_PAYLOAD_OFFSET);

			memset( &cgc, 0, sizeof(struct cdrom_generic_command));
			memcpy(cgc.cmd, vgc->cmd, CDROM_PACKET_SIZE);
			cgc.stat = vgc->stat;
			cgc.data_direction = vgc->data_direction;
			cgc.quiet = vgc->quiet;
			cgc.timeout = vgc->timeout;

			if (prv->fd == -1) {
				xcp = &(sp->xcp);
				xcp->ret = -1;
				xcp->err =  0 - ENODEV;
				return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
			}
			if (prv->dev_type == FILE_DEVICE) {
				DPRINTF("%s() FILE_DEVICE inappropriate packetcmd \n",__func__);
				return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
			}
			switch ( cgc.cmd[0]) {
				case GPCMD_PREVENT_ALLOW_MEDIUM_REMOVAL:
					{
						int lock;
						lock = cgc.cmd[4] & 1;
						if (ioctl (prv->fd, CDROM_LOCKDOOR, lock) < 0) {
							xcp->err = -(errno);
							xcp->ret = -1;
						}
					}
					break;
				case GPCMD_START_STOP_UNIT:
					{
						int start, eject;
						start = cgc.cmd[4] & 1;
						eject = (cgc.cmd[4] >> 1) & 1;
						if (eject && !start) {
							if (ioctl (prv->fd, CDROMEJECT, NULL) < 0) {
								xcp->err = -(errno);
								xcp->ret = -1;
							}
						} else if (eject && start) {
							if (ioctl (prv->fd, CDROMCLOSETRAY, NULL) < 0) {
								xcp->err = -(errno);
								xcp->ret = -1;
							}
						}
					}
					break;
				default:
					{
						if (vgc->sense_offset) {
							cgc.sense = &sense;
						}
						if (vgc->buffer_offset) {
							cgc.buffer = malloc(vgc->buflen);
							memcpy(cgc.buffer, (char *)sp + PACKET_BUFFER_OFFSET, vgc->buflen);
							cgc.buflen = vgc->buflen;
						}
						if (ioctl (prv->fd, CDROM_SEND_PACKET, &cgc) < 0 ) {
							xcp->err = -(errno);
							xcp->ret = -1;
						}
						if (cgc.sense) {
							memcpy((char *)sp + PACKET_SENSE_OFFSET, cgc.sense, sizeof(struct request_sense));
						}
						if (cgc.buffer) {
							vgc->buflen = cgc.buflen;
							memcpy((char *)sp + PACKET_BUFFER_OFFSET, cgc.buffer, cgc.buflen);
							free(cgc.buffer);
						}
						break;
					}
			}
			break;
		case XEN_TYPE_CDROM_OPEN:
			{
				char *buf = NULL;
				unsigned int len;
				struct stat statbuf;
				int major = 0;
				int minor = 0;
				char *num;

				if (stat (prv->dev_name, &statbuf) == 0) {
					major = major (statbuf.st_rdev);
					minor = minor (statbuf.st_rdev);
				}
				xco = &(sp->xco);
				xco->err = 0;
				xco->ret = 0;
				if (xco->payload_offset) {
					char * nodename;
					char media_present[2];
					nodename = (char *)sp + xco->payload_offset;
					asprintf(&buf, "%s/media-present", nodename);
					if (!xs_read(prv->xs_handle, XBT_NULL, buf, &len)) {
						sprintf(media_present, "%d", prv->media_present);
						xs_write(prv->xs_handle, XBT_NULL, buf, media_present, strlen(media_present));
						xs_watch(prv->xs_handle, buf, "media-present");
						asprintf(&buf, "%s/params", nodename);
						xs_watch(prv->xs_handle, buf, "params");
						asprintf(&num, "%x:%x", major, minor);
						asprintf(&buf, "%s/physical-device", nodename);
						xs_write(prv->xs_handle, XBT_NULL, buf, num, strlen(num));
					}
					free(buf);
				}

				xco->media_present = prv->media_present;
				xco->sectors = 0;
				xco->sector_size = 2048;
				if (prv->media_present && prv->fd != -1 ) {
					get_image_info(dd);
					xco->sectors = s->size;
					xco->sector_size = s->sector_size;
				}
			}
			break;
		case XEN_TYPE_CDROM_MEDIA_CHANGED:
			xcmc = &(sp->xcmc);
			xcmc->err = 0;
			xcmc->ret = 0;
			xcmc->media_changed = prv->media_changed;
			prv->media_changed = 0;
			break;
		default:
			xcp = &(sp->xcp);
			xcp->err = -EINVAL;
			xcp->ret = -1;
			break;
	}

	return cb(dd, (ret < 0) ? ret: 0, sector, nb_sectors, id, private);
}

int tdcdrom_submit(struct disk_driver *dd)
{
	return 0;
}

int tdcdrom_close(struct disk_driver *dd)
{
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;

	if (prv->fd != -1) {
		close(prv->fd);
		prv->fd = -1;
	}
	prv->xs_fd = -1;
	xs_daemon_close(prv->xs_handle);
	free(prv->dev_name);

	return 0;
}

void tdcdrom_process_media_change_event(struct disk_driver *dd, char **vec)
{
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
    char *media_present = NULL;
    unsigned int len;

	media_present = xs_read(prv->xs_handle, XBT_NULL, vec[XS_WATCH_PATH], &len);
	if (strcmp(media_present, "0") == 0) {
		close(prv->fd);
		prv->fd = -1;
		prv->media_present = 0;
	}
	else {
		open_device(dd);
		prv->media_changed = 1;
	}
}

void tdcrom_process_params_event(struct disk_driver *dd, char **vec)
{
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
    char * params = NULL;
    unsigned int len;

	params = xs_read(prv->xs_handle, XBT_NULL, vec[XS_WATCH_PATH], &len);
	if (params != NULL) {
		char *cp = strchr(params, ':');
		if (cp) {
			cp++;
			if (prv->dev_name)
				free(prv->dev_name);
			asprintf(&prv->dev_name, "%s", cp);
			if (prv->fd != -1) {
				close(prv->fd);
				prv->fd = -1;
			}
			open_device(dd);
			prv->media_changed = 1;
		}
	}
}

int tdcdrom_do_callbacks(struct disk_driver *dd, int sid)
{
	struct tdcdrom_state *prv = (struct tdcdrom_state *)dd->private;
	char **vec;
	unsigned int num;

	vec = xs_read_watch(prv->xs_handle, &num);
	if (!vec)
		return 1;

    if (!strcmp(vec[XS_WATCH_TOKEN], "media-present")) {
        tdcdrom_process_media_change_event(dd, vec);
        goto out;
    }

    if (!strcmp(vec[XS_WATCH_TOKEN], "params")) {
        tdcrom_process_params_event(dd, vec);
        goto out;
    }

 out:
    free(vec);
	return 1;
}

int tdcdrom_get_parent_id(struct disk_driver *dd, struct disk_id *id)
{
	return TD_NO_PARENT;
}

int tdcdrom_validate_parent(struct disk_driver *dd,
		struct disk_driver *parent, td_flag_t flags)
{
	return -EINVAL;
}

struct tap_disk tapdisk_cdrom = {
	.disk_type           = "tapdisk_cdrom",
	.private_data_size   = sizeof(struct tdcdrom_state),
	.td_open             = tdcdrom_open,
	.td_queue_read       = tdcdrom_queue_read,
	.td_queue_packet     = tdcdrom_queue_packet,
	.td_queue_write      = tdcdrom_queue_write,
	.td_submit           = tdcdrom_submit,
	.td_close            = tdcdrom_close,
	.td_do_callbacks     = tdcdrom_do_callbacks,
	.td_get_parent_id    = tdcdrom_get_parent_id,
	.td_validate_parent  = tdcdrom_validate_parent
};
