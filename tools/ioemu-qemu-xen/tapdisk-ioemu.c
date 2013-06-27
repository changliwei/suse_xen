#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

#include <assert.h>
#include <hw/xen_blktap.h>

extern void qemu_aio_init(void);
extern void qemu_aio_poll(void);

extern void *fd_start;
extern int connected_disks;

int domid = 0;
FILE* logfile;

typedef struct IOHandlerRecord {
    int fd;
    IOCanRWHandler *fd_read_poll;
    IOHandler *fd_read;
    IOHandler *fd_write;
    int deleted;
    void *opaque;
    /* temporary data */
    struct pollfd *ufd;
    struct IOHandlerRecord *next;
} IOHandlerRecord;

static IOHandlerRecord *first_io_handler;

int qemu_set_fd_handler2(int fd, 
                         IOCanRWHandler *fd_read_poll, 
                         IOHandler *fd_read, 
                         IOHandler *fd_write, 
                         void *opaque)
{
    IOHandlerRecord *ioh;

    /* This is a stripped down version of fd handling */
    assert(fd_read_poll == NULL);
    assert(fd_write == NULL);

    for(ioh = first_io_handler; ioh != NULL; ioh = ioh->next)
        if (ioh->fd == fd)
            goto found;
    
    if (!fd_read && !fd_write)
        return 0;
        
    ioh = qemu_mallocz(sizeof(IOHandlerRecord));
    if (!ioh)
        return -1;
    ioh->next = first_io_handler;
    first_io_handler = ioh;

found:
    if (!fd_read && !fd_write) {
        ioh->deleted = 1;
    } else {
        ioh->fd = fd;
        ioh->fd_read = fd_read;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }

    return 0;
}

int main(void) 
{
    IOHandlerRecord *ioh, **pioh;
    int max_fd;
    fd_set rfds;
    struct timeval tv;
    int old_connected_disks = 0;

    /* Daemonize */
    if (fork() != 0)
        exit(0);

    bdrv_init();
    init_blktap();

    logfile = fopen("/var/log/xen/tapdisk-ioemu.log", "a");
    if (logfile) {
        setbuf(logfile, NULL);
        fclose(stderr);
        stderr = logfile;
    } else {
        logfile = stderr;
    }

    /* 
     * Main loop: Pass events to the corrsponding handlers and check for
     * completed aio operations.
     */
    while (1) {
        max_fd = -1;
        FD_ZERO(&rfds);
        for(ioh = first_io_handler; ioh != NULL; ioh = ioh->next)
            if (!ioh->deleted) {
                FD_SET(ioh->fd, &rfds);
                max_fd = max_fd > ioh->fd ? max_fd : ioh->fd;
            }

        tv.tv_sec = 0;
        tv.tv_usec = 10000;
        if (select(max_fd + 1, &rfds, NULL, NULL, &tv) <= 0)
            continue;
            
        /* Call handlers */
        for(ioh = first_io_handler; ioh != NULL; ioh = ioh->next)
            if (FD_ISSET(ioh->fd, &rfds))
                ioh->fd_read(ioh->opaque);

        /* Remove deleted IO handlers */
        pioh = &first_io_handler;
        while (*pioh) {
            ioh = *pioh;
            if (ioh->deleted) {
                *pioh = ioh->next;
                qemu_free(ioh);
            } else 
                pioh = &ioh->next;
        }

	if (old_connected_disks != connected_disks)
            fprintf(stderr, "connected disks: %d => %d\n",
	        old_connected_disks, connected_disks);

        /* Exit when the last image has been closed */
        if (old_connected_disks != 0 && connected_disks == 0) {
	    fprintf(stderr, "Last image is closed, exiting.\n");
            exit(0);
	}

        old_connected_disks = connected_disks;
    }
    return 0;
}
