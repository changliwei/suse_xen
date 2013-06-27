NAME = xen-utils
VERSION = 0.1

INSTALL = install
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p
SBINDIR = /usr/sbin
DOC_MAN1 = xen-list.1.gz
MAN1DIR = /usr/share/man/man1

CC = gcc
CFLAGS += -I. -D_DEBUG -D_GNU_SOURCE

ifdef XEN_INTREE_BUILD
XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk
CFLAGS  += -I $(XEN_XC)
CFLAGS += -I $(XEN_XENSTORE)
CFLAGS  += $(CFLAGS_libxenctrl)
CFLAGS += $(CFLAGS_libxenstore)
LIBS += $(LDFLAGS_libxenctrl) $(LDLIBS_libxenctrl)
LIBS += $(LDFLAGS_libxenguest) $(LDLIBS_libxenguest)
LIBS += $(LDFLAGS_libxenstore) $(LDLIBS_libxenstore)
else
CFLAGS += -Werror -Wall
LIBS += -lxenstore -lxenctrl -lxenguest
endif


PROGRAMS = xen-list xen-destroy
SRCS = xen-list.c xen-destroy.c xen-utils.c 
OBJS = xen-utils.o
AUX = Makefile README xen-utils.h
EXECS = xen-vmresync


.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

$(PROGRAMS): %: %.o $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(PROGRAMS)
	rm -f *.o

.PHONY: install
install: build
	$(INSTALL_PROG) $(PROGRAMS) $(EXECS) $(DESTDIR)$(SBINDIR)
	$(INSTALL_DATA) $(DOC_MAN1) $(DESTDIR)$(MAN1DIR)

.PHONY: dist
dist: $(SRCS) $(AUX)
	rm -rf $(NAME)-$(VERSION)
	mkdir $(NAME)-$(VERSION)
	ln $(SRCS) $(AUX) $(EXECS) $(DOC_MAN1) $(NAME)-$(VERSION)
	tar cvfj $(NAME)-$(VERSION).tar.bz2 $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

