XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -I $(XEN_XC)
CFLAGS   += -I ./
CFLAGS   += $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore)
LDLIBS += $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) -pthread

POLICY    = default

SRC      :=
SRCS     += file_ops.c xenpaging.c policy_$(POLICY).c
SRCS     += pagein.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -g

CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(SRCS:.c=.o)
IBINS    = xenpaging xenmem

all: $(IBINS)

xenpaging: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(XEN_PAGING_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(LIBEXEC)

clean:
	rm -f *.o *~ $(DEPS) xen TAGS $(IBINS) $(LIB)

.PHONY: clean install

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)
