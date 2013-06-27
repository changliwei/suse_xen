CC = gcc

CFLAGS += -g
CFLAGS += -fno-strict-aliasing
CFLAGS += -std=gnu99
CFLAGS += -Wall -Wstrict-prototypes
CFLAGS += -Wno-unused-value
CFLAGS += -Wdeclaration-after-statement

CFLAGS  += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += -mno-tls-direct-seg-refs
CFLAGS  += -Werror

BIN      = xenalyze dump-raw

HDRS = trace.h analyze.h

all: $(BIN)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(LIBBIN)

%: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -o $@ $<
