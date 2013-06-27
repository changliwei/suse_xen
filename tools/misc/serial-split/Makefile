CC     ?= gcc
CFLAGS ?= -Wall -Os
CFILES = $(wildcard *.c)
OBJS   = $(patsubst %.c,%.o,$(wildcard *.c))
TARGET = serial-split

all: $(TARGET)

install: all
	install -d $(DESTDIR)/usr/bin
	install -s $(TARGET) $(DESTDIR)/usr/bin/

clean:
	rm *.o $(TARGET) *~

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
