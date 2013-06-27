#
# tools/kboot/Makefile
#
# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.
#
# Copyright (C) 2005 by Christian Limpach
#

XEN_ROOT	= ../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all clean
all: kboot.initramfs

clean:
	rm -f kboot.initramfs
	rm -f *~

kboot.initramfs: mkinitramfs init select-kernel ../xcutils/xc_kexec
	sh ./mkinitramfs | tee $@

