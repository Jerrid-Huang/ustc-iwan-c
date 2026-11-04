# SPDX-License-Identifier: GPL-2.0
#
# Kernel-side build (out-of-tree module):
#   make -C kernel            # build iwan.ko against the running kernel headers
#   make -C kernel KDIR=/lib/modules/$(uname -r)/build
#   make -C kernel clean
#
# Output: iwan.ko (inbound netfilter decap + outbound vnic encap + /dev/iwan shm page)

ifneq ($(KERNELRELEASE),)
obj-m := iwan.o
iwan-y := iwan_core.o iwan_rx.o iwan_tx.o iwan_netlink.o iwan_shm.o
ccflags-y += -Wall -Wextra -Wno-unused-parameter
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

.PHONY: all clean install
endif
