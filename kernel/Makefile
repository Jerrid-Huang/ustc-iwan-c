# SPDX-License-Identifier: GPL-2.0
#
# 内核侧构建（树外模块）：
#   make -C kernel            # 用当前运行内核的 headers 构建 iwan.ko
#   make -C kernel KDIR=/lib/modules/$(uname -r)/build
#   make -C kernel clean
#
# 产物：iwan.ko（入站 netfilter 解封 + 出站虚拟网卡封装 + /dev/iwan 共享内存页）

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
