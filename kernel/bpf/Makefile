# SPDX-License-Identifier: GPL-2.0
#
# eBPF 对照程序构建。产物由 iproute2 的 legacy 加载器直接使用，不需要 libbpf：
#   ip route add 10.9.0.2/32 dev veth-c encap bpf xmit obj lwt_encap.o sec lwt_xmit
#   （配置用 bpftool 写 map，见 kernel/bpf/lwt_cfg.py 与 tests/ab_lwt_test.sh）
#
# 优先用系统的 <bpf/bpf_helpers.h>（装了 libbpf-dev 时），否则退回本目录自带的
# 最小垫片 —— 两者 ABI 一致，垫片只是把 helper 声明成常量函数指针。

CLANG ?= $(shell command -v clang 2>/dev/null || command -v clang-20 2>/dev/null || echo /usr/lib/llvm-20/bin/clang)
OBJDUMP ?= $(shell command -v llvm-objdump 2>/dev/null || echo /usr/lib/llvm-20/bin/llvm-objdump)

CFLAGS := -O2 -g -target bpf -D__BPF__ -Wall -Wno-unused-variable -I$(CURDIR)
OBJS := lwt_encap.o

all: $(OBJS)

%.o: %.c bpf/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# 源码用 .bpf.c 后缀（clang 的惯例）：没有这条规则时 make 找不到 lwt_encap.o
# 的来源，直接 "No rule to make target"。
%.o: %.bpf.c bpf/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# 打印指令数（iptables/nft 的 tc 程序有 4096 指令限制，LWT 没有，仅供参考）
insns: $(OBJS)
	@for o in $(OBJS); do \
		printf '%s: %s insns\n' $$o $$($(OBJDUMP) -d $$o | grep -cE '^\s+[0-9a-f]+:'); \
	done

clean:
	rm -f $(OBJS) *.ll

.PHONY: all insns clean
