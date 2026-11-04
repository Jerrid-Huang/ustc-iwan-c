# SPDX-License-Identifier: GPL-2.0
#
# eBPF reference programs. Outputs are loaded by iproute2's legacy loader; no libbpf needed:
#   ip route add 10.9.0.2/32 dev veth-c encap bpf xmit obj lwt_encap.o sec lwt_xmit
#   (maps are written with bpftool; see kernel/bpf/lwt_cfg.py and tests/ab_lwt_test.sh)
#
# Prefer the system <bpf/bpf_helpers.h> (with libbpf-dev), otherwise fall back to the bundled
# minimal shim -- same ABI; the shim only declares helpers as constant function pointers.

CLANG ?= $(shell command -v clang 2>/dev/null || command -v clang-20 2>/dev/null || echo /usr/lib/llvm-20/bin/clang)
OBJDUMP ?= $(shell command -v llvm-objdump 2>/dev/null || echo /usr/lib/llvm-20/bin/llvm-objdump)

CFLAGS := -O2 -g -target bpf -D__BPF__ -Wall -Wno-unused-variable -I$(CURDIR)
OBJS := lwt_encap.o

all: $(OBJS)

%.o: %.c bpf/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Sources use the .bpf.c suffix (clang convention): without this rule make cannot find
# the source of lwt_encap.o and fails with "No rule to make target".
%.o: %.bpf.c bpf/bpf_helpers.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Print instruction count (tc programs for iptables/nft are capped at 4096; LWT is not -- info only)
insns: $(OBJS)
	@for o in $(OBJS); do \
		printf '%s: %s insns\n' $$o $$($(OBJDUMP) -d $$o | grep -cE '^\s+[0-9a-f]+:'); \
	done

clean:
	rm -f $(OBJS) *.ll

.PHONY: all insns clean
