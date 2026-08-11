CC      ?= cc
CLANG   ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fPIE -MMD -MP -pthread
LDFLAGS ?= -pie -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack

# Build target: linux (default) or win32 (Windows cross-compile, e.g.
# make TARGET=win32 CC=x86_64-w64-mingw32-gcc). Every Windows-specific
# bit below keys off this variable so the default Linux build is
# byte-for-byte unchanged.
TARGET ?= linux

ifeq ($(TARGET),win32)
# MinGW-w64 build. -D_GNU_SOURCE and -fPIE are glibc/ELF-isms; mingw-w64's
# FORTIFY_SOURCE support is unreliable, so drop all three and keep the
# portable flags plus the Windows API version pins. -pthread stays
# (winpthreads on win32 thread model). These defaults apply when CFLAGS is
# not given on the command line; CI passes the full set itself.
CFLAGS := $(filter-out -D_GNU_SOURCE -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3,$(CFLAGS))
CFLAGS += -D_WIN32_WINNT=0x0601 -DWINVER=0x0601
# ELF hardening flags (-pie, -z now/relro/noexecstack) don't apply to PE;
# use the equivalent PE hardening flags.
LDFLAGS := -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va
LDLIBS  := -lws2_32 -liphlpapi -lbcrypt -lcrypt32 -lshell32 -lssl -lcrypto
BIN_SUFFIX := .exe
# OpenSSL cross sysroot (e.g. an MSYS2 ucrt64 package unpacked locally,
# or a no-shared mingw build installed to lib64/).
# override: OPENSSL_DIR must take effect even when CFLAGS/LDFLAGS are given
# on the command line (CI passes CFLAGS explicitly).
ifneq ($(OPENSSL_DIR),)
override CFLAGS += -I$(OPENSSL_DIR)/include
override LDFLAGS += -L$(OPENSSL_DIR)/lib -L$(OPENSSL_DIR)/lib64
endif
# STATIC=1: link OpenSSL + winpthread + libssp statically so the exe
# runs with no DLLs beside it (system DLLs — ws2_32, bcrypt, ... — stay
# imported). Requires a no-shared OpenSSL sysroot (see README). The
# -Wl,-Bstatic/-Bdynamic scoping is essential: a plain -static would
# also strip the ws2_32/iphlpapi import libs and fail to link.
ifeq ($(STATIC),1)
LDFLAGS += -static-libgcc
LDLIBS := -Wl,-Bstatic -Wl,--start-group -lcrypto -lssl -Wl,--end-group \
          -lwinpthread -lssp -Wl,-Bdynamic \
          $(filter-out -lssl -lcrypto -lwinpthread -lssp,$(LDLIBS))
endif
else
# https.c links against libssl (both platforms).
LDLIBS := -lssl -lcrypto
BIN_SUFFIX :=
endif

SRC_DIR    := src
COMMON_DIR := $(SRC_DIR)/common
OIDC_DIR   := $(SRC_DIR)/oidc
BUILD_DIR  := build
BIN_DIR    := bin

# steer_bpf.c is compiled with clang -target bpf into a BPF ELF object
# (build/steer_bpf.o) that is embedded, not linked: it must never be
# recompiled for the host nor archived into the host static libraries,
# so exclude it from COMMON_SRCS. On win32, server.c (server-only, does
# not compile for Windows) and tun.c (replaced by tun_win.c) are also
# excluded, and port.c + tun_win.c supply the Windows halves of the
# portability layer (the Linux halves are static inlines in port.h).
ifeq ($(TARGET),win32)
# tun_win.c is appended explicitly (filtered from the wildcard) so it is
# listed exactly once whether or not it exists on disk yet; port.c is
# already picked up by the wildcard.
COMMON_SRCS := $(filter-out $(COMMON_DIR)/server.c $(COMMON_DIR)/tun.c $(COMMON_DIR)/steer_bpf.c $(COMMON_DIR)/tun_win.c,$(wildcard $(COMMON_DIR)/*.c)) $(COMMON_DIR)/tun_win.c
else
COMMON_SRCS := $(filter-out $(COMMON_DIR)/steer_bpf.c,$(wildcard $(COMMON_DIR)/*.c))
endif
OIDC_SRCS   := $(wildcard $(OIDC_DIR)/*.c)

# Objects are bucketed by source directory (build/common/, build/oidc/,
# build/main/) so the %.o pattern rules below cannot collide on basenames
# shared between directories.
COMMON_OBJS := $(patsubst $(COMMON_DIR)/%.c,$(BUILD_DIR)/common/%.o,$(COMMON_SRCS))
OIDC_OBJS   := $(patsubst $(OIDC_DIR)/%.c,$(BUILD_DIR)/oidc/%.o,$(OIDC_SRCS))

LIBCORE := $(BUILD_DIR)/libiwan_core.a
LIBOIDC := $(BUILD_DIR)/libiwan_oidc.a

.PHONY: all clean test
all: $(BIN_DIR)/iwan-client$(BIN_SUFFIX) $(BIN_DIR)/iwan-client-oidc$(BIN_SUFFIX)
ifneq ($(TARGET),win32)
all: $(BIN_DIR)/iwan-server
endif

# The steer BPF payload is Linux-only (embedded BPF ELF, loaded by
# tun.c); win32 links no steer_bpf chain at all, so LIBCORE's prereq list
# drops the generated data object on that target.
ifneq ($(TARGET),win32)
STEER_BPF_DATA_OBJ := $(BUILD_DIR)/steer_bpf_data.o
endif

$(LIBCORE): $(COMMON_OBJS) $(STEER_BPF_DATA_OBJ)
	rm -f $@ && ar rcs $@ $^

$(LIBOIDC): $(OIDC_OBJS)
	rm -f $@ && ar rcs $@ $^

$(BIN_DIR)/iwan-client$(BIN_SUFFIX): $(LIBCORE) $(BUILD_DIR)/main/iwan_client.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_client.o $(LIBCORE) $(LDLIBS)

$(BIN_DIR)/iwan-client-oidc$(BIN_SUFFIX): $(LIBCORE) $(LIBOIDC) $(BUILD_DIR)/main/iwan_client_oidc.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_client_oidc.o \
		-Wl,--start-group $(LIBCORE) $(LIBOIDC) -Wl,--end-group $(LDLIBS)

ifneq ($(TARGET),win32)
$(BIN_DIR)/iwan-server: $(LIBCORE) $(BUILD_DIR)/main/iwan_server.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_server.o $(LIBCORE) $(LDLIBS)
endif

# Compile the tun steering classifier with clang for the BPF target. The
# result is a BPF ELF object, not a host object: never link it directly
# and never archive it into the host libraries. BPF is Linux-only, so
# none of this chain exists on win32.
#
# linux/bpf.h -> linux/types.h includes <asm/types.h>; the asm headers
# live in the gcc multiarch include dir (/usr/include/<triplet>), which
# clang does not search when compiling for the bpf target (a cross
# compile). Ubuntu 24.04+ linux-libc-dev no longer ships the
# /usr/include/asm symlink (the gcc-multilib package that does is not a
# build dependency), so point clang at the triplet dir explicitly.
ifneq ($(TARGET),win32)
# must NOT use $(CC): the clang build passes CC=clang, and clang has no
# -print-multiarch (gcc option) — probe gcc/cc instead
BPF_MULTIARCH_INC := $(shell gcc -print-multiarch 2>/dev/null || cc -print-multiarch 2>/dev/null)
$(BUILD_DIR)/steer_bpf.o: $(COMMON_DIR)/steer_bpf.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -O2 -target bpf -Wall -MMD -MP -isystem /usr/include/$(BPF_MULTIARCH_INC) -c -o $@ $<

# Embed the BPF object as a C array consumed by src/common/tun.c
# (bpf_prog_load_steer), which parses the embedded ELF section table and
# loads the instructions from the "classifier" section and the license
# string from the "license" section. Keep those section names in sync with
# the SEC() annotations in steer_bpf.c. The payload is written to a temp
# file and moved into place so a failed generation never leaves a
# truncated source; .DELETE_ON_ERROR removes the target on failure.
$(BUILD_DIR)/steer_bpf_data.c: $(BUILD_DIR)/steer_bpf.o
	@echo "generating embedded bpf payload"
	@set -e; \
	trap 'rm -f $@.hex $@.tmp' EXIT; \
	od -An -v -tx1 $< > $@.hex; \
	{ \
	  printf '/* generated from steer_bpf.o; do not edit */\n'; \
	  printf 'const unsigned char steer_bpf_o[] = {\n'; \
	  awk '{ for (i = 1; i <= NF; i++) printf "0x%s,", $$i; printf "\n" }' $@.hex; \
	  printf '};\nconst unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);\n'; \
	} > $@.tmp; \
	mv $@.tmp $@

$(BUILD_DIR)/steer_bpf_data.o: $(BUILD_DIR)/steer_bpf_data.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<
endif

$(BUILD_DIR)/common/%.o: $(COMMON_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/common
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c -o $@ $<

$(BUILD_DIR)/oidc/%.o: $(OIDC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/oidc
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -I$(OIDC_DIR) -c -o $@ $<

$(BUILD_DIR)/main/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/main
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -I$(OIDC_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f SHASUMS.txt build-*.log

# Integration suite: tests/integration.sh needs root (TUN devices) and is
# therefore not run by CI — only locally, via sudo. The script handles
# privilege requirements itself; hint when it is not present yet (the
# script lands with the integration phase). The suite is Linux-only
# (TUN devices, root); the win32 cross build gets a no-op target.
ifeq ($(TARGET),win32)
test:
	@echo "integration tests are Linux-only (TUN devices, root); skipped for TARGET=win32"
else
test: all
	@if [ ! -x tests/integration.sh ]; then \
		echo "tests/integration.sh not found (integration phase pending); make test skipped"; \
		exit 0; \
	fi
	./tests/integration.sh
endif

# Compiler-generated header dependencies (from -MMD -MP). Wildcards expand
# to nothing on a fresh tree, which -include tolerates.
-include $(wildcard $(BUILD_DIR)/*.d $(BUILD_DIR)/common/*.d $(BUILD_DIR)/oidc/*.d $(BUILD_DIR)/main/*.d)

.DELETE_ON_ERROR:
