CC      ?= cc
CLANG   ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=c11 -D_GNU_SOURCE -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fPIE -MMD -MP
LDFLAGS := -pie -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack
LDLIBS  := -lcrypto -lpthread

SRC_DIR    := src
COMMON_DIR := $(SRC_DIR)/common
OIDC_DIR   := $(SRC_DIR)/oidc
BUILD_DIR  := build
BIN_DIR    := bin

# steer_bpf.c is compiled with clang -target bpf into a BPF ELF object
# (build/steer_bpf.o) that is embedded, not linked: it must never be
# recompiled for the host nor archived into the host static libraries,
# so exclude it from COMMON_SRCS.
COMMON_SRCS := $(filter-out $(COMMON_DIR)/steer_bpf.c,$(wildcard $(COMMON_DIR)/*.c))
OIDC_SRCS   := $(wildcard $(OIDC_DIR)/*.c)

# Objects are bucketed by source directory (build/common/, build/oidc/,
# build/main/) so the %.o pattern rules below cannot collide on basenames
# shared between directories.
COMMON_OBJS := $(patsubst $(COMMON_DIR)/%.c,$(BUILD_DIR)/common/%.o,$(COMMON_SRCS))
OIDC_OBJS   := $(patsubst $(OIDC_DIR)/%.c,$(BUILD_DIR)/oidc/%.o,$(OIDC_SRCS))

LIBCORE := $(BUILD_DIR)/libiwan_core.a
LIBOIDC := $(BUILD_DIR)/libiwan_oidc.a

.PHONY: all clean
all: $(BIN_DIR)/iwan-client $(BIN_DIR)/iwan-client-oidc $(BIN_DIR)/iwan-server

$(LIBCORE): $(COMMON_OBJS) $(BUILD_DIR)/steer_bpf_data.o
	rm -f $@ && ar rcs $@ $^

$(LIBOIDC): $(OIDC_OBJS)
	rm -f $@ && ar rcs $@ $^

$(BIN_DIR)/iwan-client: $(LIBCORE) $(BUILD_DIR)/main/iwan_client.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_client.o $(LIBCORE) $(LDLIBS)

$(BIN_DIR)/iwan-client-oidc: $(LIBCORE) $(LIBOIDC) $(BUILD_DIR)/main/iwan_client_oidc.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_client_oidc.o \
		-Wl,--start-group $(LIBCORE) $(LIBOIDC) -Wl,--end-group $(LDLIBS)

$(BIN_DIR)/iwan-server: $(LIBCORE) $(BUILD_DIR)/main/iwan_server.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(BUILD_DIR)/main/iwan_server.o $(LIBCORE) $(LDLIBS)

# Compile the tun steering classifier with clang for the BPF target. The
# result is a BPF ELF object, not a host object: never link it directly
# and never archive it into the host libraries.
$(BUILD_DIR)/steer_bpf.o: $(COMMON_DIR)/steer_bpf.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -O2 -target bpf -Wall -c -o $@ $<

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

# Compiler-generated header dependencies (from -MMD -MP). Wildcards expand
# to nothing on a fresh tree, which -include tolerates.
-include $(wildcard $(BUILD_DIR)/*.d $(BUILD_DIR)/common/*.d $(BUILD_DIR)/oidc/*.d $(BUILD_DIR)/main/*.d)

.DELETE_ON_ERROR:
