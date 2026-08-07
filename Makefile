CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=c11 -D_GNU_SOURCE
LDLIBS  := -lcrypto -lpthread

SRC_DIR    := src
COMMON_DIR := $(SRC_DIR)/common
OIDC_DIR   := $(SRC_DIR)/oidc
BUILD_DIR  := build
BIN_DIR    := bin

COMMON_SRCS := $(wildcard $(COMMON_DIR)/*.c)
OIDC_SRCS   := $(wildcard $(OIDC_DIR)/*.c)
MAIN_SRCS   := $(SRC_DIR)/iwan_client.c $(SRC_DIR)/iwan_client_oidc.c $(SRC_DIR)/iwan_server.c

COMMON_OBJS := $(patsubst $(COMMON_DIR)/%.c,$(BUILD_DIR)/%.o,$(COMMON_SRCS))
OIDC_OBJS   := $(patsubst $(OIDC_DIR)/%.c,$(BUILD_DIR)/%.o,$(OIDC_SRCS))
MAIN_OBJS   := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MAIN_SRCS))
ALL_HEADERS := $(wildcard $(COMMON_DIR)/*.h $(OIDC_DIR)/*.h)

LIBCORE := $(BUILD_DIR)/libiwan_core.a
LIBOIDC := $(BUILD_DIR)/libiwan_oidc.a

.PHONY: all clean
all: $(BIN_DIR)/iwan-client $(BIN_DIR)/iwan-client-oidc $(BIN_DIR)/iwan-server

$(LIBCORE): $(COMMON_OBJS) $(BUILD_DIR)/steer_bpf_data.o
	ar rcs $@ $^

$(LIBOIDC): $(OIDC_OBJS)
	ar rcs $@ $^

$(BIN_DIR)/iwan-client: $(LIBCORE) $(BUILD_DIR)/iwan_client.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(BUILD_DIR)/iwan_client.o $(LIBCORE) $(LDLIBS)

$(BIN_DIR)/iwan-client-oidc: $(LIBCORE) $(LIBOIDC) $(BUILD_DIR)/iwan_client_oidc.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(BUILD_DIR)/iwan_client_oidc.o \
		-Wl,--start-group $(LIBCORE) $(LIBOIDC) -Wl,--end-group $(LDLIBS)

$(BIN_DIR)/iwan-server: $(LIBCORE) $(BUILD_DIR)/iwan_server.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(BUILD_DIR)/iwan_server.o $(LIBCORE) $(LDLIBS)

$(BUILD_DIR)/steer_bpf.o: $(COMMON_DIR)/steer_bpf.c
	@mkdir -p $(BUILD_DIR)
	clang -O2 -target bpf -Wall -c -o $@ $<

$(BUILD_DIR)/steer_bpf_data.c: $(BUILD_DIR)/steer_bpf.o
	@echo "generating embedded bpf payload"
	@(printf '/* generated from steer_bpf.o; do not edit */\n'; \
	  printf 'const unsigned char steer_bpf_o[] = {\n'; \
	  od -An -v -tx1 $< | awk '{ for (i = 1; i <= NF; i++) printf "0x%s,", $$i; printf "\n" }'; \
	  printf '};\nconst unsigned int steer_bpf_o_len = sizeof(steer_bpf_o);\n') > $@

$(BUILD_DIR)/steer_bpf_data.o: $(BUILD_DIR)/steer_bpf_data.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: $(COMMON_DIR)/%.c $(ALL_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c -o $@ $<

$(BUILD_DIR)/%.o: $(OIDC_DIR)/%.c $(ALL_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -I$(OIDC_DIR) -c -o $@ $<

$(BUILD_DIR)/iwan_client.o: $(SRC_DIR)/iwan_client.c $(ALL_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c -o $@ $<

$(BUILD_DIR)/iwan_client_oidc.o: $(SRC_DIR)/iwan_client_oidc.c $(ALL_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -I$(OIDC_DIR) -c -o $@ $<

$(BUILD_DIR)/iwan_server.o: $(SRC_DIR)/iwan_server.c $(ALL_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(COMMON_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)