#!/bin/bash
# Cross-implementation differential test: is the kernel module iwan_xor() byte-for-byte equivalent to the userspace production xor_crypt()?
#
# Why this test exists: the wire format specifies XOR over all bytes of the inner IPv4 packet, and each side
# has its own implementation (the module uses 64-bit words + tail bytes, userspace xor_crypt() is written differently).
# If "byte-for-byte equivalent" is only a claim in a comment, a change on either side can silently break interoperability, and such
# breakage is completely invisible in a "module talks to itself" test.
#
# Approach: extract iwan_xor() **verbatim from the source** of kernel/iwan_core.c and compare it against
# xor_crypt() from src/common/crypto.c on random data and random lengths (including zero length and various tails not 8-byte aligned).
# Extracting rather than rewriting guarantees that the code under test is exactly the code compiled into the module.
#
# No root required. Usage: bash kernel/tests/xor_equiv_test.sh
set -u

cd "$(dirname "$0")/../.." || exit 1

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  bad  %s\n' "$*"; FAIL=$((FAIL + 1)); }
info() { printf '  --   %s\n' "$*"; }

PASS=0
FAIL=0
TRIALS=${TRIALS:-200000}

say "== module iwan_xor() vs production xor_crypt() differential test (no root) =="

SRC=kernel/iwan_core.c
[ -f "$SRC" ] || { say "$SRC not found"; exit 1; }

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# Extract the function: from "^void iwan_xor(" to the first "}" at line start, immune to source line number changes.
awk '/^void iwan_xor\(/{f=1} f{print} f&&/^}/{exit}' "$SRC" > "$TMP/iwan_xor.inc"
if ! grep -q 'while (i + 8 <= len)' "$TMP/iwan_xor.inc"; then
    bad "iwan_xor() extraction failed or the implementation changed (content of $TMP/iwan_xor.inc does not match expectations)"
    say "PASS=$PASS FAIL=$FAIL"
    exit 1
fi
info "extracted $(wc -l < "$TMP/iwan_xor.inc") lines of iwan_xor() source from $SRC"

cat > "$TMP/equiv.c" <<'EOF'
/* Differential test driver: module iwan_xor() (extracted verbatim) vs production xor_crypt() */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint64_t u64;
#define IWAN_KEY_LEN 8
#include "iwan_xor.inc"
#include "crypto.h"

/* Symbols referenced by crypto.c functions this test does not call; minimal stubs for linking */
void log_err(const char *fmt, ...) { (void)fmt; }
void oom_abort(void) { abort(); }

int main(int argc, char **argv)
{
	unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 200000;
	unsigned long t, bad = 0, len0 = 0, maxlen = 0;
	srand(12345);
	for (t = 0; t < trials; t++) {
		size_t len = (size_t)(rand() % 129), i;
		uint8_t key[8], a[160], b[160];
		for (i = 0; i < 8; i++)
			key[i] = (uint8_t)rand();
		for (i = 0; i < len; i++)
			a[i] = b[i] = (uint8_t)rand();
		if (len == 0)
			len0++;
		if (len > maxlen)
			maxlen = len;
		xor_crypt(a, len, key, 8);
		iwan_xor(b, len, key, 0);
		if (memcmp(a, b, len)) {
			if (bad++ < 3)
				printf("MISMATCH len=%zu\n", len);
		}
	}
	printf("TRIALS=%lu MISMATCH=%lu LEN0_CASES=%lu MAXLEN=%lu XOR_EQUIV=%d\n",
	       trials, bad, len0, maxlen, bad == 0);
	return bad != 0;
}
EOF

if ! cc -O2 -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -I src/common -I "$TMP" \
	-o "$TMP/equiv" "$TMP/equiv.c" src/common/crypto.c -lcrypto 2> "$TMP/cc.log"; then
	bad "compilation failed"
	sed -n '1,20p' "$TMP/cc.log"
	say "PASS=$PASS FAIL=$FAIL"
	exit 1
fi
if [ -s "$TMP/cc.log" ]; then
	info "compile warnings: $(grep -c warning "$TMP/cc.log") (-Wall -Wextra)"
fi
ok "differential test driver compiled"

OUT=$("$TMP/equiv" "$TRIALS")
RC=$?
say "$OUT"
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -q 'XOR_EQUIV=1'; then
	ok "module iwan_xor() and production xor_crypt() are byte-for-byte equivalent over $TRIALS random cases"
else
	bad "mismatch found (exit code $RC)"
fi

say "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
