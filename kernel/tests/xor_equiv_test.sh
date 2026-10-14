#!/bin/bash
# 跨实现对拍：内核模块的 iwan_xor() 与用户态生产实现 xor_crypt() 是否逐字节等价。
#
# 为什么要有这个测试：线格式规定 XOR 作用于内层 IPv4 包的全部字节，两侧各自
# 实现了一份（模块用 64 位字 + 尾部字节，用户态 xor_crypt() 另有其写法）。
# "逐字节等价"如果只是注释里的声明，任何一侧改动都可能悄悄破坏互通，而这种
# 破坏在"模块自打自收"的测试里完全看不出来。
#
# 做法：从 kernel/iwan_core.c **按源码原文抽取** iwan_xor()，与 src/common/crypto.c
# 的 xor_crypt() 在随机数据、随机长度（含 0 长度与各种非 8 字节对齐尾巴）上对拍。
# 抽取而不是重写，是为了保证被测的就是模块真正编译进去的那段代码。
#
# 不需要 root。用法：bash kernel/tests/xor_equiv_test.sh
set -u

cd "$(dirname "$0")/../.." || exit 1

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  bad  %s\n' "$*"; FAIL=$((FAIL + 1)); }
info() { printf '  --   %s\n' "$*"; }

PASS=0
FAIL=0
TRIALS=${TRIALS:-200000}

say "== 模块 iwan_xor() vs 生产 xor_crypt() 对拍（无 root） =="

SRC=kernel/iwan_core.c
[ -f "$SRC" ] || { say "找不到 $SRC"; exit 1; }

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# 抽取函数：从 "^void iwan_xor(" 到第一个行首 "}"，对源码行号变化免疫。
awk '/^void iwan_xor\(/{f=1} f{print} f&&/^}/{exit}' "$SRC" > "$TMP/iwan_xor.inc"
if ! grep -q 'while (i + 8 <= len)' "$TMP/iwan_xor.inc"; then
    bad "iwan_xor() 抽取失败或实现已变（$TMP/iwan_xor.inc 内容不符预期）"
    say "PASS=$PASS FAIL=$FAIL"
    exit 1
fi
info "已从 $SRC 抽取 $(wc -l < "$TMP/iwan_xor.inc") 行 iwan_xor() 源码"

cat > "$TMP/equiv.c" <<'EOF'
/* 对拍驱动：模块 iwan_xor()（源码原文抽取）vs 生产 xor_crypt() */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint64_t u64;
#define IWAN_KEY_LEN 8
#include "iwan_xor.inc"
#include "crypto.h"

/* crypto.c 中本测试不调用的函数所引用的符号，链接用最小桩 */
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
	bad "编译失败"
	sed -n '1,20p' "$TMP/cc.log"
	say "PASS=$PASS FAIL=$FAIL"
	exit 1
fi
if [ -s "$TMP/cc.log" ]; then
	info "编译告警：$(grep -c warning "$TMP/cc.log") 条（-Wall -Wextra）"
fi
ok "对拍驱动编译通过"

OUT=$("$TMP/equiv" "$TRIALS")
RC=$?
say "$OUT"
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -q 'XOR_EQUIV=1'; then
	ok "模块 iwan_xor() 与生产 xor_crypt() 在 $TRIALS 组随机用例上逐字节等价"
else
	bad "存在不一致（退出码 $RC）"
fi

say "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
