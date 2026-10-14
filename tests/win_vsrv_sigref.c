/* 宿主侧对拍：用树内 ctrl_hdr()（OpenSSL 的 md5）生成四个控制帧整帧，
 * 与 tests/win_vsrv.c 内置 MD5 生成的同名帧逐字节比较。 */
#include <stdio.h>

#include "common.h"
#include "protocol.h"

static void dump(const char *tag, uint8_t typ, uint8_t enc, uint16_t sid, uint32_t tok)
{
    buf_t b;
    size_t i;

    buf_init(&b);
    ctrl_hdr(&b, typ, enc, sid, tok);
    printf("%s ", tag);
    for (i = 0; i < b.len; i++)
        printf("%02x", b.data[i]);
    printf("\n");
    buf_free(&b);
}

int main(void)
{
    dump("OPEN_ACK", PT_OPEN_ACK, 1, 0x1234, 0x12345678u);
    dump("ECHO_RES", PT_ECHO_RES, 1, 0x1234, 0x12345678u);
    dump("PING_RSP", PT_PING_RSP, 0, IWAN_PING_SID, IWAN_PING_TOK);
    dump("ECHO_REQ", PT_ECHO_REQ, 1, 0x0002, 0xdeadbeefu);
    return 0;
}
