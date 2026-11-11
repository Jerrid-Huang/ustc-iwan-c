#include "iwan_nt_session.h"

#include "iwan_nt_string.h"

#include "iwan_nt_crypto.h"

static const uint8_t IwanNtSessionMagic[2] = { 'm', 'w' };

static void
IwanNtSessionPutBe16(
    uint8_t *Buffer,
    uint16_t Value
    )
{
    Buffer[0] = (uint8_t)((Value >> 8) & 0xFFu);
    Buffer[1] = (uint8_t)(Value & 0xFFu);
}

static void
IwanNtSessionPutBe32(
    uint8_t *Buffer,
    uint32_t Value
    )
{
    Buffer[0] = (uint8_t)((Value >> 24) & 0xFFu);
    Buffer[1] = (uint8_t)((Value >> 16) & 0xFFu);
    Buffer[2] = (uint8_t)((Value >> 8) & 0xFFu);
    Buffer[3] = (uint8_t)(Value & 0xFFu);
}

static uint16_t
IwanNtSessionGetBe16(
    const uint8_t *Buffer
    )
{
    return (uint16_t)(((uint16_t)Buffer[0] << 8) | (uint16_t)Buffer[1]);
}


/*
 * The session identifiers are not network order. The reference client loads them
 * with a plain 16/32-bit read and stores them with a plain write (no ntohs/ntohl
 * anywhere in its answer handler), so both ends must agree on the machine order of
 * the word -- little endian for the x86 builds this protocol ships for. Treating
 * them as network order parses an answer into a session whose identifiers never
 * match the ones on incoming frames, and every frame is then rejected as foreign.
 */
static void
IwanNtSessionPutLe16(
    uint8_t *Buffer,
    uint16_t Value
    )
{
    Buffer[0] = (uint8_t)(Value & 0xFFu);
    Buffer[1] = (uint8_t)((Value >> 8) & 0xFFu);
}

static void
IwanNtSessionPutLe32(
    uint8_t *Buffer,
    uint32_t Value
    )
{
    Buffer[0] = (uint8_t)(Value & 0xFFu);
    Buffer[1] = (uint8_t)((Value >> 8) & 0xFFu);
    Buffer[2] = (uint8_t)((Value >> 16) & 0xFFu);
    Buffer[3] = (uint8_t)((Value >> 24) & 0xFFu);
}

static uint16_t
IwanNtSessionGetLe16(
    const uint8_t *Buffer
    )
{
    return (uint16_t)((uint16_t)Buffer[0] | ((uint16_t)Buffer[1] << 8));
}

static uint32_t
IwanNtSessionGetLe32(
    const uint8_t *Buffer
    )
{
    return (uint32_t)Buffer[0] | ((uint32_t)Buffer[1] << 8) |
           ((uint32_t)Buffer[2] << 16) | ((uint32_t)Buffer[3] << 24);
}



/*
 * The signature covers the frame header and the literal suffix "mw"; the TLVs are
 * not covered, so a frame is authentic if and only if these ten bytes match.
 */
static void
IwanNtSessionSign(
    uint8_t *Frame
    )
{
    IWAN_NT_MD5_CTX context;
    uint8_t digest[16];

    IwanNtMd5Initialize(&context);
    IwanNtMd5Update(&context, Frame, IWAN_NT_SESSION_HEADER);
    IwanNtMd5Update(&context, IwanNtSessionMagic, sizeof(IwanNtSessionMagic));
    IwanNtMd5Finalize(&context, digest);
    IwanNtMemCopy(Frame + IWAN_NT_SESSION_HEADER, digest, sizeof(digest));
}

void
IwanNtSessionSignFrame(
    uint8_t *Frame
    )
{
    IwanNtSessionSign(Frame);
}

int
IwanNtSessionVerify(
    const uint8_t *Frame,
    size_t Length
    )
{
    IWAN_NT_MD5_CTX context;
    uint8_t digest[16];
    uint8_t difference;
    size_t index;

    if (Frame == NULL || Length < IWAN_NT_SESSION_PREFIX) {
        return 0;
    }

    /*
     * The deployed client verifies every control frame this way before it
     * touches the payload: md5(header || "mw") into the 16 bytes after the
     * header. Comparing without an early exit keeps the rejection branch from
     * depending on where the first differing byte sits.
     */
    IwanNtMd5Initialize(&context);
    IwanNtMd5Update(&context, Frame, IWAN_NT_SESSION_HEADER);
    IwanNtMd5Update(&context, IwanNtSessionMagic, sizeof(IwanNtSessionMagic));
    IwanNtMd5Finalize(&context, digest);

    difference = 0;
    for (index = 0; index < sizeof(digest); index++) {
        difference |= (uint8_t)(digest[index] ^
            Frame[IWAN_NT_SESSION_HEADER + index]);
    }
    return (difference == 0) ? 1 : 0;
}

void
IwanNtSessionKey(
    const char *User,
    const char *Password,
    uint8_t Key[8]
    )
{
    IWAN_NT_MD5_CTX context;
    uint8_t digest[16];

    IwanNtMd5Initialize(&context);
    IwanNtMd5Update(&context, User, IwanNtStringLength(User));
    IwanNtMd5Update(&context, Password, IwanNtStringLength(Password));
    IwanNtMd5Finalize(&context, digest);
    IwanNtMemCopy(Key, digest, 8);
    IwanNtMemZero(digest, sizeof(digest));
}

static size_t
IwanNtSessionPasswordBlock(
    const char *User,
    const char *Password,
    uint8_t Out[16]
    )
{
    IWAN_NT_MD5_CTX context;
    uint8_t key[16];
    uint8_t plain[16];
    size_t length;

    IwanNtMd5Initialize(&context);
    IwanNtMd5Update(&context, IwanNtSessionMagic, sizeof(IwanNtSessionMagic));
    IwanNtMd5Update(&context, User, IwanNtStringLength(User));
    IwanNtMd5Finalize(&context, key);

    /*
     * Long passwords are truncated, not rejected: the reference implementation
     * does the same, and the server compares against that same truncation.
     */
    IwanNtMemZero(plain, sizeof(plain));
    length = IwanNtStringLength(Password);
    if (length > sizeof(plain)) {
        length = sizeof(plain);
    }
    IwanNtMemCopy(plain, Password, length);

    IwanNtAes128EncryptBlock(key, plain, Out);
    IwanNtMemZero(key, sizeof(key));
    IwanNtMemZero(plain, sizeof(plain));
    return length;
}

IWAN_NT_SESSION_RESULT
IwanNtSessionBuildOpen(
    const IWAN_NT_SESSION_OPEN *Open,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    )
{
    size_t userLength;
    size_t offset = IWAN_NT_SESSION_PREFIX;
    uint8_t password[16];

    if (Open == NULL || Open->User == NULL || Open->Password == NULL ||
        Buffer == NULL || Length == NULL) {
        return IwanNtSessionBadArgument;
    }

    userLength = IwanNtStringLength(Open->User);
    if (userLength == 0 || userLength > 64u) {
        return IwanNtSessionBadArgument;
    }
    if (Capacity < IWAN_NT_SESSION_PREFIX + 4u + (2u + userLength) + 18u + 3u) {
        return IwanNtSessionTooLarge;
    }

    IwanNtMemZero(Buffer, IWAN_NT_SESSION_PREFIX);
    Buffer[0] = IWAN_NT_SESSION_TYPE_OPEN;
    /*
     * Header byte 1 carries the encryption request in OPEN and the session's
     * encryption state in every later frame. The deployment always asks for it,
     * and the server echoes the bit in its answer.
     */
    Buffer[1] = 1;

    /* TLV 3: path MTU, big endian. */
    Buffer[offset + 0u] = IWAN_NT_SESSION_TLV_MTU;
    Buffer[offset + 1u] = 4;
    IwanNtSessionPutBe16(Buffer + offset + 2u, Open->Mtu);
    offset += 4u;

    /*
     * TLV 1: user name, not NUL terminated.
     *
     * The length byte is the whole TLV size, header included, so it is the value
     * length plus two. This is the protocol's convention (both the vendor client
     * and src/common/protocol.c's tlv_put write vlen + 2), but it reads like an
     * off-by-two to anyone expecting a payload count: adding two bytes of padding
     * to "make the declaration true" shifts every later TLV and the server answers
     * "invalid packet format" without naming the field. Keep vlen + 2, write vlen.
     */
    Buffer[offset + 0u] = IWAN_NT_SESSION_TLV_USER;
    Buffer[offset + 1u] = (uint8_t)(2u + userLength);
    IwanNtMemCopy(Buffer + offset + 2u, Open->User, userLength);
    offset += 2u + userLength;

    /* TLV 2: AES-128-ECB of the zero-padded password. */
    (void)IwanNtSessionPasswordBlock(Open->User, Open->Password, password);
    Buffer[offset + 0u] = IWAN_NT_SESSION_TLV_PASSWORD;
    Buffer[offset + 1u] = 18;
    IwanNtMemCopy(Buffer + offset + 2u, password, sizeof(password));
    offset += 18u;
    IwanNtMemZero(password, sizeof(password));

    /* TLV 8: request the encrypted DATA form. */
    Buffer[offset + 0u] = IWAN_NT_SESSION_TLV_ENCRYPT;
    Buffer[offset + 1u] = 3;
    Buffer[offset + 2u] = 1;
    offset += 3u;

    IwanNtSessionSign(Buffer);
    *Length = offset;
    return IwanNtSessionOk;
}

IWAN_NT_SESSION_RESULT
IwanNtSessionParseAck(
    const uint8_t *Frame,
    size_t Length,
    IWAN_NT_SESSION_ACK *Ack
    )
{
    size_t offset;

    if (Frame == NULL || Ack == NULL) {
        return IwanNtSessionBadArgument;
    }
    if (Length < IWAN_NT_SESSION_PREFIX) {
        return IwanNtSessionShortFrame;
    }
    if (IwanNtSessionVerify(Frame, Length) == 0) {
        return IwanNtSessionBadSignature;
    }
    if (Frame[0] != IWAN_NT_SESSION_TYPE_OPEN_ACK &&
        Frame[0] != IWAN_NT_SESSION_TYPE_OPEN_REJECT) {
        return IwanNtSessionWrongType;
    }

    IwanNtMemZero(Ack, sizeof(*Ack));
    Ack->Sid = IwanNtSessionGetLe16(Frame + 2u);
    Ack->Token = IwanNtSessionGetLe32(Frame + 4u);

    offset = IWAN_NT_SESSION_PREFIX;
    while (offset + 2u <= Length) {
        uint8_t type = Frame[offset + 0u];
        uint8_t tlvLength = Frame[offset + 1u];
        const uint8_t *value = Frame + offset + 2u;
        size_t valueLength;

        if (tlvLength < 2u || offset + tlvLength > Length) {
            return IwanNtSessionBadTlv;
        }
        valueLength = (size_t)tlvLength - 2u;

        switch (type) {
        case IWAN_NT_SESSION_TLV_MTU:
            if (valueLength != 2u) {
                return IwanNtSessionBadTlv;
            }
            Ack->Mtu = IwanNtSessionGetBe16(value);
            break;
        case IWAN_NT_SESSION_TLV_ADDRESS:
            if (valueLength != 4u) {
                return IwanNtSessionBadTlv;
            }
            IwanNtMemCopy(Ack->Address, value, 4);
            Ack->HasAddress = 1;
            break;
        case IWAN_NT_SESSION_TLV_GATEWAY:
            if (valueLength != 4u) {
                return IwanNtSessionBadTlv;
            }
            IwanNtMemCopy(Ack->Gateway, value, 4);
            Ack->HasGateway = 1;
            break;
        case IWAN_NT_SESSION_TLV_ENCRYPT:
            if (valueLength != 1u) {
                return IwanNtSessionBadTlv;
            }
            Ack->Encrypted = value[0];
            break;
        default:
            /* DNS and the IPv6 peer group are parsed elsewhere; skip them. */
            break;
        }

        offset += tlvLength;
    }

    return IwanNtSessionOk;
}

IWAN_NT_SESSION_RESULT
IwanNtSessionBuildEchoRequest(
    uint16_t Sid,
    uint32_t Token,
    uint64_t TickMicros,
    uint8_t *Buffer,
    size_t Capacity,
    size_t *Length
    )
{
    size_t offset;

    if (Buffer == NULL || Length == NULL) {
        return IwanNtSessionBadArgument;
    }
    if (Capacity < IWAN_NT_SESSION_ECHO_LEN) {
        return IwanNtSessionTooLarge;
    }

    IwanNtMemZero(Buffer, IWAN_NT_SESSION_ECHO_LEN);
    Buffer[0] = IWAN_NT_SESSION_TYPE_ECHO_REQUEST;
    Buffer[1] = 0;
    IwanNtSessionPutLe16(Buffer + 2u, Sid);
    IwanNtSessionPutLe32(Buffer + 4u, Token);
    IwanNtSessionSign(Buffer);

    offset = IWAN_NT_SESSION_PREFIX;
    /* The tick is little endian: the peer reads it as a host-order integer. */
    IwanNtMemCopy(Buffer + offset, &TickMicros, sizeof(TickMicros));
    offset += 8u;
    /*
     * The delays are machine order as well: the reference client stores them from
     * its own fields with plain moves, in the same buffer as the tick.
     */
    /* current delay: unknown before the first response */
    IwanNtSessionPutLe32(Buffer + offset, 0);
    offset += 4u;
    /* minimum delay seed, matching the reference client */
    IwanNtSessionPutLe32(Buffer + offset, 5000000u);
    offset += 4u;
    /* maximum delay */
    IwanNtSessionPutLe32(Buffer + offset, 0);
    offset += 4u;
    /* four bytes the reference client never writes */
    offset += 4u;
    IwanNtMemCopy(Buffer + offset, "SDRT", 4u);
    offset += 4u;
    /* route magic and entry count: this build never fills the table */
    IwanNtSessionPutBe32(Buffer + offset, 0);
    offset += 4u;
    IwanNtSessionPutBe32(Buffer + offset, 0);
    offset += 4u;

    *Length = offset;
    return IwanNtSessionOk;
}

uint8_t
IwanNtSessionType(
    const uint8_t *Frame,
    size_t Length
    )
{
    if (Frame == NULL || Length < 1u) {
        return 0;
    }
    return Frame[0];
}

IWAN_NT_SESSION_RESULT
IwanNtSessionParseEchoResponse(
    const uint8_t *Frame,
    size_t Length,
    IWAN_NT_SESSION_ECHO *Echo
    )
{
    if (Frame == NULL || Echo == NULL) {
        return IwanNtSessionBadArgument;
    }
    if (Length < IWAN_NT_SESSION_ECHO_LEN) {
        return IwanNtSessionShortFrame;
    }
    if (Frame[0] != IWAN_NT_SESSION_TYPE_ECHO_RESPONSE) {
        return IwanNtSessionWrongType;
    }

    IwanNtMemZero(Echo, sizeof(*Echo));
    Echo->Sid = IwanNtSessionGetLe16(Frame + 2u);
    Echo->Token = IwanNtSessionGetLe32(Frame + 4u);
    IwanNtMemCopy(&Echo->Tick, Frame + IWAN_NT_SESSION_PREFIX, sizeof(Echo->Tick));
    Echo->Current = IwanNtSessionGetLe32(Frame + IWAN_NT_SESSION_PREFIX + 8u);
    Echo->Minimum = IwanNtSessionGetLe32(Frame + IWAN_NT_SESSION_PREFIX + 12u);
    Echo->Maximum = IwanNtSessionGetLe32(Frame + IWAN_NT_SESSION_PREFIX + 16u);
    return IwanNtSessionOk;
}
