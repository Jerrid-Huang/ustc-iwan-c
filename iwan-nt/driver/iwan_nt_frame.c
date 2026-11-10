#include "iwan_nt_frame.h"

void
IwanNtFrameHeaderEncode(
    uint8_t *Out,
    const IWAN_NT_FRAME_HEADER *Header
    )
{
    if (Out == NULL || Header == NULL) {
        return;
    }

    Out[0] = Header->Type;
    Out[1] = Header->Encrypt;
    Out[2] = (uint8_t)(Header->Sid & 0xffu);
    Out[3] = (uint8_t)((Header->Sid >> 8) & 0xffu);
    Out[4] = (uint8_t)(Header->Token & 0xffu);
    Out[5] = (uint8_t)((Header->Token >> 8) & 0xffu);
    Out[6] = (uint8_t)((Header->Token >> 16) & 0xffu);
    Out[7] = (uint8_t)((Header->Token >> 24) & 0xffu);
}

IWAN_NT_FRAME_RESULT
IwanNtFrameHeaderDecode(
    const uint8_t *In,
    size_t Length,
    IWAN_NT_FRAME_HEADER *Header
    )
{
    if (In == NULL || Header == NULL) {
        return IwanNtFrameBadArgument;
    }
    if (Length < IWAN_NT_FRAME_HDR_LEN) {
        return IwanNtFrameTooShort;
    }

    Header->Type = In[0];
    Header->Encrypt = In[1];
    Header->Sid = (uint16_t)((uint16_t)In[2] | ((uint16_t)In[3] << 8));
    Header->Token = ((uint32_t)In[4]) |
                    ((uint32_t)In[5] << 8) |
                    ((uint32_t)In[6] << 16) |
                    ((uint32_t)In[7] << 24);
    return IwanNtFrameOk;
}

void
IwanNtFrameXor(
    uint8_t *Body,
    size_t Length,
    const uint8_t *Key
    )
{
    size_t i;

    if (Body == NULL || Key == NULL) {
        return;
    }

    for (i = 0; i < Length; i++) {
        Body[i] ^= Key[i & (IWAN_NT_FRAME_KEY_LEN - 1u)];
    }
}

unsigned
IwanNtFrameInnerFamily(
    const uint8_t *Inner,
    size_t Length
    )
{
    if (Inner == NULL) {
        return 0;
    }

    if (Length >= IWAN_NT_INNER_IP4_MIN && (Inner[0] >> 4) == 4u) {
        return 4;
    }
    if (Length >= IWAN_NT_INNER_IP6_MIN && (Inner[0] >> 4) == 6u) {
        return 6;
    }
    return 0;
}

IWAN_NT_FRAME_RESULT
IwanNtFrameInnerSane(
    const uint8_t *Inner,
    size_t Length
    )
{
    unsigned family;
    size_t declared;

    if (Inner == NULL) {
        return IwanNtFrameBadArgument;
    }

    family = IwanNtFrameInnerFamily(Inner, Length);
    if (family == 4u) {
        size_t ihl = (size_t)(Inner[0] & 0x0fu) * 4u;
        size_t total;

        if (ihl < IWAN_NT_INNER_IP4_MIN) {
            return IwanNtFrameBadLength;
        }
        total = ((size_t)Inner[2] << 8) | (size_t)Inner[3];
        if (total < ihl || total > Length) {
            return IwanNtFrameBadLength;
        }
        return IwanNtFrameOk;
    }
    if (family == 6u) {
        size_t payload = ((size_t)Inner[4] << 8) | (size_t)Inner[5];

        declared = IWAN_NT_INNER_IP6_MIN + payload;
        if (declared > Length) {
            return IwanNtFrameBadLength;
        }
        return IwanNtFrameOk;
    }

    return IwanNtFrameBadFamily;
}

int
IwanNtFrameTypeIsEncrypted(
    uint8_t Type
    )
{
    return Type == IWAN_NT_TYPE_DATA_ENC || Type == IWAN_NT_TYPE_DATA6_ENC;
}

int
IwanNtFrameTypeIsData(
    uint8_t Type
    )
{
    return Type == IWAN_NT_TYPE_DATA ||
           Type == IWAN_NT_TYPE_DATA_ENC ||
           Type == IWAN_NT_TYPE_DATA6 ||
           Type == IWAN_NT_TYPE_DATA6_ENC;
}

IWAN_NT_FRAME_RESULT
IwanNtFrameSeal(
    uint8_t *Out,
    size_t OutCap,
    const uint8_t *Inner,
    size_t InnerLength,
    const IWAN_NT_FRAME_HEADER *Header,
    const uint8_t *Key,
    size_t *OutLength
    )
{
    IWAN_NT_FRAME_HEADER header;
    size_t body_start = IWAN_NT_FRAME_HDR_LEN;

    if (Out == NULL || Inner == NULL || Header == NULL || OutLength == NULL) {
        return IwanNtFrameBadArgument;
    }
    if (!IwanNtFrameTypeIsData(Header->Type)) {
        return IwanNtFrameBadType;
    }
    if (OutCap < body_start || InnerLength > OutCap - body_start) {
        return IwanNtFrameTooLong;
    }
    if (IwanNtFrameInnerSane(Inner, InnerLength) != IwanNtFrameOk) {
        return IwanNtFrameBadFamily;
    }

    header = *Header;
    if (IwanNtFrameTypeIsEncrypted(header.Type)) {
        if (Key == NULL) {
            return IwanNtFrameBadArgument;
        }
        header.Encrypt = 1u;
    } else {
        header.Encrypt = 0u;
    }

    IwanNtFrameHeaderEncode(Out, &header);

    /* Copy the inner packet body, then transform it in place. */
    {
        size_t i;

        for (i = 0; i < InnerLength; i++) {
            Out[body_start + i] = Inner[i];
        }
    }

    if (header.Encrypt != 0u) {
        IwanNtFrameXor(Out + body_start, InnerLength, Key);
    }

    *OutLength = body_start + InnerLength;
    return IwanNtFrameOk;
}

IWAN_NT_FRAME_RESULT
IwanNtFrameOpen(
    uint8_t *Payload,
    size_t Length,
    const uint8_t *Key,
    IWAN_NT_FRAME_HEADER *Header,
    const uint8_t **Inner,
    size_t *InnerLength
    )
{
    IWAN_NT_FRAME_RESULT result;
    IWAN_NT_FRAME_HEADER header;
    size_t body_length;

    if (Payload == NULL || Header == NULL || Inner == NULL ||
        InnerLength == NULL) {
        return IwanNtFrameBadArgument;
    }

    result = IwanNtFrameHeaderDecode(Payload, Length, &header);
    if (result != IwanNtFrameOk) {
        return result;
    }
    if (!IwanNtFrameTypeIsData(header.Type)) {
        return IwanNtFrameBadType;
    }

    /*
     * The encrypted flag in the header and the frame type must agree; a body
     * transformed under one rule must never be interpreted under the other.
     */
    if ((header.Encrypt != 0u) !=
        (IwanNtFrameTypeIsEncrypted(header.Type) ? 1 : 0)) {
        return IwanNtFrameBadType;
    }

    body_length = Length - IWAN_NT_FRAME_HDR_LEN;
    if (header.Encrypt != 0u) {
        if (Key == NULL) {
            return IwanNtFrameBadArgument;
        }
        IwanNtFrameXor(Payload + IWAN_NT_FRAME_HDR_LEN, body_length, Key);
    }

    result = IwanNtFrameInnerSane(Payload + IWAN_NT_FRAME_HDR_LEN, body_length);
    if (result != IwanNtFrameOk) {
        /*
         * Restore the ciphertext so a rejected frame is left exactly as it
         * arrived; callers may still need the original bytes for diagnosis.
         */
        if (header.Encrypt != 0u) {
            IwanNtFrameXor(Payload + IWAN_NT_FRAME_HDR_LEN, body_length, Key);
        }
        return result;
    }

    *Header = header;
    *Inner = Payload + IWAN_NT_FRAME_HDR_LEN;
    *InnerLength = body_length;
    return IwanNtFrameOk;
}
