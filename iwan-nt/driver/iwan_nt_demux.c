#include "iwan_nt_demux.h"

#include <string.h>

static IWAN_NT_DEMUX_RESULT
SetResult(
    IWAN_NT_DEMUX_DECISION *Decision,
    IWAN_NT_DEMUX_RESULT Result
    )
{
    Decision->Result = Result;
    return Result;
}

static IWAN_NT_DEMUX_CLASS
Classify(
    uint8_t Type
    )
{
    if (IwanNtFrameTypeIsData(Type)) {
        return IwanNtDemuxClassData;
    }

    switch (Type) {
    case IWAN_NT_TYPE_OPEN_REJECT:
    case IWAN_NT_TYPE_OPEN_ACK:
    case IWAN_NT_TYPE_OPEN:
    case IWAN_NT_TYPE_ECHO_REQ:
    case IWAN_NT_TYPE_ECHO_RESPONSE:
    case IWAN_NT_TYPE_CLOSE:
        return IwanNtDemuxClassControl;
    default:
        break;
    }

    return IwanNtDemuxClassUnknown;
}

IWAN_NT_DEMUX_RESULT
IwanNtDemuxPayload(
    const uint8_t *Payload,
    size_t Length,
    const IWAN_NT_DEMUX_SESSION *Session,
    IWAN_NT_DEMUX_DECISION *Decision
    )
{
    IWAN_NT_FRAME_RESULT frameResult;
    IWAN_NT_DEMUX_CLASS frameClass;
    size_t bodyLength;
    size_t innerMin;
    unsigned expectedFamily;
    unsigned innerFamily;
    int encryptedFrame;
    int encryptedSession;

    if (Decision == NULL) {
        return IwanNtDemuxBadArgument;
    }

    memset(Decision, 0, sizeof(*Decision));
    Decision->Class = IwanNtDemuxClassUnknown;
    Decision->Result = IwanNtDemuxOk;

    if (Payload == NULL || Session == NULL) {
        return SetResult(Decision, IwanNtDemuxBadArgument);
    }
    if (Length == 0) {
        return SetResult(Decision, IwanNtDemuxTooShort);
    }

    /*
     * SEGRT begins with its type and has neither the normal 8-byte header nor
     * a signature. It must be recognized before any header decoding, and its
     * sid/token bytes (if any) are not session fields.
     */
    if (Payload[0] == IWAN_NT_TYPE_SEGRT) {
        Decision->Class = IwanNtDemuxClassSegrt;
        Decision->RegionOffset = 0;
        Decision->RegionLength = Length;
        if (Length < IWAN_NT_SEGRT_MIN_LEN) {
            return SetResult(Decision, IwanNtDemuxTooShort);
        }
        return IwanNtDemuxOk;
    }

    frameClass = Classify(Payload[0]);
    Decision->Class = frameClass;

    if (Length < IWAN_NT_FRAME_HDR_LEN) {
        return SetResult(Decision, IwanNtDemuxTooShort);
    }

    frameResult = IwanNtFrameHeaderDecode(Payload, Length, &Decision->Header);
    if (frameResult != IwanNtFrameOk) {
        /*
         * HeaderDecode can only fail on a short or absent buffer here; the
         * length check above has already ruled out the latter.
         */
        return SetResult(Decision, IwanNtDemuxTooShort);
    }
    Decision->HeaderValid = 1;

    /*
     * Session identity is checked before type-specific framing so a payload
     * from another session is never passed to a consumer, regardless of how
     * well-formed its body is.
     */
    if (Decision->Header.Sid != Session->Sid) {
        return SetResult(Decision, IwanNtDemuxSidMismatch);
    }
    if (Decision->Header.Token != Session->Token) {
        return SetResult(Decision, IwanNtDemuxTokenMismatch);
    }

    switch (frameClass) {
    case IwanNtDemuxClassData:
        encryptedFrame = (Decision->Header.Encrypt != 0u) ? 1 : 0;
        encryptedSession = (Session->Encrypted != 0) ? 1 : 0;

        /*
         * Match the rule in IwanNtFrameOpen: the wire encrypt flag and the
         * frame type must describe the same transform. Then require that
         * transform to be the one this session negotiated.
         */
        if (encryptedFrame !=
            (IwanNtFrameTypeIsEncrypted(Decision->Header.Type) ? 1 : 0)) {
            return SetResult(Decision, IwanNtDemuxEncryptMismatch);
        }
        if (encryptedFrame != encryptedSession) {
            return SetResult(Decision, IwanNtDemuxEncryptMismatch);
        }

        bodyLength = Length - IWAN_NT_FRAME_HDR_LEN;
        if (Decision->Header.Type == IWAN_NT_TYPE_DATA6 ||
            Decision->Header.Type == IWAN_NT_TYPE_DATA6_ENC) {
            innerMin = IWAN_NT_INNER_IP6_MIN;
            expectedFamily = 6;
        } else {
            innerMin = IWAN_NT_INNER_IP4_MIN;
            expectedFamily = 4;
        }

        /*
         * An encrypted DATA body is still ciphertext at this layer. Without
         * the session key the demux cannot inspect its version nibble or
         * header lengths; IwanNtFrameOpen performs that validation when the
         * owner of the session key consumes the decision.
         */
        if (encryptedSession) {
            if (bodyLength < innerMin) {
                return SetResult(Decision, IwanNtDemuxBadInnerLength);
            }
        } else {
            innerFamily = IwanNtFrameInnerFamily(
                Payload + IWAN_NT_FRAME_HDR_LEN, bodyLength);

            /*
             * A recognizable version that contradicts the frame type is a
             * family error even when the body is also shorter than that
             * frame type's own minimum. A body too short to expose any inner
             * header is still a length error.
             */
            if (innerFamily != 0u && innerFamily != expectedFamily) {
                return SetResult(Decision, IwanNtDemuxBadInnerFamily);
            }
            if (bodyLength < innerMin) {
                return SetResult(Decision, IwanNtDemuxBadInnerLength);
            }
            if (innerFamily != expectedFamily) {
                return SetResult(Decision, IwanNtDemuxBadInnerFamily);
            }

            frameResult = IwanNtFrameInnerSane(
                Payload + IWAN_NT_FRAME_HDR_LEN, bodyLength);
            if (frameResult != IwanNtFrameOk) {
                if (frameResult == IwanNtFrameBadLength) {
                    return SetResult(Decision, IwanNtDemuxBadInnerLength);
                }
                return SetResult(Decision, IwanNtDemuxBadInnerFamily);
            }
        }

        Decision->RegionOffset = IWAN_NT_FRAME_HDR_LEN;
        Decision->RegionLength = bodyLength;
        return IwanNtDemuxOk;

    case IwanNtDemuxClassControl:
        /*
         * Control frames are not transformed and must carry the complete
         * signature. Its contents are checked by the control consumer, which
         * owns the authentication material.
         */
        if (Decision->Header.Encrypt != 0u) {
            return SetResult(Decision, IwanNtDemuxEncryptMismatch);
        }
        if (Length < (size_t)IWAN_NT_CONTROL_MIN_LEN) {
            return SetResult(Decision, IwanNtDemuxBadSignatureLength);
        }

        Decision->RegionOffset = IWAN_NT_CONTROL_MIN_LEN;
        Decision->RegionLength = Length - IWAN_NT_CONTROL_MIN_LEN;
        return IwanNtDemuxOk;

    case IwanNtDemuxClassUnknown:
        /*
         * An unrecognized type is not malformed by itself. Once its normal
         * header and session identity check out, expose the unparsed tail to
         * the caller instead of rejecting bytes this module cannot classify.
         */
        Decision->RegionOffset = IWAN_NT_FRAME_HDR_LEN;
        Decision->RegionLength = Length - IWAN_NT_FRAME_HDR_LEN;
        return IwanNtDemuxOk;

    default:
        return SetResult(Decision, IwanNtDemuxBadArgument);
    }
}
