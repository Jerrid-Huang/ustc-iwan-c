#include "iwan_nt_mtu.h"

uint32_t
IwanNtMtuOverhead(
    unsigned Family
    )
{
    return (Family == 6u) ? IWAN_NT_MTU_OVERHEAD_V6 : IWAN_NT_MTU_OVERHEAD_V4;
}

uint32_t
IwanNtMtuEffective(
    uint32_t CarrierMtu,
    uint32_t PeerMtu,
    unsigned Family
    )
{
    uint32_t overhead = IwanNtMtuOverhead(Family);
    uint32_t candidate;

    candidate = (CarrierMtu > overhead) ? (CarrierMtu - overhead) : 0u;
    if (PeerMtu != 0u && PeerMtu < candidate) {
        candidate = PeerMtu;
    }
    if (candidate < IWAN_NT_MTU_MIN) {
        candidate = IWAN_NT_MTU_MIN;
    }
    if (candidate > IWAN_NT_MTU_MAX) {
        candidate = IWAN_NT_MTU_MAX;
    }
    return candidate;
}
