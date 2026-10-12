/*
 * 打印 WFP 内建层键（FWPM_LAYER_*）的真实 GUID 数值。
 *
 * 为什么需要：内核态的 fwpkclnt.lib 不导出这些层 GUID，驱动因此改成了运行时
 * 用 FwpmLayerGetById0(engine, FWPS_LAYER_* 枚举值) 反查。那个 id 空间与 FWPM
 * 的层 ID 并不是一回事，装错层的"终止型 callout 过滤器"会让判定无法解析、
 * 协议栈只能丢包 —— 全机流量的黑洞。层键是稳定常量，取出数值写死最稳。
 *
 * 用户态能链到 fwpuclnt.lib 里的这些符号，所以在这里打出来。
 */
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>

static void show(const char *name, const GUID *g)
{
	printf("%-40s 0x%08lX, 0x%04X, 0x%04X, { 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X }\n",
	       name, (unsigned long)g->Data1, (unsigned)g->Data2, (unsigned)g->Data3,
	       g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
	       g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

int main(void)
{
	show("FWPM_LAYER_OUTBOUND_IPPACKET_V4", &FWPM_LAYER_OUTBOUND_IPPACKET_V4);
	show("FWPM_LAYER_OUTBOUND_IPPACKET_V6", &FWPM_LAYER_OUTBOUND_IPPACKET_V6);
	show("FWPM_LAYER_INBOUND_TRANSPORT_V4", &FWPM_LAYER_INBOUND_TRANSPORT_V4);
	show("FWPM_LAYER_INBOUND_TRANSPORT_V6", &FWPM_LAYER_INBOUND_TRANSPORT_V6);
	show("FWPM_LAYER_INBOUND_IPPACKET_V4", &FWPM_LAYER_INBOUND_IPPACKET_V4);
	show("FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD", &FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD);
	show("FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD", &FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD);
	show("FWPM_LAYER_ALE_AUTH_CONNECT_V4", &FWPM_LAYER_ALE_AUTH_CONNECT_V4);
	show("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4", &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
	return 0;
}
