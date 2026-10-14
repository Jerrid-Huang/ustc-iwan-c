#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# capture_iwan.py —— 在设备层抓 iWAN 外层报文，把 UDP 载荷写盘，供跨实现对拍。
#
# 为什么不用 tcpdump/ss：内核模块的 RX 钩子挂在 netfilter PRE_ROUTING
# (prio=-300)，命中外层四元组的报文会被 NF_STOLEN / 就地改写成内层包，IP 层
# 之上的任何观察点都看不到原始外层帧。AF_PACKET 挂在**设备层**
# （__netif_receive_skb_core 的 ptype 分发），早于 netfilter，所以模块把包
# "吞"掉之后这里仍然能看到链路层上的原始外层帧。
#
# 用法：
#   python3 capture_iwan.py --ifname veth-s --dport 6100 \
#           --count 1 --timeout 8 --out /tmp/cap [--sport 6100] [--l2-len 14]
#
# 写盘约定（"一个包一个文件"，文件可以直接喂给 interop_c decap）：
#   <out>.<i>       第 i 个包的 **UDP 载荷**（纯载荷 = 8B iWAN 帧头 + XOR 内层包）
#   <out>.<i>.hdr   第 i 个包的外层头**前 26 字节**：IPv4 20B + UDP sport/dport/len
#                   不含 UDP 校验和（第 27/28 字节）：veth/HW_CSUM 卸载下抓到的
#                   可能是部分和，比对无意义 —— 与 interop_c outer 的注释同口径。
#   i 从 0 开始，按抓到的先后顺序编号。
#
# stdout 是稳定的 KEY=value（每个包一段，段首 INDEX=<i>）：
#   CAPTURE_READY=1 / IFNAME / WANTED / TIMEOUT            启动握手（脚本等这一行）
#   INDEX / OUTER_IP_SRC / OUTER_IP_DST / OUTER_IP_PROTO / OUTER_IP_TOT_LEN /
#   OUTER_IP_TTL / OUTER_IP_ID / OUTER_IP_DF / OUTER_IP_CSUM /
#   OUTER_UDP_SPORT / OUTER_UDP_DPORT / OUTER_UDP_LEN /
#   PAYLOAD_BYTES / PAYLOAD_FILE / OUTER_HDR_FILE          每个包一段
#   CAPTURED / WANTED / SKIPPED / RESULT=ok|timeout         收尾
# 外层头的键名与 `interop_c outer` 完全一致（含 0x%04x 的校验和格式），
# 于是 interop_test.sh 可以逐字段直接做字符串比较。
#
# stderr 是人看的诊断（跳过的包、非 IPv4/UDP、分片、读设备错误）。
# 退出码：0 = 抓够；1 = 超时/数量不足（**抓不到是失败，不是挂住**）；2 = 用法
# 或环境错误（无 CAP_NET_RAW、网卡不存在、输出路径不可写）。

import argparse
import select
import socket
import struct
import sys
import time

ETH_P_IP = 0x0800
PACKET_OUTGOING = 4		# linux/if_packet.h
ARPHRD_ETHER = 1		# linux/if_arp.h
ARPHRD_LOOPBACK = 772
ARPHRD_NONE = 0xFFFE
ETH_HLEN = 14			# ARPHRD_ETHER / ARPHRD_LOOPBACK 的链路层头
HDR_PREFIX = 26			# IPv4 20B + UDP sport/dport/len（不含 UDP 校验和）
IP_DF = 0x4000
IP_MF = 0x2000
IP_OFFMASK = 0x1FFF


def emit(line):
	"""stdout 逐行 flush：脚本靠 CAPTURE_READY 行做握手，不能被缓冲吃掉。"""
	sys.stdout.write("%s\n" % line)
	sys.stdout.flush()


def warn(msg):
	sys.stderr.write("capture_iwan: %s\n" % msg)
	sys.stderr.flush()


def ipv4_csum_ok(hdr):
	"""IPv4 头校验和自洽（ones' complement 求和 == 0xFFFF）。"""
	s = 0
	for i in range(0, len(hdr) - 1, 2):
		s += (hdr[i] << 8) | hdr[i + 1]
	while s >> 16:
		s = (s & 0xFFFF) + (s >> 16)
	return s == 0xFFFF


def l2_len_for(buf, hatype, explicit):
	"""链路层头长度。

	SOCK_RAW 的 AF_PACKET **包含**链路层头（SOCK_DGRAM 才剥掉），所以要先
	跳过它才能看到 IPv4。这里按 sll_hatype 判定；--l2-len 可显式覆盖。
	"""
	if explicit is not None:
		return explicit
	if hatype in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
		return ETH_HLEN
	if hatype == ARPHRD_NONE:
		return 0
	# 兜底：首字节高 4 位是 4 说明拿到的已经是 IPv4 本身。
	if len(buf) > 0 and (buf[0] >> 4) == 4:
		return 0
	raise ValueError("未知链路类型 hatype=%d，请用 --l2-len 显式指定" % hatype)


def parse_frame(buf, l2):
	"""解析链路层之下的 IPv4 + UDP，返回字段字典（纯手写，不引第三方库）。"""
	if len(buf) < l2 + 20:
		raise ValueError("帧太短（%d 字节）" % len(buf))
	ip = l2
	vihl = buf[ip]
	if (vihl >> 4) != 4:
		raise ValueError("不是 IPv4（version=%d）" % (vihl >> 4))
	ihl = (vihl & 0x0F) * 4
	if ihl < 20 or len(buf) < ip + ihl:
		raise ValueError("IPv4 头长度非法（ihl=%d）" % ihl)

	tot_len = struct.unpack_from("!H", buf, ip + 2)[0]
	ip_id = struct.unpack_from("!H", buf, ip + 4)[0]
	frag = struct.unpack_from("!H", buf, ip + 6)[0]
	ttl = buf[ip + 8]
	proto = buf[ip + 9]
	ip_csum = struct.unpack_from("!H", buf, ip + 10)[0]
	src = socket.inet_ntoa(buf[ip + 12:ip + 16])
	dst = socket.inet_ntoa(buf[ip + 16:ip + 20])

	info = {
		"OUTER_IP_SRC": src,
		"OUTER_IP_DST": dst,
		"OUTER_IP_PROTO": proto,
		"OUTER_IP_TOT_LEN": tot_len,
		"OUTER_IP_TTL": ttl,
		"OUTER_IP_ID": ip_id,
		"OUTER_IP_DF": 1 if (frag & IP_DF) else 0,
		"OUTER_IP_FRAG": frag,
		"OUTER_IP_CSUM": ip_csum,
		"OUTER_IP_CSUM_OK": 1 if ipv4_csum_ok(buf[ip:ip + ihl]) else 0,
	}
	if proto != 17:
		info["reason"] = "非 UDP（proto=%d）" % proto
		return info
	if frag & IP_OFFMASK:
		info["reason"] = "非首片外层分片（frag_off=0x%04x），片内没有 UDP 头" % frag
		return info
	if frag & IP_MF:
		info["reason"] = "外层仍带 MF（本片不是完整数据报）"
		return info
	if len(buf) < ip + ihl + 8:
		raise ValueError("UDP 头不完整")

	sport, dport, ulen, ucsum = struct.unpack_from("!HHHH", buf, ip + ihl)
	payload_off = ip + ihl + 8
	# 内层数据的边界：UDP 长度 与 IP 总长 取小，再夹到实际抓到的字节数。
	udp_data = max(ulen - 8, 0)
	ip_end = len(buf)
	if tot_len >= ihl:
		ip_end = min(ip + tot_len, len(buf))
	payload_end = min(payload_off + udp_data, ip_end)
	if payload_end < payload_off:
		raise ValueError("UDP 长度 %d 与 IP 总长 %d 矛盾" % (ulen, tot_len))

	info.update({
		"OUTER_UDP_SPORT": sport,
		"OUTER_UDP_DPORT": dport,
		"OUTER_UDP_LEN": ulen,
		"OUTER_UDP_CSUM": ucsum,
		"payload": buf[payload_off:payload_end],
		"hdr": buf[ip:min(ip + HDR_PREFIX, len(buf))],
	})
	return info


def write_file(path, data):
	with open(path, "wb") as f:
		f.write(data)


def main(argv):
	ap = argparse.ArgumentParser(
		prog="capture_iwan.py",
		description="在设备层抓 iWAN 外层 UDP 报文，写出 UDP 载荷与外层头前缀",
		epilog="退出码：0 抓够 / 1 超时 / 2 用法或环境错误")
	ap.add_argument("--ifname", required=True, help="抓包网卡（在当前 netns 里）")
	ap.add_argument("--dport", required=True, type=int, help="外层 UDP 目的端口")
	ap.add_argument("--sport", type=int, default=None,
			help="外层 UDP 源端口（默认不过滤）")
	ap.add_argument("--count", type=int, default=1, help="要抓几个包（默认 1）")
	ap.add_argument("--timeout", type=float, default=8.0,
			help="总超时秒数（默认 8，超时退出码 1）")
	ap.add_argument("--out", required=True,
			help="输出前缀：载荷写 <out>.i，外层头前缀写 <out>.i.hdr")
	ap.add_argument("--l2-len", type=int, default=None,
			help="链路层头长度（默认按 hatype 自动判定）")
	args = ap.parse_args(argv)

	if args.count < 1:
		ap.error("--count 必须 >= 1")
	if args.timeout <= 0:
		ap.error("--timeout 必须 > 0")
	for name, v in (("--dport", args.dport), ("--sport", args.sport)):
		if v is not None and not (0 <= v <= 65535):
			ap.error("%s 超出 [0,65535]" % name)

	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
				  socket.htons(ETH_P_IP))
	except PermissionError:
		warn("没有 CAP_NET_RAW：请用 root（或 sudo）运行")
		return 2
	except OSError as e:
		warn("创建 AF_PACKET 套接字失败：%s" % e)
		return 2

	try:
		s.bind((args.ifname, 0))
	except OSError as e:
		warn("绑定网卡 %s 失败：%s（网卡在当前 netns 里存在吗？）"
		     % (args.ifname, e))
		return 2
	# 抓包不能因为用户态来不及收就丢帧（默认 rmem 只有 ~200KB）。
	try:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
	except OSError:
		pass

	# 握手行必须先于任何 recv 出现：调用脚本据此确定"已经在抓了"再发包。
	emit("CAPTURE_READY=1")
	emit("IFNAME=%s" % args.ifname)
	emit("WANTED=%d" % args.count)
	emit("TIMEOUT=%s" % args.timeout)

	captured = 0
	skipped = 0
	deadline = time.monotonic() + args.timeout

	while captured < args.count:
		remain = deadline - time.monotonic()
		if remain <= 0:
			break
		try:
			ready, _, _ = select.select([s], [], [], remain)
		except OSError as e:
			warn("select 失败：%s" % e)
			return 2
		if not ready:
			break
		try:
			buf, addr = s.recvfrom(65535)
		except OSError as e:
			warn("收包失败：%s" % e)
			return 2

		# sll_pkttype：只认"收到的"。本机发出的帧（例如对端解封后内核回的
		# ICMP 差错被模块重新封装）同样会被 AF_PACKET 看到，不能算抓到的包。
		pkttype = addr[2] if len(addr) > 2 else -1
		hatype = addr[3] if len(addr) > 3 else ARPHRD_NONE
		if pkttype == PACKET_OUTGOING:
			continue

		try:
			l2 = l2_len_for(buf, hatype, args.l2_len)
			info = parse_frame(buf, l2)
		except ValueError as e:
			warn("跳过一帧：%s" % e)
			skipped += 1
			continue

		if "reason" in info:
			warn("跳过一帧：%s" % info["reason"])
			skipped += 1
			continue
		if info["OUTER_UDP_DPORT"] != args.dport:
			skipped += 1	# 同网卡上的其它 UDP 流量是常态，不逐条刷屏
			continue
		if args.sport is not None and info["OUTER_UDP_SPORT"] != args.sport:
			skipped += 1
			continue

		idx = captured
		pl_path = "%s.%d" % (args.out, idx)
		hdr_path = "%s.%d.hdr" % (args.out, idx)
		try:
			write_file(pl_path, info["payload"])
			write_file(hdr_path, info["hdr"])
		except OSError as e:
			warn("写 %s 失败：%s" % (pl_path, e))
			return 2

		emit("INDEX=%d" % idx)
		for k in ("OUTER_IP_SRC", "OUTER_IP_DST", "OUTER_IP_PROTO",
			  "OUTER_IP_TOT_LEN", "OUTER_IP_TTL", "OUTER_IP_ID",
			  "OUTER_IP_DF"):
			emit("%s=%s" % (k, info[k]))
		emit("OUTER_IP_CSUM=0x%04x" % info["OUTER_IP_CSUM"])
		for k in ("OUTER_UDP_SPORT", "OUTER_UDP_DPORT", "OUTER_UDP_LEN"):
			emit("%s=%s" % (k, info[k]))
		emit("PAYLOAD_BYTES=%d" % len(info["payload"]))
		emit("PAYLOAD_FILE=%s" % pl_path)
		emit("OUTER_HDR_FILE=%s" % hdr_path)
		if not info["OUTER_IP_CSUM_OK"]:
			warn("第 %d 个包的外层 IP 头校验和不自洽" % idx)
		captured += 1

	emit("CAPTURED=%d" % captured)
	emit("SKIPPED=%d" % skipped)
	if captured < args.count:
		emit("RESULT=timeout")
		warn("超时 %gs：只抓到 %d/%d 个 dport=%d 的外层包"
		     % (args.timeout, captured, args.count, args.dport))
		return 1
	emit("RESULT=ok")
	return 0


if __name__ == "__main__":
	try:
		sys.exit(main(sys.argv[1:]))
	except KeyboardInterrupt:
		sys.exit(1)
