#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# capture_iwan.py -- capture iWAN outer packets at the device layer, write the UDP payloads to disk for cross-implementation comparison.
#
# Why not tcpdump/ss: the RX hook of the kernel module sits at netfilter PRE_ROUTING
# (prio=-300); packets matching the outer 4-tuple are NF_STOLEN / rewritten in place into inner packets, so
# no observation point above the IP layer can see the original outer frame. AF_PACKET sits at the **device layer**
# (ptype dispatch in __netif_receive_skb_core), earlier than netfilter, so after the module swallows the packet
# this point can still see the original outer frame on the link layer.
#
# Usage:
#   python3 capture_iwan.py --ifname veth-s --dport 6100 \
#           --count 1 --timeout 8 --out /tmp/cap [--sport 6100] [--l2-len 14]
#
# On-disk convention ("one packet per file", the files can be fed directly to interop_c decap):
#   <out>.<i>       **UDP payload** of packet i (pure payload = 8B iWAN frame header + XOR inner packet)
#   <out>.<i>.hdr   **first 26 bytes** of the outer header of packet i: IPv4 20B + UDP sport/dport/len
#                   excluding the UDP checksum (bytes 27/28): captured under veth/HW_CSUM offload it
#                   may be a partial sum, so comparing it is meaningless -- same stance as the comment in interop_c outer.
#   i starts at 0 and numbers packets in capture order.
#
# stdout is stable KEY=value (one section per packet, starting with INDEX=<i>):
#   CAPTURE_READY=1 / IFNAME / WANTED / TIMEOUT            startup handshake (the script waits for this line)
#   INDEX / OUTER_IP_SRC / OUTER_IP_DST / OUTER_IP_PROTO / OUTER_IP_TOT_LEN /
#   OUTER_IP_TTL / OUTER_IP_ID / OUTER_IP_DF / OUTER_IP_CSUM /
#   OUTER_UDP_SPORT / OUTER_UDP_DPORT / OUTER_UDP_LEN /
#   PAYLOAD_BYTES / PAYLOAD_FILE / OUTER_HDR_FILE          one section per packet
#   CAPTURED / WANTED / SKIPPED / RESULT=ok|timeout         epilogue
# The outer header key names are exactly the same as `interop_c outer` (including the 0x%04x checksum format),
# so interop_test.sh can compare them field by field as plain strings.
#
# stderr is diagnostics for humans (skipped packets, non-IPv4/UDP, fragments, device read errors).
# Exit codes: 0 = captured enough; 1 = timeout/too few (**failing to capture is a failure, not a hang**); 2 = usage
# or environment error (no CAP_NET_RAW, interface missing, output path not writable).

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
ETH_HLEN = 14			# link-layer header for ARPHRD_ETHER / ARPHRD_LOOPBACK
HDR_PREFIX = 26			# IPv4 20B + UDP sport/dport/len (excluding the UDP checksum)
IP_DF = 0x4000
IP_MF = 0x2000
IP_OFFMASK = 0x1FFF


def emit(line):
	"""stdout line-by-line flush: the script uses the CAPTURE_READY line as a handshake, so it must not be eaten by buffering."""
	sys.stdout.write("%s\n" % line)
	sys.stdout.flush()


def warn(msg):
	sys.stderr.write("capture_iwan: %s\n" % msg)
	sys.stderr.flush()


def ipv4_csum_ok(hdr):
	"""IPv4 header checksum is self-consistent (ones' complement sum == 0xFFFF)."""
	s = 0
	for i in range(0, len(hdr) - 1, 2):
		s += (hdr[i] << 8) | hdr[i + 1]
	while s >> 16:
		s = (s & 0xFFFF) + (s >> 16)
	return s == 0xFFFF


def l2_len_for(buf, hatype, explicit):
	"""Link-layer header length.

	SOCK_RAW AF_PACKET **includes** the link-layer header (only SOCK_DGRAM strips it), so it must be
	skipped first to see IPv4. Decided from sll_hatype here; --l2-len overrides it explicitly.
	"""
	if explicit is not None:
		return explicit
	if hatype in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
		return ETH_HLEN
	if hatype == ARPHRD_NONE:
		return 0
	# Fallback: if the top 4 bits of the first byte are 4, what we got is already IPv4 itself.
	if len(buf) > 0 and (buf[0] >> 4) == 4:
		return 0
	raise ValueError("unknown link type hatype=%d, use --l2-len to specify it explicitly" % hatype)


def parse_frame(buf, l2):
	"""Parse IPv4 + UDP below the link layer, return a field dict (hand-written, no third-party libraries)."""
	if len(buf) < l2 + 20:
		raise ValueError("frame too short (%d bytes)" % len(buf))
	ip = l2
	vihl = buf[ip]
	if (vihl >> 4) != 4:
		raise ValueError("not IPv4 (version=%d)" % (vihl >> 4))
	ihl = (vihl & 0x0F) * 4
	if ihl < 20 or len(buf) < ip + ihl:
		raise ValueError("invalid IPv4 header length (ihl=%d)" % ihl)

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
		info["reason"] = "not UDP (proto=%d)" % proto
		return info
	if frag & IP_OFFMASK:
		info["reason"] = "outer fragment that is not the first fragment (frag_off=0x%04x), no UDP header inside a fragment" % frag
		return info
	if frag & IP_MF:
		info["reason"] = "the outer packet still has MF set (this fragment is not a complete datagram)"
		return info
	if len(buf) < ip + ihl + 8:
		raise ValueError("incomplete UDP header")

	sport, dport, ulen, ucsum = struct.unpack_from("!HHHH", buf, ip + ihl)
	payload_off = ip + ihl + 8
	# Boundary of the inner data: take the smaller of the UDP length and the IP total length, then clamp to the bytes actually captured.
	udp_data = max(ulen - 8, 0)
	ip_end = len(buf)
	if tot_len >= ihl:
		ip_end = min(ip + tot_len, len(buf))
	payload_end = min(payload_off + udp_data, ip_end)
	if payload_end < payload_off:
		raise ValueError("UDP length %d contradicts IP total length %d" % (ulen, tot_len))

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
		description="capture iWAN outer UDP packets at the device layer, write out the UDP payload and the outer header prefix",
		epilog="exit codes: 0 captured enough / 1 timeout / 2 usage or environment error")
	ap.add_argument("--ifname", required=True, help="capture interface (in the current netns)")
	ap.add_argument("--dport", required=True, type=int, help="outer UDP destination port")
	ap.add_argument("--sport", type=int, default=None,
			help="outer UDP source port (no filtering by default)")
	ap.add_argument("--count", type=int, default=1, help="how many packets to capture (default 1)")
	ap.add_argument("--timeout", type=float, default=8.0,
			help="total timeout in seconds (default 8, timeout exits with code 1)")
	ap.add_argument("--out", required=True,
			help="output prefix: payload written to <out>.i, outer header prefix written to <out>.i.hdr")
	ap.add_argument("--l2-len", type=int, default=None,
			help="link-layer header length (default: determined automatically from hatype)")
	args = ap.parse_args(argv)

	if args.count < 1:
		ap.error("--count must be >= 1")
	if args.timeout <= 0:
		ap.error("--timeout must be > 0")
	for name, v in (("--dport", args.dport), ("--sport", args.sport)):
		if v is not None and not (0 <= v <= 65535):
			ap.error("%s out of range [0,65535]" % name)

	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
				  socket.htons(ETH_P_IP))
	except PermissionError:
		warn("no CAP_NET_RAW: run as root (or with sudo)")
		return 2
	except OSError as e:
		warn("failed to create AF_PACKET socket: %s" % e)
		return 2

	try:
		s.bind((args.ifname, 0))
	except OSError as e:
		warn("failed to bind interface %s: %s (does the interface exist in the current netns?)"
		     % (args.ifname, e))
		return 2
	# capture must not drop frames just because user space is slow to receive (the default rmem is only ~200KB).
	try:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
	except OSError:
		pass

	# The handshake line must appear before any recv: the calling script uses it to know that capturing is already running before sending packets.
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
			warn("select failed: %s" % e)
			return 2
		if not ready:
			break
		try:
			buf, addr = s.recvfrom(65535)
		except OSError as e:
			warn("recv failed: %s" % e)
			return 2

		# sll_pkttype: only accept "received" packets. Frames sent by this host (for example the kernel's
		# ICMP error reply after the peer decapsulated, re-encapsulated by the module) are also visible to AF_PACKET and must not count as captured packets.
		pkttype = addr[2] if len(addr) > 2 else -1
		hatype = addr[3] if len(addr) > 3 else ARPHRD_NONE
		if pkttype == PACKET_OUTGOING:
			continue

		try:
			l2 = l2_len_for(buf, hatype, args.l2_len)
			info = parse_frame(buf, l2)
		except ValueError as e:
			warn("skipping a frame: %s" % e)
			skipped += 1
			continue

		if "reason" in info:
			warn("skipping a frame: %s" % info["reason"])
			skipped += 1
			continue
		if info["OUTER_UDP_DPORT"] != args.dport:
			skipped += 1	# other UDP traffic on the same NIC is normal, do not flood the log per packet
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
			warn("failed to write %s: %s" % (pl_path, e))
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
			warn("outer IP header checksum of packet %d is not self-consistent" % idx)
		captured += 1

	emit("CAPTURED=%d" % captured)
	emit("SKIPPED=%d" % skipped)
	if captured < args.count:
		emit("RESULT=timeout")
		warn("timeout %gs: only captured %d/%d outer packets with dport=%d"
		     % (args.timeout, captured, args.count, args.dport))
		return 1
	emit("RESULT=ok")
	return 0


if __name__ == "__main__":
	try:
		sys.exit(main(sys.argv[1:]))
	except KeyboardInterrupt:
		sys.exit(1)
