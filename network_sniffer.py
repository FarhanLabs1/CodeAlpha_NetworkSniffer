#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer

Captures live packets with Scapy and shows source/destination IPs,
protocol, ports, TCP flags and a payload preview.

Usage (run with admin/root rights, only on networks you own or may monitor):
    sudo python3 network_sniffer.py                      # sniff everything
    sudo python3 network_sniffer.py -c 50                # stop after 50 packets
    sudo python3 network_sniffer.py -f "tcp port 80"     # BPF filter
    sudo python3 network_sniffer.py -i eth0 -w out.pcap  # pick interface, save pcap

Install:  pip install scapy
Windows:  also install Npcap (https://npcap.com) and run terminal as Administrator.
"""

import argparse
import signal
import sys
from collections import Counter
from datetime import datetime

from scapy.all import (
    ARP, DNS, ICMP, IP, IPv6, Raw, TCP, UDP, Ether,
    sniff, wrpcap,
)

stats = Counter()
captured = []

TCP_FLAGS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
}


def decode_flags(flag_str):
    return "+".join(TCP_FLAGS.get(f, f) for f in str(flag_str)) or "-"


def payload_preview(raw_bytes, limit=64):
    """Return printable preview of payload (non-printable bytes shown as '.')."""
    data = raw_bytes[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    more = "..." if len(raw_bytes) > limit else ""
    return f"{text}{more}"


def service_name(port):
    return WELL_KNOWN_PORTS.get(port, "")


def process_packet(pkt):
    captured.append(pkt)
    ts = datetime.now().strftime("%H:%M:%S")
    lines = []

    # ---- Layer 2 ----
    if Ether in pkt:
        lines.append(f"  [L2] MAC  {pkt[Ether].src} -> {pkt[Ether].dst}")

    # ---- ARP ----
    if ARP in pkt:
        stats["ARP"] += 1
        op = "who-has" if pkt[ARP].op == 1 else "is-at"
        print(f"\n[{ts}] ARP {op}  {pkt[ARP].psrc} -> {pkt[ARP].pdst}")
        for l in lines:
            print(l)
        return

    # ---- Layer 3 ----
    if IP in pkt:
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, ip.ttl
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src, dst, ttl = ip.src, ip.dst, ip.hlim
    else:
        stats["OTHER"] += 1
        return

    proto = "OTHER"
    extra = ""

    # ---- Layer 4 ----
    if TCP in pkt:
        t = pkt[TCP]
        proto = "TCP"
        svc = service_name(t.dport) or service_name(t.sport)
        extra = (f"ports {t.sport} -> {t.dport}"
                 f"{' (' + svc + ')' if svc else ''} | "
                 f"flags {decode_flags(t.flags)} | seq {t.seq}")
    elif UDP in pkt:
        u = pkt[UDP]
        proto = "UDP"
        svc = service_name(u.dport) or service_name(u.sport)
        extra = (f"ports {u.sport} -> {u.dport}"
                 f"{' (' + svc + ')' if svc else ''} | len {u.len}")
        if DNS in pkt and pkt[DNS].qd is not None:
            proto = "DNS"
            extra += f" | query {pkt[DNS].qd.qname.decode(errors='ignore')}"
    elif ICMP in pkt:
        proto = "ICMP"
        extra = f"type {pkt[ICMP].type} code {pkt[ICMP].code}"

    stats[proto] += 1

    print(f"\n[{ts}] {proto:<5} {src} -> {dst} | TTL {ttl} | {len(pkt)} bytes")
    for l in lines:
        print(l)
    if extra:
        print(f"  [L4] {extra}")

    # ---- Payload ----
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
        print(f"  [PAYLOAD] {len(raw)} bytes: {payload_preview(raw)}")
        # Educational note: plaintext protocols expose data
        if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            if raw.startswith((b"GET", b"POST", b"HTTP")):
                first_line = raw.split(b"\r\n")[0].decode(errors="ignore")
                print(f"  [HTTP] {first_line}")


def print_summary(*_):
    print("\n" + "=" * 50)
    print("CAPTURE SUMMARY")
    print("=" * 50)
    total = sum(stats.values())
    print(f"Total packets: {total}")
    for proto, count in stats.most_common():
        print(f"  {proto:<6} {count:>5}  ({count / total * 100:.1f}%)")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Scapy)")
    parser.add_argument("-i", "--iface", help="Network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp port 80" or "icmp"')
    parser.add_argument("-w", "--write", help="Save capture to a .pcap file")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, print_summary)

    print("[*] Starting sniffer... press Ctrl+C to stop")
    print(f"[*] Interface: {args.iface or 'default'} | Filter: {args.filter or 'none'}")

    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        sys.exit("[!] Permission denied. Run as root/Administrator.")
    except OSError as e:
        sys.exit(f"[!] Capture error: {e}")

    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"\n[+] Saved {len(captured)} packets to {args.write}")

    print_summary()


if __name__ == "__main__":
    main()
