"""Unit tests for sentinelflow.parser using hand-crafted Scapy packets.

Tests:
- Extraction of TCP, UDP, ICMP, and ARP packets
- Handling of non-IP packets (raw layer 2)
- Handling of malformed/empty packets without exceptions
- DataFrame column schemas and nullable types
- Chunked streaming and whole-PCAP parsing
"""

from pathlib import Path

import pandas as pd
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

from sentinelflow.parser import (
    PARSER_COLUMNS,
    extract_packet_dict,
    parse_packets,
    parse_pcap,
    stream_pcap,
)


def create_hand_built_packets() -> list[Packet]:
    """Construct a deterministic set of tiny hand-crafted packets across protocols."""
    pkts: list[Packet] = []

    # 1. TCP 3-way handshake + payload + teardown
    syn = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S", seq=100)
    syn.time = 1000.0
    pkts.append(syn)

    syn_ack = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="SA", seq=500, ack=101)
    syn_ack.time = 1000.01
    pkts.append(syn_ack)

    ack = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="A", seq=101, ack=501)
    ack.time = 1000.02
    pkts.append(ack)

    data = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="PA", seq=101, ack=501) / Raw(b"GET / HTTP/1.1\r\n\r\n")
    data.time = 1000.03
    pkts.append(data)

    fin = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="FA", seq=120, ack=501)
    fin.time = 1000.04
    pkts.append(fin)

    # 2. UDP DNS query
    udp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(b"\x12\x34\x01\x00")
    udp.time = 1001.0
    pkts.append(udp)

    # 3. ICMP Ping Request & Reply
    icmp_req = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0, id=1, seq=1)
    icmp_req.time = 1002.0
    pkts.append(icmp_req)

    icmp_rep = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, code=0, id=1, seq=1)
    icmp_rep.time = 1002.005
    pkts.append(icmp_rep)

    # 4. ARP Request & Reply
    arp_req = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="10.0.0.1", hwdst="00:00:00:00:00:00", pdst="10.0.0.2")
    arp_req.time = 1003.0
    pkts.append(arp_req)

    arp_rep = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / ARP(op=2, hwsrc="66:77:88:99:aa:bb", psrc="10.0.0.2", hwdst="00:11:22:33:44:55", pdst="10.0.0.1")
    arp_rep.time = 1003.001
    pkts.append(arp_rep)

    # 5. Non-IP raw Ethernet frame
    non_ip = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0x88CC) / Raw(b"LLDP_PAYLOAD")
    non_ip.time = 1004.0
    pkts.append(non_ip)

    return pkts


def test_parse_packets_schema_and_counts() -> None:
    """Verify parse_packets produces exact columns, dtypes, and correct row counts."""
    pkts = create_hand_built_packets()
    df = parse_packets(pkts)

    assert len(df) == len(pkts)
    assert list(df.columns) == PARSER_COLUMNS

    # Check timestamps are preserved
    assert float(df.iloc[0]["ts"]) == 1000.0
    assert float(df.iloc[1]["ts"]) == 1000.01

    # Check TCP flag extraction
    assert df.iloc[0]["tcp_flags"] == "S"
    assert df.iloc[1]["tcp_flags"] == "SA"
    assert df.iloc[2]["tcp_flags"] == "A"
    assert df.iloc[3]["tcp_flags"] == "PA"
    assert df.iloc[4]["tcp_flags"] == "FA"

    # Check UDP ports
    udp_row = df[df["proto"] == "UDP"].iloc[0]
    assert int(udp_row["src_port"]) == 53000
    assert int(udp_row["dst_port"]) == 53

    # Check ICMP
    icmp_rows = df[df["proto"] == "ICMP"]
    assert len(icmp_rows) == 2
    assert pd.isna(icmp_rows.iloc[0]["src_port"])

    # Check ARP
    arp_rows = df[df["proto"] == "ARP"]
    assert len(arp_rows) == 2
    assert int(arp_rows.iloc[0]["arp_op"]) == 1
    assert int(arp_rows.iloc[1]["arp_op"]) == 2
    assert arp_rows.iloc[0]["src_ip"] == "10.0.0.1"
    assert arp_rows.iloc[1]["src_ip"] == "10.0.0.2"

    # Check Non-IP frame
    non_ip_row = df[df["proto"] == "NON_IP"].iloc[0]
    assert non_ip_row["src_mac"] == "00:11:22:33:44:55"
    assert pd.isna(non_ip_row["src_ip"])


def test_malformed_packet_handling() -> None:
    """Verify that malformed or incomplete packets do not raise exceptions."""
    malformed = Packet(b"\x00\x01\x02\x03\x04")
    record = extract_packet_dict(malformed)

    assert record["length"] == 5
    assert record["proto"] in ("OTHER", "NON_IP")


def test_pcap_streaming_and_concatenation(tmp_path: Path) -> None:
    """Verify stream_pcap and parse_pcap on disk with chunked reading."""
    pkts = create_hand_built_packets()
    test_pcap = tmp_path / "test_sample.pcap"
    wrpcap(str(test_pcap), pkts)

    # Test chunked streaming with small chunk_size=3
    chunks = list(stream_pcap(test_pcap, chunk_size=3))
    assert len(chunks) == 4  # 11 packets / 3 = 3 chunks of 3 + 1 chunk of 2
    assert sum(len(c) for c in chunks) == len(pkts)

    # Test whole-file parse_pcap
    full_df = parse_pcap(test_pcap, chunk_size=4)
    assert len(full_df) == len(pkts)
    assert full_df["ts"].is_monotonic_increasing
