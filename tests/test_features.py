"""Unit tests for sentinelflow.features using hand-crafted packet lists and DataFrames.

Validates:
- Windowed statistical feature calculations (pps, bps, syn_count, protocol shares, etc.)
- Bidirectional flow aggregation and state classification (completed, reset, half_open)
- Ground-truth label interval joining
"""

import pandas as pd
import pytest

from sentinelflow.features import (
    WINDOW_FEATURE_COLUMNS,
    extract_bidirectional_flows,
    extract_window_features,
    label_windows,
)


def test_window_features_exact_math() -> None:
    """Verify windowed feature extraction with exact hand-calculated assertions."""
    # Build 10 packets spanning [100.0, 104.5] for src_ip="10.0.0.1"
    packets = [
        # 3 pure SYNs to distinct ports 80, 443, 8080
        {"ts": 100.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 100, "tcp_flags": "S", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        {"ts": 100.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1001, "dst_port": 443, "proto": "TCP", "length": 100, "tcp_flags": "S", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        {"ts": 101.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1002, "dst_port": 8080, "proto": "TCP", "length": 100, "tcp_flags": "S", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        # 1 SYN-ACK packet
        {"ts": 101.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 80, "dst_port": 1000, "proto": "TCP", "length": 100, "tcp_flags": "SA", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        # 2 pure ACKs
        {"ts": 102.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 100, "tcp_flags": "A", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        {"ts": 102.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 100, "tcp_flags": "A", "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        # 2 UDP packets to port 53
        {"ts": 103.0, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 4000, "dst_port": 53, "proto": "UDP", "length": 100, "tcp_flags": None, "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        {"ts": 103.5, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "src_port": 4001, "dst_port": 53, "proto": "UDP", "length": 100, "tcp_flags": None, "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        # 1 ICMP packet
        {"ts": 104.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": None, "dst_port": None, "proto": "ICMP", "length": 100, "tcp_flags": None, "arp_op": None, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
        # 1 ARP reply
        {"ts": 104.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": None, "dst_port": None, "proto": "ARP", "length": 100, "tcp_flags": None, "arp_op": 2, "src_mac": "00:aa:bb:cc:dd:ee", "dst_mac": "00:11:22:33:44:55"},
    ]
    df = pd.DataFrame(packets)
    features_df = extract_window_features(df, window_size=5.0)

    assert len(features_df) == 1
    row = features_df.iloc[0]

    # 1. Rate & Volume assertions
    assert row["packet_count"] == 10
    assert row["pps"] == 10 / 5.0  # 2.0 pps
    assert row["bps"] == (10 * 100 * 8.0) / 5.0  # 1600.0 bps
    assert row["bytes_per_sec"] == 1000.0 / 5.0  # 200.0 B/s

    # 2. Cardinality
    assert row["unique_dst_ips"] == 2  # 10.0.0.2 and 8.8.8.8
    assert row["unique_dst_ports"] == 5  # 80, 443, 8080, 1000, 53

    # 3. Connection & Flag Dynamics
    assert row["syn_count"] == 3
    # synack_ratio = syn_count / (synack_count + 1) = 3 / (1 + 1) = 1.5
    assert row["synack_ratio"] == 1.5
    # syn_without_ack_fraction = 2 uncompleted SYNs out of 3 = 2/3 (ports 443 and 8080 unanswered)
    assert abs(row["syn_without_ack_fraction"] - (2.0 / 3.0)) < 1e-4

    # 4. Protocol Shares
    assert row["tcp_share"] == 0.6  # 6 / 10
    assert row["udp_share"] == 0.2  # 2 / 10
    assert row["icmp_share"] == 0.1  # 1 / 10
    assert row["arp_share"] == 0.1  # 1 / 10

    # 5. ARP & MAC metrics
    assert row["arp_reply_count"] == 1
    assert row["mac_binding_changes"] == 0


def test_bidirectional_flows_states() -> None:
    """Verify bidirectional flow extraction and state classification."""
    packets = [
        # Flow 1: Completed TCP connection (handshake + teardown)
        {"ts": 10.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 54, "tcp_flags": "S"},
        {"ts": 10.01, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 1000, "proto": "TCP", "length": 54, "tcp_flags": "SA"},
        {"ts": 10.02, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 54, "tcp_flags": "A"},
        {"ts": 10.05, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000, "dst_port": 80, "proto": "TCP", "length": 54, "tcp_flags": "FA"},
        {"ts": 10.06, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 1000, "proto": "TCP", "length": 54, "tcp_flags": "FA"},

        # Flow 2: Reset TCP connection (Port scan probe rejected with RST)
        {"ts": 20.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 2000, "dst_port": 22, "proto": "TCP", "length": 54, "tcp_flags": "S"},
        {"ts": 20.01, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 22, "dst_port": 2000, "proto": "TCP", "length": 54, "tcp_flags": "RA"},

        # Flow 3: Half-open connection (SYN without response)
        {"ts": 30.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 3000, "dst_port": 443, "proto": "TCP", "length": 54, "tcp_flags": "S"},
    ]
    df = pd.DataFrame(packets)
    flows = extract_bidirectional_flows(df)

    assert len(flows) == 3

    # Check Flow 1 (completed)
    f1 = flows[flows["dst_port"] == 80].iloc[0]
    assert f1["state"] == "completed"
    assert f1["fwd_packets"] == 3
    assert f1["bwd_packets"] == 2
    assert f1["total_packets"] == 5

    # Check Flow 2 (reset)
    f2 = flows[flows["dst_port"] == 22].iloc[0]
    assert f2["state"] == "reset"
    assert f2["fwd_packets"] == 1
    assert f2["bwd_packets"] == 1

    # Check Flow 3 (half_open)
    f3 = flows[flows["dst_port"] == 443].iloc[0]
    assert f3["state"] == "half_open"
    assert f3["fwd_packets"] == 1
    assert f3["bwd_packets"] == 0

    # Flow 4: Same-IP loopback / local flow
    same_ip_packets = [
        {"ts": 40.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.1", "src_port": 5000, "dst_port": 80, "proto": "TCP", "length": 60, "tcp_flags": "S"},
        {"ts": 40.01, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 5000, "proto": "TCP", "length": 60, "tcp_flags": "SA"},
    ]
    same_ip_flows = extract_bidirectional_flows(pd.DataFrame(same_ip_packets))
    assert len(same_ip_flows) == 1
    assert same_ip_flows.iloc[0]["fwd_packets"] == 1
    assert same_ip_flows.iloc[0]["bwd_packets"] == 1
    assert same_ip_flows.iloc[0]["total_packets"] == 2


def test_label_windows_joining() -> None:
    """Verify ground-truth attack interval matching to aggregated windows."""
    windows_data = [
        {"win_start": 100.0, "win_end": 105.0, "src_ip": "192.168.1.99"},  # before attack
        {"win_start": 120.0, "win_end": 125.0, "src_ip": "192.168.1.99"},  # during attack
        {"win_start": 120.0, "win_end": 125.0, "src_ip": "192.168.1.10"},  # benign host during attack
    ]
    win_df = pd.DataFrame(windows_data)

    labels_data = [
        {"start_ts": 115.0, "end_ts": 130.0, "src_ip": "192.168.1.99", "dst_ip": "192.168.1.20", "attack_type": "port_scan"}
    ]
    lbl_df = pd.DataFrame(labels_data)

    labeled = label_windows(win_df, lbl_df)

    assert len(labeled) == 3
    # Window 0: before attack -> benign
    assert not labeled.iloc[0]["is_malicious"]
    assert labeled.iloc[0]["attack_type"] == "benign"

    # Window 1: during attack and matches attacker IP -> malicious port_scan
    assert labeled.iloc[1]["is_malicious"]
    assert labeled.iloc[1]["attack_type"] == "port_scan"

    # Window 2: during attack time but benign host IP -> benign
    assert not labeled.iloc[2]["is_malicious"]
    assert labeled.iloc[2]["attack_type"] == "benign"


def test_handshake_successful() -> None:
    """Verify that a successful 3-way handshake is correctly correlated across endpoints.

    Client A initiates SYN, Server B responds with SYN-ACK (residing in B's traffic),
    and Client A completes with ACK. Client A must NOT flag the handshake as incomplete
    merely because B's SYN-ACK appears under a different source IP.
    """
    packets = [
        # Client A sends SYN to Server B
        {"ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "proto": "TCP", "length": 60, "tcp_flags": "S"},
        # Server B responds with SYN-ACK to Client A (src_ip is Server B!)
        {"ts": 1.02, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 5000, "proto": "TCP", "length": 60, "tcp_flags": "SA"},
        # Client A completes with ACK
        {"ts": 1.03, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "proto": "TCP", "length": 60, "tcp_flags": "A"},
    ]
    df = pd.DataFrame(packets)
    windows = extract_window_features(df, window_size=5.0)

    # Client A's window
    client_win = windows[windows["src_ip"] == "10.0.0.1"].iloc[0]
    assert client_win["syn_count"] == 1
    # 1 SYN matched 1 received SYN-ACK -> synack_ratio = 1 / (1 + 1) = 0.5
    assert client_win["synack_ratio"] == 0.5
    # Handshake successfully completed with ACK -> 0.0 uncompleted fraction
    assert client_win["syn_without_ack_fraction"] == 0.0


def test_handshake_unanswered_syn() -> None:
    """Verify that an unanswered SYN (SYN flood / stealth scan) is correctly flagged."""
    packets = [
        # Attacker sends SYN to closed/unresponsive port
        {"ts": 1.0, "src_ip": "10.0.0.99", "dst_ip": "10.0.0.2", "src_port": 6000, "dst_port": 9999, "proto": "TCP", "length": 60, "tcp_flags": "S"},
    ]
    df = pd.DataFrame(packets)
    windows = extract_window_features(df, window_size=5.0)

    attacker_win = windows[windows["src_ip"] == "10.0.0.99"].iloc[0]
    assert attacker_win["syn_count"] == 1
    # 0 SYN-ACKs received -> synack_ratio = 1 / (0 + 1) = 1.0
    assert attacker_win["synack_ratio"] == 1.0
    # Unanswered SYN -> 1.0 (100% without ACK)
    assert attacker_win["syn_without_ack_fraction"] == 1.0


def test_handshake_reverse_traffic() -> None:
    """Verify that responder/server traffic and reverse connection initiations are handled accurately."""
    packets = [
        # 1. Inbound connection to Server B (10.0.0.2:80)
        {"ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "proto": "TCP", "length": 60, "tcp_flags": "S"},
        {"ts": 1.01, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 5000, "proto": "TCP", "length": 60, "tcp_flags": "SA"},
        {"ts": 1.02, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "proto": "TCP", "length": 60, "tcp_flags": "A"},

        # 2. Outbound reverse connection initiated by Server B (10.0.0.2:2000 -> 10.0.0.1:4000)
        {"ts": 2.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 2000, "dst_port": 4000, "proto": "TCP", "length": 60, "tcp_flags": "S"},
        {"ts": 2.01, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 4000, "dst_port": 2000, "proto": "TCP", "length": 60, "tcp_flags": "SA"},
        {"ts": 2.02, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 2000, "dst_port": 4000, "proto": "TCP", "length": 60, "tcp_flags": "A"},
    ]
    df = pd.DataFrame(packets)
    windows = extract_window_features(df, window_size=5.0)

    server_win = windows[windows["src_ip"] == "10.0.0.2"].iloc[0]
    # Server B initiated 1 outbound SYN (to port 4000)
    assert server_win["syn_count"] == 1
    # Server B sent 1 SYN-ACK (for inbound port 80) and received 1 SYN-ACK (for outbound port 4000) -> synack_count = 2
    # synack_ratio = 1 / (2 + 1) = 1/3
    assert abs(server_win["synack_ratio"] - (1.0 / 3.0)) < 1e-4
    # The outbound connection completed with ACK -> 0.0 uncompleted fraction
    assert server_win["syn_without_ack_fraction"] == 0.0
