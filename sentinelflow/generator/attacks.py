"""Synthetic attack traffic generator modules.

Implements realistic synthetic attack scenarios designed to test signature rules,
Isolation Forest anomaly detection, and hybrid fusion logic:
- S2: Port Scanning (Fast SYN scan of 1000 ports, Slow scan evasion)
- S3: Denial of Service (SYN flood with random ports, Spoofed source SYN flood, UDP flood)
      along with victim host telemetry degradation simulation
- S4: SSH Brute Force authentication & Layer-2 ARP Spoofing / Cache Poisoning
- S5: Ambiguous traffic (Benign enterprise backup / flash crowd, Distributed slow scan)

All packets are generated in memory and annotated with precise ground-truth AttackLabel records.
"""

import logging
import random
from typing import List, Tuple

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from sentinelflow.generator.models import AttackLabel, GeneratorConfig, NetworkHost, VictimMetric

logger = logging.getLogger(__name__)


def generate_fast_syn_port_scan(
    attacker_ip: str,
    attacker_mac: str,
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    port_count: int = 1000,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a rapid TCP SYN port scan (e.g., `nmap -sS -T4 -p 1-1000`).

    Real-World Behavior:
    An adversary transmits a high-frequency sequence of TCP SYN packets across
    ports 1 through 1000 to discover active services.
    - Closed ports: Victim kernel responds with TCP RST-ACK.
    - Open ports (e.g. 22, 80, 443, 8080): Victim kernel responds with TCP SYN-ACK.
      The attacker immediately transmits a TCP RST to tear down the connection
      without completing the 3-way handshake (classic half-open stealth scan).

    Args:
        attacker_ip: Scanning IP address.
        attacker_mac: Attacker Ethernet MAC address.
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        start_time: Scan initiation epoch timestamp.
        port_count: Number of ports scanned (default: 1000).
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    open_ports = {22, 80, 443, 8080}
    t = start_time
    inter_probe_delay = 0.015  # ~66 probes per second (~15s scan duration for 1000 ports)
    sport_base = rng.randint(40000, 50000)

    for port in range(1, port_count + 1):
        sport = sport_base + (port % 10000)
        c_seq = rng.randint(100000, 9000000)

        # SYN Probe
        syn_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=port, flags="S", seq=c_seq)
        )
        syn_pkt.time = t
        packets.append(syn_pkt)

        rtt = rng.uniform(0.001, 0.003)
        if port in open_ports:
            # Open port: Victim responds SYN-ACK
            s_seq = rng.randint(100000, 9000000)
            syn_ack = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / TCP(sport=port, dport=sport, flags="SA", seq=s_seq, ack=c_seq + 1)
            )
            syn_ack.time = t + rtt
            packets.append(syn_ack)

            # Attacker sends RST to tear down half-open socket
            rst = (
                Ether(src=attacker_mac, dst=victim_mac)
                / IP(src=attacker_ip, dst=victim_ip)
                / TCP(sport=sport, dport=port, flags="R", seq=c_seq + 1)
            )
            rst.time = t + rtt + 0.001
            packets.append(rst)
        else:
            # Closed port: Victim responds RST-ACK
            rst_ack = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=c_seq + 1)
            )
            rst_ack.time = t + rtt
            packets.append(rst_ack)

        t += inter_probe_delay

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="port_scan",
    )
    return packets, label


def generate_slow_port_scan(
    attacker_ip: str,
    attacker_mac: str,
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    port_count: int = 80,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a stealthy, low-and-slow port scan (e.g. `nmap -sS -T1 --scan-delay 3s`).

    Real-World Behavior:
    A sophisticated attacker evades short-term time-window rate thresholds by pacing
    probes 2 to 4 seconds apart. While a standard sliding window of 10s will only see
    2-5 probes (below typical scan thresholds), the persistent long-term behavior
    manifests as anomalous baseline deviation.

    Args:
        attacker_ip: Scanning IP address.
        attacker_mac: Attacker Ethernet MAC address.
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        start_time: Scan initiation epoch timestamp.
        port_count: Number of scanned target ports (default: 80).
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    open_ports = {22, 80, 443}
    t = start_time
    target_ports = rng.sample(range(1, 1024), port_count)

    for port in target_ports:
        sport = rng.randint(49152, 65535)
        c_seq = rng.randint(100000, 9000000)

        syn = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=port, flags="S", seq=c_seq)
        )
        syn.time = t
        packets.append(syn)

        rtt = rng.uniform(0.001, 0.003)
        if port in open_ports:
            s_seq = rng.randint(100000, 9000000)
            syn_ack = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / TCP(sport=port, dport=sport, flags="SA", seq=s_seq, ack=c_seq + 1)
            )
            syn_ack.time = t + rtt
            packets.append(syn_ack)

            rst = (
                Ether(src=attacker_mac, dst=victim_mac)
                / IP(src=attacker_ip, dst=victim_ip)
                / TCP(sport=sport, dport=port, flags="R", seq=c_seq + 1)
            )
            rst.time = t + rtt + 0.001
            packets.append(rst)
        else:
            rst_ack = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=c_seq + 1)
            )
            rst_ack.time = t + rtt
            packets.append(rst_ack)

        t += rng.uniform(2.5, 4.5)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="slow_scan",
    )
    return packets, label


def generate_syn_flood(
    attacker_ip: str,
    attacker_mac: str,
    victim_ip: str,
    victim_mac: str,
    target_port: int,
    start_time: float,
    duration: float = 30.0,
    rate_pps: float = 120.0,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a single-source TCP SYN flood attack (e.g. `hping3 -S --flood`).

    Real-World Behavior:
    An attacker generates a rapid stream of TCP SYN packets from randomised high
    ephemeral source ports targeting an active service port (e.g., HTTP/80).
    The attacker ignores SYN-ACK replies and does not complete the 3-way handshake,
    filling the operating system's TCP SYN backlog queue and denying service to legitimate clients.

    Args:
        attacker_ip: Attacking source IP address.
        attacker_mac: Attacking source MAC address.
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        target_port: Destination port under attack.
        start_time: Attack initiation epoch timestamp.
        duration: Attack active duration in seconds (default: 30.0).
        rate_pps: SYN packets transmitted per second (default: 120.0).
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    total_packets = int(duration * rate_pps)
    inter_packet_delay = 1.0 / rate_pps
    t = start_time

    for _ in range(total_packets):
        sport = rng.randint(1024, 65535)
        seq = rng.randint(100000, 9000000)

        syn_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=target_port, flags="S", seq=seq)
        )
        syn_pkt.time = t
        packets.append(syn_pkt)

        # Victim kernel responds with SYN-ACK for a fraction of requests before backlog exhaustion
        if rng.random() < 0.15:
            syn_ack = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / TCP(sport=target_port, dport=sport, flags="SA", seq=rng.randint(10000, 90000), ack=seq + 1)
            )
            syn_ack.time = t + rng.uniform(0.001, 0.005)
            packets.append(syn_ack)

        t += inter_packet_delay + rng.uniform(-0.001, 0.001)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="syn_flood",
    )
    return packets, label


def generate_syn_flood_spoofed(
    victim_ip: str,
    victim_mac: str,
    gateway_mac: str,
    target_port: int,
    start_time: float,
    duration: float = 30.0,
    rate_pps: float = 120.0,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a distributed / raw-socket spoofed SYN flood (e.g. `hping3 --rand-source -S`).

    Real-World Behavior:
    An attacker transmits SYN packets with forged, pseudo-randomized source IP addresses
    routed through the gateway. Because source IPs vary continuously, simple single-source
    rate limiters fail to flag a single offensive IP, requiring anomaly models or
    unbalanced SYN/ACK global ratio detection.

    Args:
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        gateway_mac: Default gateway MAC routing external spoofed traffic.
        target_port: Target TCP port.
        start_time: Attack initiation epoch timestamp.
        duration: Attack active duration in seconds.
        rate_pps: Target packet transmission rate per second.
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    total_packets = int(duration * rate_pps)
    inter_packet_delay = 1.0 / rate_pps
    t = start_time

    for _ in range(total_packets):
        # Generate arbitrary external routable IPs
        spoofed_src = f"{rng.randint(11, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        sport = rng.randint(1024, 65535)
        seq = rng.randint(100000, 9000000)

        syn_pkt = (
            Ether(src=gateway_mac, dst=victim_mac)
            / IP(src=spoofed_src, dst=victim_ip)
            / TCP(sport=sport, dport=target_port, flags="S", seq=seq)
        )
        syn_pkt.time = t
        packets.append(syn_pkt)

        # Victim attempts SYN-ACK towards spoofed external IP
        if rng.random() < 0.12:
            syn_ack = (
                Ether(src=victim_mac, dst=gateway_mac)
                / IP(src=victim_ip, dst=spoofed_src)
                / TCP(sport=target_port, dport=sport, flags="SA", seq=rng.randint(10000, 90000), ack=seq + 1)
            )
            syn_ack.time = t + rng.uniform(0.001, 0.004)
            packets.append(syn_ack)

        t += inter_packet_delay + rng.uniform(-0.001, 0.001)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip="spoofed_various",
        dst_ip=victim_ip,
        attack_type="syn_flood_spoofed",
    )
    return packets, label


def generate_udp_flood(
    attacker_ip: str,
    attacker_mac: str,
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    duration: float = 25.0,
    rate_pps: float = 140.0,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a high-bandwidth UDP flood attack (e.g. `hping3 --udp --flood`).

    Real-World Behavior:
    Attacker floods target IP across random high UDP ports with large binary payloads.
    Since UDP is connectionless and requires no handshakes, the operating system kernel
    is burdened with protocol stack traversal and generating ICMP Destination Unreachable
    (Port Unreachable) error packets.

    Args:
        attacker_ip: Attacking source IP.
        attacker_mac: Attacking source MAC.
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        start_time: Start timestamp.
        duration: Flood duration in seconds.
        rate_pps: Packet rate per second.
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    total_packets = int(duration * rate_pps)
    inter_packet_delay = 1.0 / rate_pps
    t = start_time

    for _ in range(total_packets):
        sport = rng.randint(1024, 65535)
        dport = rng.randint(10000, 65000)
        payload = bytes([rng.randint(0, 255) for _ in range(rng.randint(512, 1024))])

        udp_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / UDP(sport=sport, dport=dport)
            / Raw(load=payload)
        )
        udp_pkt.time = t
        packets.append(udp_pkt)

        # Periodic ICMP Port Unreachable from victim kernel (rate-limited by kernel)
        if rng.random() < 0.05:
            icmp_unreach = (
                Ether(src=victim_mac, dst=attacker_mac)
                / IP(src=victim_ip, dst=attacker_ip)
                / ICMP(type=3, code=3)
            )
            icmp_unreach.time = t + rng.uniform(0.001, 0.004)
            packets.append(icmp_unreach)

        t += inter_packet_delay + rng.uniform(-0.001, 0.001)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="udp_flood",
    )
    return packets, label


def generate_victim_telemetry(
    attack_start_time: float,
    attack_duration: float,
    total_duration: float,
    baseline_pps: float = 8.0,
    peak_pps: float = 260.0,
    rng: random.Random = None,
) -> List[VictimMetric]:
    """Generate simulated second-by-second victim telemetry metrics during DoS attack.

    Real-World Behavior:
    Records operational service degradation during a denial-of-service attack:
    - Pre-attack: Normal baseline SYN/ACK ratio (~0.98), low latency (~12ms), low pps (~8).
    - During flood: SYN/ACK ratio collapses (<0.20) as connection backlog fills,
      legitimate client response latency surges (500-1200ms), and pps spikes dramatically.
    - Post-attack: Gradual recovery back to normal baseline metrics.

    Args:
        attack_start_time: Timestamp when flood starts.
        attack_duration: Duration of flood in seconds.
        total_duration: Total simulation time.
        baseline_pps: Average normal background PPS.
        peak_pps: Peak attack PPS during flood.
        rng: Deterministic random generator.

    Returns:
        List of VictimMetric instances per second.
    """
    if rng is None:
        rng = random.Random(42)

    metrics: List[VictimMetric] = []
    attack_end_time = attack_start_time + attack_duration

    for sec in range(int(total_duration)):
        t = float(sec)

        if t < attack_start_time:
            # Baseline normal state
            syn_ack = rng.uniform(0.95, 1.0)
            delay = rng.uniform(8.0, 15.0)
            pps = baseline_pps + rng.uniform(-2.0, 3.0)
        elif attack_start_time <= t <= attack_end_time:
            # Under severe attack
            syn_ack = rng.uniform(0.12, 0.28)
            delay = rng.uniform(600.0, 1400.0)
            pps = peak_pps + rng.uniform(-25.0, 35.0)
        else:
            # Recovery period
            recovery_delta = t - attack_end_time
            if recovery_delta < 15.0:
                syn_ack = 0.3 + (recovery_delta / 15.0) * 0.65 + rng.uniform(-0.05, 0.05)
                delay = 800.0 - (recovery_delta / 15.0) * 780.0 + rng.uniform(-20.0, 20.0)
                pps = peak_pps * (1.0 - recovery_delta / 15.0) + baseline_pps
            else:
                syn_ack = rng.uniform(0.94, 0.99)
                delay = rng.uniform(9.0, 18.0)
                pps = baseline_pps + rng.uniform(-2.0, 3.0)

        metrics.append(
            VictimMetric(
                timestamp=t,
                syn_ack_ratio=max(0.0, min(1.0, syn_ack)),
                response_delay_ms=max(1.0, delay),
                pps=max(0.0, pps),
            )
        )

    return metrics


def generate_ssh_brute_force(
    attacker_ip: str,
    attacker_mac: str,
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    attempts: int = 40,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate an SSH dictionary password guessing attack (e.g., `hydra -l root -P dict.txt`).

    Real-World Behavior:
    An adversary attempts automated password authentication against TCP/22 in rapid succession:
    1. Complete 3-way handshake (SYN, SYN-ACK, ACK).
    2. Exchange protocol banners (SSH-2.0).
    3. Transmit SSH_MSG_USERAUTH_REQUEST packet containing guessed credentials.
    4. Victim server responds with SSH_MSG_USERAUTH_FAILURE.
    5. Connection is promptly reset or closed with FIN, and the attacker repeats
       the sequence dozens of times within a short time window.

    Args:
        attacker_ip: Attacker IP.
        attacker_mac: Attacker MAC.
        victim_ip: Victim SSH server IP.
        victim_mac: Victim MAC.
        start_time: Epoch start timestamp.
        attempts: Number of authentication attempts (default: 40).
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    t = start_time

    for i in range(attempts):
        sport = rng.randint(49152, 65535)
        c_seq = rng.randint(100000, 9000000)
        s_seq = rng.randint(100000, 9000000)
        rtt = rng.uniform(0.001, 0.004)

        # 1. Handshake
        syn = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=22, flags="S", seq=c_seq)
        )
        syn.time = t
        packets.append(syn)
        c_seq += 1

        t += rtt
        syn_ack = (
            Ether(src=victim_mac, dst=attacker_mac)
            / IP(src=victim_ip, dst=attacker_ip)
            / TCP(sport=22, dport=sport, flags="SA", seq=s_seq, ack=c_seq)
        )
        syn_ack.time = t
        packets.append(syn_ack)
        s_seq += 1

        t += rtt
        ack = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=22, flags="A", seq=c_seq, ack=s_seq)
        )
        ack.time = t
        packets.append(ack)

        # 2. SSH Banner Exchange
        t += 0.002
        c_banner = b"SSH-2.0-libssh_0.9.6\r\n"
        c_banner_pkt = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=22, flags="PA", seq=c_seq, ack=s_seq)
            / Raw(load=c_banner)
        )
        c_banner_pkt.time = t
        packets.append(c_banner_pkt)
        c_seq += len(c_banner)

        s_banner = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        s_banner_pkt = (
            Ether(src=victim_mac, dst=attacker_mac)
            / IP(src=victim_ip, dst=attacker_ip)
            / TCP(sport=22, dport=sport, flags="PA", seq=s_seq, ack=c_seq)
            / Raw(load=s_banner)
        )
        s_banner_pkt.time = t + rtt
        packets.append(s_banner_pkt)
        s_seq += len(s_banner)

        # 3. Failed Auth Exchange (small encrypted packet)
        t += 0.005
        auth_req_payload = bytes([rng.randint(0, 255) for _ in range(rng.randint(240, 380))])
        auth_req = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=22, flags="PA", seq=c_seq, ack=s_seq)
            / Raw(load=auth_req_payload)
        )
        auth_req.time = t
        packets.append(auth_req)
        c_seq += len(auth_req_payload)

        auth_fail_payload = bytes([rng.randint(0, 255) for _ in range(rng.randint(80, 160))])
        auth_fail = (
            Ether(src=victim_mac, dst=attacker_mac)
            / IP(src=victim_ip, dst=attacker_ip)
            / TCP(sport=22, dport=sport, flags="PA", seq=s_seq, ack=c_seq)
            / Raw(load=auth_fail_payload)
        )
        auth_fail.time = t + rtt
        packets.append(auth_fail)
        s_seq += len(auth_fail_payload)

        # 4. Immediate Teardown / RST
        rst = (
            Ether(src=attacker_mac, dst=victim_mac)
            / IP(src=attacker_ip, dst=victim_ip)
            / TCP(sport=sport, dport=22, flags="R", seq=c_seq)
        )
        rst.time = t + rtt + 0.001
        packets.append(rst)

        # Inter-attempt delay (e.g. 0.4s to 1.2s)
        t += rng.uniform(0.4, 1.2)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="ssh_brute_force",
    )
    return packets, label


def generate_arp_spoofing(
    attacker_ip: str,
    attacker_mac: str,
    gateway_ip: str,
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    duration: float = 60.0,
    interval_seconds: float = 1.5,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate ARP cache poisoning / Adversary-in-the-Middle attack (e.g. `arpspoof`).

    Real-World Behavior:
    An attacker broadcasts or unicasts unsolicited gratuitous ARP replies (opcode 2: is-at)
    to a victim workstation or server, claiming that the gateway's IP address (192.168.1.1)
    is associated with the attacker's physical MAC address. This poisons the victim's ARP cache
    and diverts outbound LAN/WAN traffic through the attacker machine.

    Args:
        attacker_ip: Attacker's own IP.
        attacker_mac: Attacker's physical MAC address (used in false claim).
        gateway_ip: IP address being spoofed (e.g. default gateway).
        victim_ip: Target workstation IP whose ARP cache is being poisoned.
        victim_mac: Target workstation MAC.
        start_time: Attack initiation epoch timestamp.
        duration: Active poisoning duration in seconds (default: 60.0).
        interval_seconds: Delay between periodic unsolicited ARP replies.
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    t = start_time
    end_time = start_time + duration

    # 1. Attacker LAN presence announcement (RFC 5227 gratuitous ARP):
    # Binds attacker_mac to attacker_ip on the network switch/inspection tables
    announcement = (
        Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=2,  # is-at
            hwsrc=attacker_mac,
            psrc=attacker_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=attacker_ip,
        )
    )
    announcement.time = t
    packets.append(announcement)
    t += 0.05

    while t < end_time:
        # Unsolicited ARP reply: "gateway_ip is at attacker_mac"
        arp_reply = (
            Ether(src=attacker_mac, dst=victim_mac)
            / ARP(
                op=2,  # is-at (reply)
                hwsrc=attacker_mac,
                psrc=gateway_ip,
                hwdst=victim_mac,
                pdst=victim_ip,
            )
        )
        arp_reply.time = t
        packets.append(arp_reply)

        t += interval_seconds + rng.uniform(-0.1, 0.1)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=attacker_ip,
        dst_ip=victim_ip,
        attack_type="arp_spoofing",
    )
    return packets, label


def generate_benign_backup_flash_crowd(
    source_host: NetworkHost,
    destination_host: NetworkHost,
    start_time: float,
    duration: float = 40.0,
    rate_pps: float = 180.0,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate high-volume legitimate backup job or flash crowd (e.g. `rsync -avz`).

    Real-World Behavior:
    A high-throughput internal data transfer between an internal database server and backup host.
    While the packet rate and volume superficially resemble a denial-of-service flood,
    this session features valid TCP 3-way handshakes, full TCP flow control ACKs, maximum-sized
    MTU payloads (1460 bytes), and graceful connection teardowns. This serves as an ambiguous
    case to test false positive mitigation in anomaly detection.

    Args:
        source_host: Data source endpoint.
        destination_host: Backup / file storage destination endpoint.
        start_time: Start timestamp.
        duration: Duration of high-volume transfer in seconds.
        rate_pps: Packet rate per second.
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel marked benign_backup).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    sport = rng.randint(49152, 65535)
    dport = 873  # rsync default port
    c_seq = rng.randint(100000, 9000000)
    s_seq = rng.randint(100000, 9000000)
    t = start_time
    rtt = rng.uniform(0.001, 0.002)

    # 1. Clean Handshake
    syn = (
        Ether(src=source_host.mac, dst=destination_host.mac)
        / IP(src=source_host.ip, dst=destination_host.ip)
        / TCP(sport=sport, dport=dport, flags="S", seq=c_seq)
    )
    syn.time = t
    packets.append(syn)
    c_seq += 1

    t += rtt
    syn_ack = (
        Ether(src=destination_host.mac, dst=source_host.mac)
        / IP(src=destination_host.ip, dst=source_host.ip)
        / TCP(sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq)
    )
    syn_ack.time = t
    packets.append(syn_ack)
    s_seq += 1

    t += rtt
    ack = (
        Ether(src=source_host.mac, dst=destination_host.mac)
        / IP(src=source_host.ip, dst=destination_host.ip)
        / TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq)
    )
    ack.time = t
    packets.append(ack)

    # 2. Bulk Data Transfer
    total_packets = int(duration * rate_pps)
    inter_delay = 1.0 / rate_pps

    for i in range(total_packets):
        payload_chunk = bytes([rng.randint(0, 255) for _ in range(1420)])
        data_pkt = (
            Ether(src=source_host.mac, dst=destination_host.mac)
            / IP(src=source_host.ip, dst=destination_host.ip)
            / TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq)
            / Raw(load=payload_chunk)
        )
        data_pkt.time = t
        packets.append(data_pkt)
        c_seq += len(payload_chunk)

        # Destination sends periodic TCP ACKs (every 2-3 data packets)
        if i % 3 == 0:
            ack_pkt = (
                Ether(src=destination_host.mac, dst=source_host.mac)
                / IP(src=destination_host.ip, dst=source_host.ip)
                / TCP(sport=dport, dport=sport, flags="A", seq=s_seq, ack=c_seq)
            )
            ack_pkt.time = t + rtt
            packets.append(ack_pkt)

        t += inter_delay

    # 3. Clean FIN teardown
    fin = (
        Ether(src=source_host.mac, dst=destination_host.mac)
        / IP(src=source_host.ip, dst=destination_host.ip)
        / TCP(sport=sport, dport=dport, flags="FA", seq=c_seq, ack=s_seq)
    )
    fin.time = t
    packets.append(fin)

    t += rtt
    dest_fin = (
        Ether(src=destination_host.mac, dst=source_host.mac)
        / IP(src=destination_host.ip, dst=source_host.ip)
        / TCP(sport=dport, dport=sport, flags="FA", seq=s_seq, ack=c_seq + 1)
    )
    dest_fin.time = t
    packets.append(dest_fin)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip=source_host.ip,
        dst_ip=destination_host.ip,
        attack_type="benign_backup",
    )
    return packets, label


def generate_distributed_slow_scan(
    victim_ip: str,
    victim_mac: str,
    start_time: float,
    source_count: int = 5,
    ports_per_source: int = 4,
    rng: random.Random = None,
) -> Tuple[List[Packet], AttackLabel]:
    """Simulate a coordinated distributed reconnaissance scan from multiple botnet nodes.

    Real-World Behavior:
    Multiple distinct compromised hosts (or distributed VPS nodes) each probe only
    a handful of destination ports spaced out over time (e.g., 3-4 ports per host).
    Individually, each source IP remains far below typical single-host port scan
    thresholds (e.g. 20 ports / 10s), but collectively they map out the victim's
    perimeter.

    Args:
        victim_ip: Target server IP.
        victim_mac: Target server MAC.
        start_time: Start timestamp.
        source_count: Number of distinct attacking nodes (default: 5).
        ports_per_source: Number of ports probed per node (default: 4).
        rng: Deterministic random generator.

    Returns:
        Tuple of (generated packets, ground-truth AttackLabel).
    """
    if rng is None:
        rng = random.Random(42)

    packets: List[Packet] = []
    attacker_ips = [f"192.168.1.{200 + i}" for i in range(source_count)]
    attacker_macs = [f"00:16:3e:00:aa:{i+1:02x}" for i in range(source_count)]
    t = start_time
    all_ports = rng.sample(range(20, 1024), source_count * ports_per_source)
    port_idx = 0

    for node_idx in range(source_count):
        src_ip = attacker_ips[node_idx]
        src_mac = attacker_macs[node_idx]

        for _ in range(ports_per_source):
            port = all_ports[port_idx]
            port_idx += 1
            sport = rng.randint(49152, 65535)
            c_seq = rng.randint(100000, 9000000)

            syn = (
                Ether(src=src_mac, dst=victim_mac)
                / IP(src=src_ip, dst=victim_ip)
                / TCP(sport=sport, dport=port, flags="S", seq=c_seq)
            )
            syn.time = t
            packets.append(syn)

            # Victim RST-ACK
            rtt = rng.uniform(0.001, 0.003)
            rst_ack = (
                Ether(src=victim_mac, dst=src_mac)
                / IP(src=victim_ip, dst=src_ip)
                / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=c_seq + 1)
            )
            rst_ack.time = t + rtt
            packets.append(rst_ack)

            t += rng.uniform(4.0, 8.0)

    label = AttackLabel(
        start_ts=start_time,
        end_ts=t,
        src_ip="distributed_multiple",
        dst_ip=victim_ip,
        attack_type="distributed_slow_scan",
    )
    return packets, label
