"""Realistic benign network traffic generator.

Simulates normal enterprise workstation activity over a configurable simulated duration
(default: 15 minutes / 900 seconds) across approximately 10 LAN hosts, an internal server,
a default gateway, and public internet services (DNS, Web).

Real-World Behaviors Imitated:
- RFC 793 / RFC 9293: Full TCP state transitions (SYN -> SYN-ACK -> ACK -> Data -> FIN-ACK -> ACK)
  for HTTP (TCP/80) and HTTPS (TCP/443).
- RFC 1035: Recursive DNS resolution queries (UDP/53) with corresponding standard answer records.
- RFC 4253 / RFC 4254: Long-lived interactive SSH sessions (TCP/22) exhibiting low-volume,
  periodic keepalive and keystroke packet dynamics.
- RFC 792: Periodic ICMP Echo Request and Echo Reply health checks and connectivity diagnostics.
- Poisson & Pareto Traffic Models: Human browsing bursts interspersed with idle think time.
"""

import logging
import random
from typing import List, Tuple

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

from sentinelflow.generator.models import GeneratorConfig, NetworkHost

logger = logging.getLogger(__name__)


def build_default_network() -> Tuple[List[NetworkHost], NetworkHost, NetworkHost, List[str]]:
    """Build default network topology representation for benign enterprise simulation.

    Returns:
        Tuple containing:
        - List of 10 internal LAN workstation hosts
        - Gateway router host
        - Internal application/file/SSH server host
        - List of external public web server IPs
    """
    gateway = NetworkHost(
        ip="192.168.1.1",
        mac="00:16:3e:00:01:01",
        hostname="gateway.corp.local",
        is_gateway=True,
    )
    server = NetworkHost(
        ip="192.168.1.20",
        mac="00:16:3e:00:01:14",
        hostname="appserver.corp.local",
        is_internal=True,
    )
    workstations = [
        NetworkHost(
            ip=f"192.168.1.{10 + i}",
            mac=f"00:16:3e:00:01:{10 + i:02x}",
            hostname=f"ws-{i+1:02d}.corp.local",
        )
        for i in range(10)
    ]
    external_web_ips = [
        "93.184.216.34",   # example.com
        "104.244.42.1",    # public cdn
        "151.101.1.69",    # media host
        "140.82.121.4",    # code repository
    ]
    return workstations, gateway, server, external_web_ips


def generate_dns_exchange(
    client: NetworkHost,
    gateway: NetworkHost,
    dns_server_ip: str,
    query_domain: str,
    resolved_ip: str,
    timestamp: float,
    rng: random.Random,
) -> List[Packet]:
    """Simulate RFC 1035 recursive DNS query and resolution.

    Real-world behavior:
    A workstation sends a UDP/53 query for an external hostname to an upstream resolver,
    receiving an authoritative or cached A-record response within a realistic 5-35ms RTT.

    Args:
        client: Requesting workstation host.
        gateway: Local gateway router forwarding external traffic.
        dns_server_ip: Upstream DNS server IP (e.g. 8.8.8.8).
        query_domain: Hostname being resolved.
        resolved_ip: IP address returned in A record.
        timestamp: Start time of the query in epoch seconds.
        rng: Deterministic random generator.

    Returns:
        List of 2 Scapy packets (Query, Response).
    """
    sport = rng.randint(49152, 65535)
    tx_id = rng.randint(1, 65535)
    rtt = rng.uniform(0.008, 0.035)

    query_pkt = (
        Ether(src=client.mac, dst=gateway.mac)
        / IP(src=client.ip, dst=dns_server_ip)
        / UDP(sport=sport, dport=53)
        / DNS(id=tx_id, qr=0, opcode=0, rd=1, qd=DNSQR(qname=query_domain))
    )
    query_pkt.time = timestamp

    resp_pkt = (
        Ether(src=gateway.mac, dst=client.mac)
        / IP(src=dns_server_ip, dst=client.ip)
        / UDP(sport=53, dport=sport)
        / DNS(
            id=tx_id,
            qr=1,
            opcode=0,
            rd=1,
            ra=1,
            qd=DNSQR(qname=query_domain),
            an=DNSRR(rrname=query_domain, ttl=300, rdata=resolved_ip),
        )
    )
    resp_pkt.time = timestamp + rtt

    return [query_pkt, resp_pkt]


def generate_tcp_session(
    client: NetworkHost,
    gateway: NetworkHost,
    server_ip: str,
    server_port: int,
    start_time: float,
    rng: random.Random,
    is_tls: bool = False,
    is_internal: bool = False,
    target_mac: str = "",
) -> List[Packet]:
    """Simulate a complete RFC 793 TCP session with 3-way handshake, payload, and FIN teardown.

    Real-world behavior:
    Models realistic HTTP/HTTPS browsing sessions:
    1. Client initiates 3-way handshake (SYN, SYN-ACK, ACK) with typical RTT.
    2. Client sends HTTP GET or TLS Client Hello request payload.
    3. Server responds with data stream broken into realistic MTU chunks.
    4. Client acknowledges received payload.
    5. Clean bidirectional 4-way FIN teardown terminates connection.

    Args:
        client: Client workstation host.
        gateway: Gateway host for routing external traffic.
        server_ip: Destination server IP.
        server_port: Destination TCP port (80, 443, etc.).
        start_time: Epoch timestamp of connection initiation.
        rng: Deterministic random generator.
        is_tls: Flag indicating HTTPS/TLS payload characteristics.
        is_internal: True if server is on internal LAN (skipping gateway MAC).
        target_mac: Direct MAC if destination is internal.

    Returns:
        List of Scapy packets representing the full connection lifecycle.
    """
    dst_mac = target_mac if is_internal and target_mac else gateway.mac
    packets: List[Packet] = []
    sport = rng.randint(49152, 65535)
    client_seq = rng.randint(100000, 5000000)
    server_seq = rng.randint(500000, 9000000)
    rtt = rng.uniform(0.012, 0.045)
    t = start_time

    # 1. 3-way Handshake
    # SYN
    syn = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="S", seq=client_seq)
    )
    syn.time = t
    packets.append(syn)
    client_seq += 1

    # SYN-ACK
    t += rtt / 2.0
    syn_ack = (
        Ether(src=dst_mac, dst=client.mac)
        / IP(src=server_ip, dst=client.ip)
        / TCP(sport=server_port, dport=sport, flags="SA", seq=server_seq, ack=client_seq)
    )
    syn_ack.time = t
    packets.append(syn_ack)
    server_seq += 1

    # ACK
    t += rtt / 2.0
    ack = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="A", seq=client_seq, ack=server_seq)
    )
    ack.time = t
    packets.append(ack)

    # 2. Application Data Exchange
    t += rng.uniform(0.005, 0.015)
    if is_tls:
        req_payload = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + bytes([rng.randint(0, 255) for _ in range(120)])
    else:
        req_payload = (
            f"GET /api/v1/resource HTTP/1.1\r\nHost: {server_ip}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
        ).encode("utf-8")

    client_req = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="PA", seq=client_seq, ack=server_seq)
        / Raw(load=req_payload)
    )
    client_req.time = t
    packets.append(client_req)
    client_seq += len(req_payload)

    # Server Response Chunks
    t += rtt
    num_response_chunks = rng.randint(2, 5)
    for _ in range(num_response_chunks):
        chunk_size = rng.randint(300, 1420)
        resp_payload = bytes([rng.randint(65, 90) for _ in range(chunk_size)])
        server_resp = (
            Ether(src=dst_mac, dst=client.mac)
            / IP(src=server_ip, dst=client.ip)
            / TCP(sport=server_port, dport=sport, flags="PA", seq=server_seq, ack=client_seq)
            / Raw(load=resp_payload)
        )
        server_resp.time = t
        packets.append(server_resp)
        server_seq += chunk_size
        t += rng.uniform(0.001, 0.004)

    # Client ACK for data
    t += rtt / 2.0
    client_ack = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="A", seq=client_seq, ack=server_seq)
    )
    client_ack.time = t
    packets.append(client_ack)

    # 3. Connection Teardown (FIN-ACK handshake)
    t += rng.uniform(0.02, 0.08)
    client_fin = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="FA", seq=client_seq, ack=server_seq)
    )
    client_fin.time = t
    packets.append(client_fin)
    client_seq += 1

    t += rtt / 2.0
    server_ack = (
        Ether(src=dst_mac, dst=client.mac)
        / IP(src=server_ip, dst=client.ip)
        / TCP(sport=server_port, dport=sport, flags="A", seq=server_seq, ack=client_seq)
    )
    server_ack.time = t
    packets.append(server_ack)

    server_fin = (
        Ether(src=dst_mac, dst=client.mac)
        / IP(src=server_ip, dst=client.ip)
        / TCP(sport=server_port, dport=sport, flags="FA", seq=server_seq, ack=client_seq)
    )
    server_fin.time = t + 0.001
    packets.append(server_fin)
    server_seq += 1

    t += rtt / 2.0
    client_final_ack = (
        Ether(src=client.mac, dst=dst_mac)
        / IP(src=client.ip, dst=server_ip)
        / TCP(sport=sport, dport=server_port, flags="A", seq=client_seq, ack=server_seq)
    )
    client_final_ack.time = t
    packets.append(client_final_ack)

    return packets


def generate_ssh_long_session(
    client: NetworkHost,
    server: NetworkHost,
    start_time: float,
    duration: float,
    rng: random.Random,
) -> List[Packet]:
    """Simulate an RFC 4253 / RFC 4254 long-lived interactive SSH terminal session.

    Real-world behavior:
    An engineer establishes an SSH connection to an internal bastion/server.
    After initial key negotiation, the session stays open for several minutes,
    producing sporadic, tiny interactive packets (e.g., keystroke echo, cursor blink,
    keepalives every 15-45 seconds) rather than high-rate bursts.

    Args:
        client: Client workstation host.
        server: Internal SSH server host.
        start_time: Session start timestamp.
        duration: Active session duration in seconds.
        rng: Deterministic random generator.

    Returns:
        List of Scapy packets representing the full SSH session.
    """
    packets: List[Packet] = []
    sport = rng.randint(49152, 65535)
    c_seq = rng.randint(1000000, 9000000)
    s_seq = rng.randint(1000000, 9000000)
    t = start_time
    rtt = rng.uniform(0.001, 0.005)  # LAN low latency

    # Handshake
    syn = (
        Ether(src=client.mac, dst=server.mac)
        / IP(src=client.ip, dst=server.ip)
        / TCP(sport=sport, dport=22, flags="S", seq=c_seq)
    )
    syn.time = t
    packets.append(syn)
    c_seq += 1

    t += rtt
    syn_ack = (
        Ether(src=server.mac, dst=client.mac)
        / IP(src=server.ip, dst=client.ip)
        / TCP(sport=22, dport=sport, flags="SA", seq=s_seq, ack=c_seq)
    )
    syn_ack.time = t
    packets.append(syn_ack)
    s_seq += 1

    t += rtt
    ack = (
        Ether(src=client.mac, dst=server.mac)
        / IP(src=client.ip, dst=server.ip)
        / TCP(sport=sport, dport=22, flags="A", seq=c_seq, ack=s_seq)
    )
    ack.time = t
    packets.append(ack)

    # SSH Protocol Banner Exchange
    c_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    s_banner = b"SSH-2.0-OpenSSH_8.9p1 Debian-1\r\n"

    t += 0.01
    c_banner_pkt = (
        Ether(src=client.mac, dst=server.mac)
        / IP(src=client.ip, dst=server.ip)
        / TCP(sport=sport, dport=22, flags="PA", seq=c_seq, ack=s_seq)
        / Raw(load=c_banner)
    )
    c_banner_pkt.time = t
    packets.append(c_banner_pkt)
    c_seq += len(c_banner)

    t += rtt
    s_banner_pkt = (
        Ether(src=server.mac, dst=client.mac)
        / IP(src=server.ip, dst=client.ip)
        / TCP(sport=22, dport=sport, flags="PA", seq=s_seq, ack=c_seq)
        / Raw(load=s_banner)
    )
    s_banner_pkt.time = t
    packets.append(s_banner_pkt)
    s_seq += len(s_banner)

    # Periodic Keepalive / Interactive Keystroke Activity
    curr_time = t + rng.uniform(5.0, 15.0)
    session_end = start_time + duration
    while curr_time < session_end:
        keystroke_payload = bytes([rng.randint(0, 255) for _ in range(rng.randint(36, 72))])
        c_act = (
            Ether(src=client.mac, dst=server.mac)
            / IP(src=client.ip, dst=server.ip)
            / TCP(sport=sport, dport=22, flags="PA", seq=c_seq, ack=s_seq)
            / Raw(load=keystroke_payload)
        )
        c_act.time = curr_time
        packets.append(c_act)
        c_seq += len(keystroke_payload)

        echo_payload = bytes([rng.randint(0, 255) for _ in range(rng.randint(36, 96))])
        s_echo = (
            Ether(src=server.mac, dst=client.mac)
            / IP(src=server.ip, dst=client.ip)
            / TCP(sport=22, dport=sport, flags="PA", seq=s_seq, ack=c_seq)
            / Raw(load=echo_payload)
        )
        s_echo.time = curr_time + rtt
        packets.append(s_echo)
        s_seq += len(echo_payload)

        # Poisson idle interval before next interaction
        curr_time += rng.expovariate(1.0 / 25.0) + 5.0

    # Clean Teardown
    t = curr_time
    fin = (
        Ether(src=client.mac, dst=server.mac)
        / IP(src=client.ip, dst=server.ip)
        / TCP(sport=sport, dport=22, flags="FA", seq=c_seq, ack=s_seq)
    )
    fin.time = t
    packets.append(fin)

    fin_ack = (
        Ether(src=server.mac, dst=client.mac)
        / IP(src=server.ip, dst=client.ip)
        / TCP(sport=22, dport=sport, flags="FA", seq=s_seq, ack=c_seq + 1)
    )
    fin_ack.time = t + rtt
    packets.append(fin_ack)

    return packets


def generate_icmp_ping_burst(
    client: NetworkHost,
    target_ip: str,
    target_mac: str,
    start_time: float,
    count: int,
    rng: random.Random,
) -> List[Packet]:
    """Simulate standard RFC 792 ICMP Echo Request / Reply sequence.

    Real-world behavior:
    Network diagnostic ping utility (e.g. `ping -c 4 192.168.1.1`) emitting
    periodic 64-byte echo requests spaced exactly 1 second apart, with matching
    ICMP sequence counters and identifiers.

    Args:
        client: Requesting host.
        target_ip: Target destination IP.
        target_mac: Next-hop or target MAC address.
        start_time: Start timestamp.
        count: Number of echo requests to send (typically 4).
        rng: Deterministic random generator.

    Returns:
        List of Scapy ICMP packets.
    """
    packets: List[Packet] = []
    ident = rng.randint(100, 65000)
    payload = b"\x00" * 48

    for seq in range(1, count + 1):
        t = start_time + (seq - 1) * 1.0 + rng.uniform(-0.01, 0.01)
        rtt = rng.uniform(0.001, 0.015)

        req = (
            Ether(src=client.mac, dst=target_mac)
            / IP(src=client.ip, dst=target_ip)
            / ICMP(type=8, code=0, id=ident, seq=seq)
            / Raw(load=payload)
        )
        req.time = t
        packets.append(req)

        rep = (
            Ether(src=target_mac, dst=client.mac)
            / IP(src=target_ip, dst=client.ip)
            / ICMP(type=0, code=0, id=ident, seq=seq)
            / Raw(load=payload)
        )
        rep.time = t + rtt
        packets.append(rep)

    return packets


def generate_benign_traffic(config: GeneratorConfig) -> List[Packet]:
    """Generate realistic benign enterprise baseline network traffic.

    Simulates a 15-minute window across 10 client workstations, gateway,
    internal app server, and public internet services with Poisson arrivals
    and idle think intervals.

    Args:
        config: GeneratorConfig specifying seed, duration, and base timestamp.

    Returns:
        List of Scapy packets sorted by timestamp.
    """
    rng = random.Random(config.seed)
    workstations, gateway, app_server, external_web_ips = build_default_network()
    all_packets: List[Packet] = []
    duration = config.simulated_duration_seconds
    base_t = config.base_timestamp

    domain_pool = [
        ("example.com", "93.184.216.34"),
        ("api.internal.corp", "192.168.1.20"),
        ("cdn.assets-delivery.net", "104.244.42.1"),
        ("git.code-repo.com", "140.82.121.4"),
        ("static.web-resources.org", "151.101.1.69"),
    ]

    # 1. Background long-lived SSH sessions (e.g. admin workstation ws-05 to app_server)
    ssh_admin = workstations[4]
    ssh_packets = generate_ssh_long_session(
        client=ssh_admin,
        server=app_server,
        start_time=base_t + 15.0,
        duration=duration - 60.0,
        rng=rng,
    )
    all_packets.extend(ssh_packets)

    # 2. Activity per workstation across 15 minutes
    for ws in workstations:
        current_time = base_t + rng.uniform(1.0, 30.0)
        while current_time < base_t + duration - 40.0:
            activity_type = rng.choices(["web_https", "web_http", "dns", "ping", "internal_api"], weights=[50, 15, 15, 8, 12])[0]

            if activity_type == "dns":
                domain, ip = rng.choice(domain_pool)
                pkts = generate_dns_exchange(
                    client=ws,
                    gateway=gateway,
                    dns_server_ip="8.8.8.8",
                    query_domain=domain,
                    resolved_ip=ip,
                    timestamp=current_time,
                    rng=rng,
                )
                all_packets.extend(pkts)
                current_time += rng.expovariate(1.0 / 30.0) + 5.0

            elif activity_type == "web_https":
                # Precede HTTPS by DNS lookup
                domain, ip = rng.choice(domain_pool)
                dns_pkts = generate_dns_exchange(
                    client=ws,
                    gateway=gateway,
                    dns_server_ip="8.8.8.8",
                    query_domain=domain,
                    resolved_ip=ip,
                    timestamp=current_time,
                    rng=rng,
                )
                all_packets.extend(dns_pkts)

                tcp_pkts = generate_tcp_session(
                    client=ws,
                    gateway=gateway,
                    server_ip=ip,
                    server_port=443,
                    start_time=current_time + rng.uniform(0.04, 0.08),
                    rng=rng,
                    is_tls=True,
                )
                all_packets.extend(tcp_pkts)
                # Bursty user behavior: think time
                current_time += rng.expovariate(1.0 / 45.0) + 10.0

            elif activity_type == "web_http":
                domain, ip = rng.choice(domain_pool)
                tcp_pkts = generate_tcp_session(
                    client=ws,
                    gateway=gateway,
                    server_ip=ip,
                    server_port=80,
                    start_time=current_time,
                    rng=rng,
                    is_tls=False,
                )
                all_packets.extend(tcp_pkts)
                current_time += rng.expovariate(1.0 / 60.0) + 15.0

            elif activity_type == "internal_api":
                tcp_pkts = generate_tcp_session(
                    client=ws,
                    gateway=gateway,
                    server_ip=app_server.ip,
                    server_port=8080,
                    start_time=current_time,
                    rng=rng,
                    is_tls=False,
                    is_internal=True,
                    target_mac=app_server.mac,
                )
                all_packets.extend(tcp_pkts)
                current_time += rng.expovariate(1.0 / 40.0) + 10.0

            elif activity_type == "ping":
                target = rng.choice([gateway.ip, "8.8.8.8"])
                dst_mac = gateway.mac
                ping_pkts = generate_icmp_ping_burst(
                    client=ws,
                    target_ip=target,
                    target_mac=dst_mac,
                    start_time=current_time,
                    count=4,
                    rng=rng,
                )
                all_packets.extend(ping_pkts)
                current_time += rng.expovariate(1.0 / 90.0) + 30.0

    # Ensure all timestamps are monotonic
    all_packets.sort(key=lambda p: float(p.time))
    logger.info(
        "Generated %d benign packets over %.1f seconds across %d hosts (seed=%d)",
        len(all_packets),
        duration,
        len(workstations),
        config.seed,
    )
    return all_packets
