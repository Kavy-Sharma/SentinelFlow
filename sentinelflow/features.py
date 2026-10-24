"""Feature Extraction Module for SentinelFlow.

Computes:
1. Per-(src_ip, window) statistical traffic features:
   - Volume & Rate: pps, bps, bytes_per_sec
   - Diversity & Cardinality: unique_dst_ips, unique_dst_ports
   - Connection Dynamics: syn_count, synack_ratio, syn_without_ack_fraction,
     short_connection_fraction, connections_to_same_dst_port_max
   - Packet Geometry: mean_packet_size, std_packet_size
   - Protocol Shares: tcp_share, udp_share, icmp_share, arp_share
   - Temporal Distributions: inter_arrival_mean, inter_arrival_std
   - Layer 2 & Spoofing Indicators: arp_reply_count, mac_binding_changes
2. Bidirectional flow table:
   - Canonical 5-tuple tracking
   - Forward/backward packet & byte counts
   - TCP flag summaries
   - Connection lifecycle states (completed, half_open, reset)
3. Ground-truth label joiner for evaluation.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

WINDOW_FEATURE_COLUMNS = [
    "win_start",
    "win_end",
    "src_ip",
    "packet_count",
    "pps",
    "bps",
    "bytes_per_sec",
    "unique_dst_ips",
    "unique_dst_ports",
    "syn_count",
    "synack_ratio",
    "syn_without_ack_fraction",
    "short_connection_fraction",
    "connections_to_same_dst_port_max",
    "mean_packet_size",
    "std_packet_size",
    "tcp_share",
    "udp_share",
    "icmp_share",
    "arp_share",
    "inter_arrival_mean",
    "inter_arrival_std",
    "arp_reply_count",
    "mac_binding_changes",
]

FLOW_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "start",
    "end",
    "duration",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "flags_summary",
    "state",
]


def _correlate_tcp_handshakes(
    packets_df: pd.DataFrame,
    max_handshake_timeout: float = 30.0,
) -> pd.DataFrame:
    """Correlate TCP SYN, SYN-ACK, and ACK packets across connections.

    Identifies for each initiated SYN whether it received a matching SYN-ACK
    from the target responder and whether the handshake was completed with a final ACK.

    Real-World Handshake Mechanics & Endpoint Correlation:
    - Initiator sends SYN: (client_ip, server_ip, client_port, server_port) with flag 'S' (no 'A').
    - Responder sends SYN-ACK: (server_ip, client_ip, server_port, client_port) with flags 'SA'.
      Notice that this packet has src_ip == server_ip and thus appears in the server's traffic,
      NOT the client's traffic. By correlating across the 4-tuple endpoints, we do not falsely
      claim a handshake is unanswered simply because its response was sent by another host.
    - Initiator sends final ACK: (client_ip, server_ip, client_port, server_port) with flag 'A'
      (no 'S' or 'R') arriving at or after the SYN-ACK.

    Limitations:
    1. Missing Packets: Packet loss or uncaptured capture taps can drop SYN-ACK or ACK,
       causing a completed handshake to appear uncompleted.
    2. Retransmissions: Retransmitted SYNs for a single connection are matched against the
       subsequent SYN-ACK, but uncoordinated duplicate SYNs can count as separate connection attempts.
    3. Window Boundaries: If a SYN arrives near the end of a window (e.g. t = 4.98s) and the
       SYN-ACK arrives in the subsequent window (e.g. t = 5.02s), window-local aggregations would
       fail to see the handshake. Our trace-wide pre-correlation resolves this across window boundaries.

    Args:
        packets_df: Full DataFrame of parsed network packets.
        max_handshake_timeout: Maximum delay (seconds) to match a SYN-ACK or ACK (default: 30.0s).

    Returns:
        DataFrame annotated with boolean flags: `syn_has_synack` and `syn_has_ack`.
    """
    df = packets_df.copy()
    df["syn_has_synack"] = False
    df["syn_has_ack"] = False

    tcp_mask = (df["proto"] == "TCP") & df["src_port"].notna() & df["dst_port"].notna()
    if not tcp_mask.any():
        return df

    tcp_df = df[tcp_mask]
    flags = tcp_df["tcp_flags"].fillna("").astype(str)

    is_syn = flags.str.contains("S") & ~flags.str.contains("A")
    is_synack = flags.str.contains("S") & flags.str.contains("A")
    is_ack = flags.str.contains("A") & ~flags.str.contains("S") & ~flags.str.contains("R")

    syn_df = tcp_df[is_syn]
    synack_df = tcp_df[is_synack]
    ack_df = tcp_df[is_ack]

    if syn_df.empty:
        return df

    # Index SYN-ACKs by (initiator_ip, responder_ip, initiator_port, responder_port)
    synack_dict: Dict[Tuple[str, str, int, int], List[float]] = {}
    for _, row in synack_df.iterrows():
        # Standard: responder is src, initiator is dst
        key = (str(row["dst_ip"]), str(row["src_ip"]), int(row["dst_port"]), int(row["src_port"]))
        synack_dict.setdefault(key, []).append(float(row["ts"]))
        # Also support synthetic/loopback unswapped IPs
        sym_key = (str(row["src_ip"]), str(row["dst_ip"]), int(row["dst_port"]), int(row["src_port"]))
        if sym_key != key:
            synack_dict.setdefault(sym_key, []).append(float(row["ts"]))

    # Index completing ACKs by (initiator_ip, responder_ip, initiator_port, responder_port)
    ack_dict: Dict[Tuple[str, str, int, int], List[float]] = {}
    for _, row in ack_df.iterrows():
        key = (str(row["src_ip"]), str(row["dst_ip"]), int(row["src_port"]), int(row["dst_port"]))
        ack_dict.setdefault(key, []).append(float(row["ts"]))

    synack_matches: List[Tuple[Any, bool]] = []
    ack_matches: List[Tuple[Any, bool]] = []

    for idx, row in syn_df.iterrows():
        key = (str(row["src_ip"]), str(row["dst_ip"]), int(row["src_port"]), int(row["dst_port"]))
        t_syn = float(row["ts"])

        has_sa = False
        has_a = False
        t_sa_matched: Optional[float] = None

        if key in synack_dict:
            for t_sa in synack_dict[key]:
                if t_syn < t_sa <= t_syn + max_handshake_timeout:
                    has_sa = True
                    t_sa_matched = t_sa
                    break

        if has_sa and t_sa_matched is not None and key in ack_dict:
            for t_a in ack_dict[key]:
                if t_sa_matched <= t_a <= t_sa_matched + max_handshake_timeout:
                    has_a = True
                    break

        synack_matches.append((idx, has_sa))
        ack_matches.append((idx, has_a))

    for idx, val in synack_matches:
        df.at[idx, "syn_has_synack"] = val
    for idx, val in ack_matches:
        df.at[idx, "syn_has_ack"] = val

    return df


def extract_window_features(
    packets_df: pd.DataFrame,
    window_size: float = 5.0,
    step_size: Optional[float] = None,
) -> pd.DataFrame:
    """Extract per-(src_ip, time-window) aggregated statistical traffic features.

    Real-World Cybersecurity Rationale for Each Feature:
    - pps (Packets Per Second): Sudden surges indicate high-volume DoS floods (SYN/UDP flood)
      or aggressive port scans.
    - bps (Bits Per Second): High bandwidth consumption indicates volumetric exfiltration
      or UDP/ICMP amplification attacks.
    - unique_dst_ips: Measures horizontal reconnaissance across subnets (network sweeps).
    - unique_dst_ports: Key signature of vertical port scans (e.g. Nmap scanning 1000 ports).
    - syn_count & synack_ratio: An imbalance indicates uncompleted half-open connection attempts
      characteristic of SYN flood DoS or stealth half-open scanning.
    - syn_without_ack_fraction: Highlights hosts initiating handshakes without completing them.
    - short_connection_fraction: High ratio of connections with <= 3 packets or RSTs exposes
      automated port scans and failed dictionary brute-force attempts.
    - connections_to_same_dst_port_max: Identifies concentrated targeting of a single critical service
      (e.g., port 22 for SSH brute force or port 80 for HTTP flood).
    - mean/std packet size: Floods often exhibit identical payload sizes (near-zero std),
      while benign traffic shows high size variance.
    - protocol_shares (TCP/UDP/ICMP/ARP): Isolates anomalous protocol shifts (e.g., pure UDP storms).
    - inter_arrival_mean/std: Automated attack tools exhibit rigidly periodic timing distributions
      compared to Poisson/Pareto human user think time.
    - arp_reply_count & mac_binding_changes: Direct indicators of ARP cache poisoning / MitM.

    Args:
        packets_df: DataFrame output from sentinelflow.parser.
        window_size: Duration of each aggregation window in seconds (default: 5.0s).
        step_size: Step interval for sliding windows. If None, defaults to window_size (disjoint bins).

    Returns:
        DataFrame containing statistical features for each (src_ip, window) group.
    """
    if packets_df.empty or "src_ip" not in packets_df.columns:
        return pd.DataFrame(columns=WINDOW_FEATURE_COLUMNS)

    df = packets_df.dropna(subset=["src_ip"]).copy()
    df = df[df["src_ip"] != ""]
    if df.empty:
        return pd.DataFrame(columns=WINDOW_FEATURE_COLUMNS)

    # Pre-correlate TCP handshakes across full capture before window partitioning
    df = _correlate_tcp_handshakes(df)

    df.sort_values(by="ts", inplace=True)
    min_ts = float(df["ts"].min())
    max_ts = float(df["ts"].max())

    actual_step = window_size if step_size is None or step_size <= 0 else step_size

    # Build window time bounds
    window_records: List[Dict[str, Any]] = []

    # Case 1: Fixed non-overlapping bins (optimized vectorization)
    if actual_step == window_size:
        df["win_idx"] = np.floor((df["ts"] - min_ts) / window_size).astype(int)
        for (src_ip, win_idx), group in df.groupby(["src_ip", "win_idx"]):
            win_start = min_ts + win_idx * window_size
            win_end = win_start + window_size
            record = _compute_single_window_features(group, src_ip, win_start, win_end, window_size)
            window_records.append(record)

    # Case 2: Sliding overlapping windows
    else:
        window_starts = np.arange(min_ts, max_ts + 1e-6, actual_step)
        for w_start in window_starts:
            w_end = w_start + window_size
            mask = (df["ts"] >= w_start) & (df["ts"] < w_end)
            w_df = df[mask]
            if w_df.empty:
                continue
            for src_ip, group in w_df.groupby("src_ip"):
                record = _compute_single_window_features(group, src_ip, w_start, w_end, window_size)
                window_records.append(record)

    if not window_records:
        return pd.DataFrame(columns=WINDOW_FEATURE_COLUMNS)

    features_df = pd.DataFrame(window_records)
    features_df.sort_values(by=["win_start", "src_ip"], inplace=True)
    features_df.reset_index(drop=True, inplace=True)
    return features_df


def _compute_single_window_features(
    group: pd.DataFrame,
    src_ip: str,
    win_start: float,
    win_end: float,
    window_size: float,
) -> Dict[str, Any]:
    """Compute statistical feature metrics for a single (src_ip, window) packet group."""
    n_packets = len(group)
    total_bytes = float(group["length"].sum())

    pps = float(n_packets) / window_size
    bps = (total_bytes * 8.0) / window_size
    bytes_per_sec = total_bytes / window_size

    unique_dst_ips = int(group["dst_ip"].dropna().nunique())
    unique_dst_ports = int(group["dst_port"].dropna().nunique())

    # TCP Flag & Handshake Metrics
    tcp_pkts = group[group["proto"] == "TCP"]
    syn_count = 0
    synack_count = 0
    syn_without_ack_fraction = 0.0
    short_conn_fraction = 0.0

    if not tcp_pkts.empty:
        flags = tcp_pkts["tcp_flags"].dropna().astype(str)
        is_syn = flags.apply(lambda f: "S" in f and "A" not in f)
        syn_pkts = tcp_pkts[is_syn]
        syn_count = len(syn_pkts)

        # Correlated Handshake Evaluation:
        # A SYN received a SYN-ACK if its matching responder packet was observed.
        synacks_received = int(syn_pkts["syn_has_synack"].sum()) if ("syn_has_synack" in syn_pkts.columns and syn_count > 0) else 0
        syns_completed_ack = int(syn_pkts["syn_has_ack"].sum()) if ("syn_has_ack" in syn_pkts.columns and syn_count > 0) else 0

        # Also count SYN-ACKs sent by this host when acting as a responder
        is_synack = flags.apply(lambda f: "S" in f and "A" in f)
        synack_sent_pkts = tcp_pkts[is_synack]
        if syn_count > 0 and len(synack_sent_pkts) > 0:
            own_syn_ports = set(zip(syn_pkts["src_port"].astype(int), syn_pkts["dst_port"].astype(int)))
            sent_responding_to_own = synack_sent_pkts.apply(
                lambda r: (int(r["dst_port"]), int(r["src_port"])) in own_syn_ports,
                axis=1,
            )
            synacks_sent = int((~sent_responding_to_own).sum())
        else:
            synacks_sent = len(synack_sent_pkts)

        synack_count = synacks_received + synacks_sent

        # syn_without_ack_fraction: fraction of initiated SYNs that never reached a completing ACK
        if syn_count > 0:
            syns_without_ack = max(0, syn_count - syns_completed_ack)
            syn_without_ack_fraction = float(syns_without_ack) / float(syn_count)
        else:
            syn_without_ack_fraction = 0.0

        # Short connection evaluation: group by (dst_ip, dst_port, src_port)
        conn_sizes = tcp_pkts.groupby(["dst_ip", "dst_port", "src_port"], observed=False).size()
        total_conns = len(conn_sizes)
        if total_conns > 0:
            has_rst = (
                tcp_pkts["tcp_flags"]
                .dropna()
                .astype(str)
                .str.contains("R")
                .groupby([tcp_pkts["dst_ip"], tcp_pkts["dst_port"], tcp_pkts["src_port"]], observed=False)
                .any()
            )
            short_conns = int(((conn_sizes <= 3) | has_rst.reindex(conn_sizes.index, fill_value=False)).sum())
            short_conn_fraction = float(short_conns) / float(total_conns)

    synack_ratio = float(syn_count) / float(synack_count + 1.0)

    # Max connections/packets targeting a single destination port
    dst_ports = group["dst_port"].dropna()
    conn_to_same_port_max = int(dst_ports.value_counts().max()) if not dst_ports.empty else 0

    # Packet Size Distributions
    mean_packet_size = float(group["length"].mean())
    std_packet_size = float(group["length"].std(ddof=0)) if n_packets > 1 else 0.0

    # Protocol Distribution Shares
    proto_counts = group["proto"].value_counts()
    tcp_share = float(proto_counts.get("TCP", 0)) / float(n_packets)
    udp_share = float(proto_counts.get("UDP", 0)) / float(n_packets)
    icmp_share = float(proto_counts.get("ICMP", 0)) / float(n_packets)
    arp_share = float(proto_counts.get("ARP", 0)) / float(n_packets)

    # Inter-Arrival Times (sorted timestamps)
    ts_array = np.sort(group["ts"].values)
    diffs = np.diff(ts_array)
    if len(diffs) == 0:
        inter_arrival_mean = 0.0
        inter_arrival_std = 0.0
    else:
        inter_arrival_mean = float(np.mean(diffs))
        inter_arrival_std = float(np.std(diffs)) if len(diffs) > 1 else 0.0

    # Layer 2 Indicators
    arp_pkts = group[group["proto"] == "ARP"]
    arp_reply_count = (
        int((arp_pkts["arp_op"] == 2).sum())
        if (not arp_pkts.empty and "arp_op" in arp_pkts.columns)
        else 0
    )
    mac_binding_changes = (
        max(0, int(group["src_mac"].dropna().nunique()) - 1)
        if "src_mac" in group.columns
        else 0
    )

    return {
        "win_start": win_start,
        "win_end": win_end,
        "src_ip": src_ip,
        "packet_count": n_packets,
        "pps": pps,
        "bps": bps,
        "bytes_per_sec": bytes_per_sec,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "syn_count": syn_count,
        "synack_ratio": synack_ratio,
        "syn_without_ack_fraction": syn_without_ack_fraction,
        "short_connection_fraction": short_conn_fraction,
        "connections_to_same_dst_port_max": conn_to_same_port_max,
        "mean_packet_size": mean_packet_size,
        "std_packet_size": std_packet_size,
        "tcp_share": tcp_share,
        "udp_share": udp_share,
        "icmp_share": icmp_share,
        "arp_share": arp_share,
        "inter_arrival_mean": inter_arrival_mean,
        "inter_arrival_std": inter_arrival_std,
        "arp_reply_count": arp_reply_count,
        "mac_binding_changes": mac_binding_changes,
    }


def extract_bidirectional_flows(packets_df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate network packets into bidirectional flow records.

    A flow is indexed by a canonical 5-tuple:
    (IP_A, IP_B, Port_A, Port_B, Protocol).
    The initiator (first packet chronologically) defines the forward direction.

    Attributes:
    - 5-tuple: src_ip, dst_ip, src_port, dst_port, proto
    - start, end, duration
    - fwd_packets, bwd_packets, total_packets
    - fwd_bytes, bwd_bytes, total_bytes
    - flags_summary: Unique TCP flags observed
    - state: "completed" (graceful FIN teardown), "reset" (RST seen), "half_open" (SYN without teardown)

    Args:
        packets_df: DataFrame output from sentinelflow.parser.

    Returns:
        DataFrame containing bidirectional flow records.
    """
    if packets_df.empty:
        return pd.DataFrame(columns=FLOW_COLUMNS)

    df = packets_df.dropna(subset=["src_ip", "dst_ip"]).copy()
    if df.empty:
        return pd.DataFrame(columns=FLOW_COLUMNS)

    df.sort_values(by="ts", inplace=True)

    # Generate canonical flow key: order endpoints symmetrically (vectorized)
    s_ip = df["src_ip"].astype(str).values
    d_ip = df["dst_ip"].astype(str).values
    s_port = df["src_port"].fillna(0).astype(int).values
    d_port = df["dst_port"].fillna(0).astype(int).values
    protos = df["proto"].astype(str).values

    swap = (s_ip > d_ip) | ((s_ip == d_ip) & (s_port > d_port))
    ip1 = np.where(swap, d_ip, s_ip)
    ip2 = np.where(swap, s_ip, d_ip)
    p1 = np.where(swap, d_port, s_port)
    p2 = np.where(swap, s_port, d_port)
    df["flow_key"] = [f"{a}:{b}_{c}:{d}_{e}" for a, b, c, d, e in zip(ip1, p1, ip2, p2, protos)]

    flow_records: List[Dict[str, Any]] = []

    for _, flow_group in df.groupby("flow_key", sort=False):
        first_pkt = flow_group.iloc[0]
        init_src_ip = first_pkt["src_ip"]
        init_dst_ip = first_pkt["dst_ip"]
        init_src_port = first_pkt["src_port"]
        init_dst_port = first_pkt["dst_port"]
        proto = first_pkt["proto"]

        start_ts = float(flow_group["ts"].min())
        end_ts = float(flow_group["ts"].max())
        duration = max(0.0, end_ts - start_ts)

        # Separate forward vs backward packets
        fwd_mask = (flow_group["src_ip"] == init_src_ip) & (flow_group["dst_ip"] == init_dst_ip)
        if pd.notna(init_src_port):
            fwd_mask = fwd_mask & (flow_group["src_port"] == init_src_port)
        fwd_pkts = flow_group[fwd_mask]
        bwd_pkts = flow_group[~fwd_mask]

        fwd_count = len(fwd_pkts)
        bwd_count = len(bwd_pkts)
        fwd_bytes = int(fwd_pkts["length"].sum())
        bwd_bytes = int(bwd_pkts["length"].sum())

        # TCP Flags & Lifecycle State
        flags_seen: List[str] = []
        state = "completed"

        if proto == "TCP":
            all_flags = flow_group["tcp_flags"].dropna().astype(str).tolist()
            flags_seen = sorted(list(set(all_flags)))
            has_rst = any("R" in f for f in all_flags)
            has_fin = any("F" in f for f in all_flags)
            has_syn = any("S" in f for f in all_flags)

            if has_rst:
                state = "reset"
            elif has_fin:
                state = "completed"
            elif has_syn:
                state = "half_open"
            else:
                state = "established"
        else:
            state = "completed"

        flow_records.append({
            "src_ip": init_src_ip,
            "dst_ip": init_dst_ip,
            "src_port": init_src_port,
            "dst_port": init_dst_port,
            "proto": proto,
            "start": start_ts,
            "end": end_ts,
            "duration": duration,
            "fwd_packets": fwd_count,
            "bwd_packets": bwd_count,
            "total_packets": fwd_count + bwd_count,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "total_bytes": fwd_bytes + bwd_bytes,
            "flags_summary": ",".join(flags_seen) if flags_seen else "",
            "state": state,
        })

    flows_df = pd.DataFrame(flow_records)
    flows_df.sort_values(by="start", inplace=True)
    flows_df.reset_index(drop=True, inplace=True)
    return flows_df


def label_windows(
    windows_df: pd.DataFrame,
    labels_df: pd.DataFrame,
) -> pd.DataFrame:
    """Join ground-truth attack label intervals to aggregated traffic windows.

    A time window is assigned an attack label if:
    1. The window interval [win_start, win_end] overlaps the attack interval [start_ts, end_ts].
    2. The window's src_ip matches the attack's src_ip (or the attack uses spoofed/distributed sources).

    Args:
        windows_df: Extracted features DataFrame from extract_window_features.
        labels_df: Ground-truth DataFrame with columns:
                   start_ts, end_ts, src_ip, dst_ip, attack_type.

    Returns:
        DataFrame enriched with `is_malicious` (bool) and `attack_type` (str).
    """
    if windows_df.empty:
        df = windows_df.copy()
        df["is_malicious"] = pd.Series(dtype=bool)
        df["attack_type"] = pd.Series(dtype=str)
        return df

    out_df = windows_df.copy()
    out_df["is_malicious"] = False
    out_df["attack_type"] = "benign"

    if labels_df.empty or "start_ts" not in labels_df.columns:
        return out_df

    # Evaluate overlap for each window
    for _, lbl in labels_df.iterrows():
        l_start = float(lbl["start_ts"])
        l_end = float(lbl["end_ts"])
        l_src = str(lbl["src_ip"])
        l_dst = str(lbl["dst_ip"]) if "dst_ip" in lbl and pd.notna(lbl["dst_ip"]) else ""
        l_type = str(lbl["attack_type"])

        # Temporal intersection condition for half-open intervals [win_start, win_end):
        if l_start < l_end:
            time_mask = (out_df["win_start"] < l_end) & (out_df["win_end"] > l_start)
        else:
            time_mask = (out_df["win_start"] <= l_end) & (out_df["win_end"] >= l_start)

        # Source attribution condition
        if l_src in ("spoofed_various", "distributed_multiple"):
            # Distributed / spoofed attacks affect external sources; exclude victim destination
            if l_dst:
                mask = time_mask & (out_df["src_ip"] != l_dst)
            else:
                mask = time_mask
        else:
            mask = time_mask & (out_df["src_ip"] == l_src)

        out_df.loc[mask, "is_malicious"] = True
        out_df.loc[mask, "attack_type"] = l_type

    return out_df
