"""Feature Extraction Module.

Extracts statistical network traffic features:
- Per-source time-windowed aggregated metrics (packet rates, SYN/ACK ratios, unique destination port counts).
- Bidirectional network flow records (5-tuple: source IP, destination IP, source port, destination port, protocol).
"""
