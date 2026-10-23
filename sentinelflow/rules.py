"""Deterministic Rule-Based Threat Detectors.

Implements heuristic and signature-based detection rules for:
- Port Scanning (TCP SYN, Full Connect)
- SYN Flood and UDP Flood DoS attacks
- SSH Brute Force authentication attacks
- ARP Spoofing / Poisoning (Adversary-in-the-Middle)

Each rule evaluates extracted flow/window features against thresholds configured
in config/default.yaml and emits structured AlertExplanation records.
"""
