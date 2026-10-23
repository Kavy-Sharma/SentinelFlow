"""PCAP Ingestion and Packet Parsing Module.

Provides offline parsing and packet extraction from .pcap files without requiring
root/admin privileges or active promiscuous network capture. Filters protocols,
extracts packet timestamps, IP 5-tuples, TCP flags, and payload lengths.
"""
