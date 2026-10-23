"""Hybrid Alert Fusion and Arbitration Engine.

Correlates and fuses deterministic rule violations with unsupervised Isolation Forest
anomaly scores. Arbitrates confidence levels (HIGH, MEDIUM, LOW), aggregates severities,
deduplicates alerts, and generates unified AlertExplanation records.
"""
