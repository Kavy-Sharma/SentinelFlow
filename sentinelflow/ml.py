"""Machine Learning Anomaly Detection Module.

Trains and evaluates an unsupervised Isolation Forest model trained exclusively
on benign baseline network traffic. Computes normalized anomaly scores and
ranks top deviating features using baseline z-score distributions to provide
explainable alert attribution.
"""
