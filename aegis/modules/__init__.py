"""AEGIS task modules.

Each subpackage is a self-contained CodSoft Cyber Security task.
Import them lazily — some pull in Scapy / scikit-learn / cryptography.
"""

__all__ = [
    "packet_eye",     # Task 1
    "phish_guard",    # Task 2
    "code_sentinel",  # Task 3
    "net_radar",      # Task 4
    "drop_vault",     # Task 5
]