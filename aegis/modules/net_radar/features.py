"""Flow features aligned with NSL-KDD / CICIDS schema."""
from __future__ import annotations
from dataclasses import dataclass

FEATURE_ORDER = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_serror_rate",
    "dst_host_rerror_rate", "logged_in", "num_failed_logins",
    "num_compromised", "root_shell", "num_root",
    "num_file_creations", "num_access_files",
    "is_guest_login", "is_host_login",
    "protocol_tcp", "protocol_udp", "protocol_icmp",
    "flag_syn", "flag_fin", "flag_rst", "flag_psh",
]

MITRE_STAGES = [
    "Reconnaissance",
    "InitialAccess",
    "Execution",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
    "Benign",
]
STAGE_INDEX = {s: i for i, s in enumerate(MITRE_STAGES)}


@dataclass
class FlowVector:
    values: list

    def to_matrix_row(self):
        return self.values


def from_nslkdd_row(row):
    idx = {
        "duration": 0, "src_bytes": 4, "dst_bytes": 5,
        "logged_in": 11, "num_failed_logins": 10, "num_compromised": 13,
        "root_shell": 14, "num_root": 15, "num_file_creations": 16,
        "num_access_files": 18, "is_guest_login": 21, "is_host_login": 20,
        "count": 22, "srv_count": 23, "serror_rate": 24, "rerror_rate": 25,
        "same_srv_rate": 26, "diff_srv_rate": 27,
        "dst_host_count": 31, "dst_host_srv_count": 32,
        "dst_host_serror_rate": 34, "dst_host_rerror_rate": 35,
    }
    out = [0.0] * len(FEATURE_ORDER)
    for name, i in idx.items():
        if i < len(row):
            out[FEATURE_ORDER.index(name)] = float(row[i])
    return FlowVector(out)