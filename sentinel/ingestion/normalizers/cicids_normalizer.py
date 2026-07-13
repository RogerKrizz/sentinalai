# ============================================================
# FILE: sentinel/ingestion/normalizers/cicids_normalizer.py
#
# PURPOSE:
#   Reads raw CICIDS2017 CSV rows and converts each row into
#   a standard normalized Python dictionary that Elasticsearch
#   can store and other layers can query consistently.
#
# INPUT:
#   One raw row from CICIDS2017 CSV as a Python dict
#   Example raw row keys:
#   "Destination Port", "Flow Duration", "Label" etc.
#
# OUTPUT:
#   One normalized Python dict with standard field names
#   that every layer in SentinelAI understands
#
# AUTHOR: rk
# PROJECT: SentinelAI
# ============================================================

import pandas as pd
from datetime import datetime


# ============================================================
# LABEL → SEVERITY MAPPING DOCUMENTATION
# ============================================================
# Every row in CICIDS2017 has a "Label" column.
# Your normalizer reads that label and derives a severity.
#
# Label value                    Severity    Reason
# ─────────────────────────────  ──────────  ──────────────────
# "BENIGN"                    →  "none"      Normal traffic
#                                            No threat
#
# "Web Attack  Brute Force"   →  "high"      Attacker trying
#                                            many passwords
#                                            fast to break in
#
# "Web Attack  XSS"           →  "high"      Cross-site
#                                            scripting attack
#                                            injects malicious
#                                            scripts into pages
#
# "Web Attack  Sql Injection" →  "critical"  Most dangerous —
#                                            attacker can read
#                                            or delete entire
#                                            bank database
#
# anything else unknown       →  "medium"    Unknown pattern,
#                                            treat with caution
# ============================================================


def normalize_cicids_row(row: dict) -> dict:
    """
    Converts ONE raw CICIDS2017 CSV row (as dict) into
    the SentinelAI standard normalized schema.

    Parameters:
        row (dict): One row from CICIDS2017 CSV.
                    Keys are the original column names.

    Returns:
        dict: Normalized event ready for Elasticsearch.
    """

    # ── STEP 1: Read the Label column ───────────────────────
    # .get("Label", "BENIGN") means:
    #   → try to read the "Label" key from row
    #   → if "Label" key is missing, use "BENIGN" as default
    # .strip() removes any accidental spaces around the value
    label = str(row.get("Label", "BENIGN")).strip()

    # ── STEP 2: Derive severity from label ──────────────────
    # We check what the label says and assign a severity level.
    # "in" checks if a word appears anywhere inside the label.
    # Example: "Sql Injection" in "Web Attack  Sql Injection"
    #          → True
    if label == "BENIGN":
        severity = "none"

    elif "Sql Injection" in label:
        # SQL Injection is critical — attacker can access
        # or destroy the entire database
        severity = "critical"

    elif "Brute Force" in label:
        # Brute force is high — attacker is hammering
        # login/auth with thousands of password attempts
        severity = "high"

    elif "XSS" in label:
        # Cross-site scripting is high — malicious scripts
        # injected into web pages to steal user sessions
        severity = "high"

    else:
        # Unknown label — treat cautiously as medium
        severity = "medium"

    # ── STEP 3: Build and return the normalized dict ────────
    # Every field below is documented with:
    # → where it comes from (which CICIDS2017 column)
    # → what it means
    # → what default value to use if column is missing

    return {

        # ── IDENTITY FIELDS ──────────────────────────────────

        # Current time in ISO format: "2026-06-14T10:30:00"
        # CICIDS2017 has no timestamp column so we use now()
        "timestamp": datetime.utcnow().isoformat(),

        # Which dataset this event came from
        # Always "cicids2017" for this normalizer
        "log_source": "cicids2017",

        # The attack type — directly from Label column
        # Values: BENIGN / Web Attack Brute Force /
        #         Web Attack XSS / Web Attack Sql Injection
        "attack_type": label,

        # Severity derived from label in Step 2 above
        # Values: none / high / critical / medium
        "severity": severity,

        # What type of log event this is
        # Always "network_flow" for CICIDS2017
        # because CICIDS2017 captures network flows not logins
        "action": "network_flow",

        # Network protocol — always TCP in CICIDS2017
        "protocol": "TCP",

        # CICIDS2017 does not contain source IP or dest IP
        # It is a flow statistics dataset not packet capture
        # So both are None (null in JSON)
        "source_ip": None,
        "dest_ip":   None,


        # ── KEY FLOW FIELDS ───────────────────────────────────

        # From column: "Destination Port"
        # The port being attacked
        # Port 80=HTTP, 443=HTTPS, 22=SSH, 3306=MySQL
        # Default 0 if missing
        # int() converts to integer — ports are whole numbers
        "dest_port": int(row.get("Destination Port", 0)),

        # From column: "Flow Duration"
        # How long the network connection lasted
        # Unit: microseconds
        # Very long = slow data exfiltration
        # Very short + high packets = DDoS
        "flow_duration": float(row.get("Flow Duration", 0)),

        # From column: "Total Fwd Packets"
        # Packets sent from attacker → target
        # High number = active attack sending lots of data
        "total_fwd_pkts": int(row.get("Total Fwd Packets", 0)),

        # From column: "Total Backward Packets"
        # Packets sent from target → attacker
        # Low backward packets = target not responding = DDoS
        "total_bwd_pkts": int(row.get("Total Backward Packets", 0)),

        # From column: "Flow Bytes/s"
        # Data transfer rate in bytes per second
        # Extremely high = DDoS flooding the network
        "flow_bytes_s": float(row.get("Flow Bytes/s", 0)),

        # From column: "Flow Packets/s"
        # Packets per second rate
        # Extremely high = DDoS or port scan
        "flow_pkts_s": float(row.get("Flow Packets/s", 0)),


        # ── ML FEATURES FOR PyOD (Layer 2) ───────────────────
        # These fields are used ONLY by the anomaly detection
        # model (PyOD) in Layer 2.
        # They are stored as a nested object to keep them
        # separate from the identity/metadata fields above.

        "ml_features": {

            # From column: "Packet Length Mean"
            # Average size of packets in bytes
            # Unusually small = DDoS with tiny flood packets
            "pkt_len_mean": float(row.get("Packet Length Mean", 0)),

            # From column: "Packet Length Std"
            # How much packet sizes vary
            # Very low std = automated attack (all same size)
            "pkt_len_std": float(row.get("Packet Length Std", 0)),

            # From column: "Packet Length Variance"
            # Variance of packet sizes
            # Related to std — confirms size consistency
            "pkt_len_variance": float(
                row.get("Packet Length Variance", 0)
            ),

            # From column: "SYN Flag Count"
            # TCP SYN packets — used to start connections
            # High SYN + low ACK = SYN flood DDoS attack
            "syn_flag_count": int(row.get("SYN Flag Count", 0)),

            # From column: "FIN Flag Count"
            # TCP FIN packets — used to end connections
            # Normal in benign traffic
            "fin_flag_count": int(row.get("FIN Flag Count", 0)),

            # From column: "ACK Flag Count"
            # TCP ACK packets — acknowledgements
            # High ACK without SYN = ACK flood attack
            "ack_flag_count": int(row.get("ACK Flag Count", 0)),

            # From column: "RST Flag Count"
            # TCP RST — connection resets
            # High RST = port scanning or connection refused
            "rst_flag_count": int(row.get("RST Flag Count", 0)),

            # From column: "Flow IAT Mean"
            # IAT = Inter-Arrival Time between packets
            # Mean time gap between packets in microseconds
            # Very low IAT = flooding attack
            "flow_iat_mean": float(row.get("Flow IAT Mean", 0)),

            # From column: "Flow IAT Std"
            # How much the inter-arrival times vary
            # Very low std = automated tool (regular intervals)
            "flow_iat_std": float(row.get("Flow IAT Std", 0)),

            # From column: "Fwd IAT Mean"
            # Mean inter-arrival time in forward direction
            # Attacker → Target timing pattern
            "fwd_iat_mean": float(row.get("Fwd IAT Mean", 0)),

            # From column: "Bwd IAT Mean"
            # Mean inter-arrival time in backward direction
            # Target → Attacker response timing
            "bwd_iat_mean": float(row.get("Bwd IAT Mean", 0)),

            # From column: "Init_Win_bytes_forward"
            # TCP initial window size from attacker side
            # Unusual window sizes = OS fingerprinting attack
            "init_win_fwd": int(
                row.get("Init_Win_bytes_forward", 0)
            ),

            # From column: "Init_Win_bytes_backward"
            # TCP initial window size from target side
            "init_win_bwd": int(
                row.get("Init_Win_bytes_backward", 0)
            ),

            # From column: "Active Mean"
            # Mean time the flow was active sending data
            # Unit: microseconds
            "active_mean": float(row.get("Active Mean", 0)),

            # From column: "Idle Mean"
            # Mean time the flow was idle (no data)
            # Very long idle = slow exfiltration attack
            "idle_mean": float(row.get("Idle Mean", 0)),

            # From column: "Fwd Packet Length Max"
            # Largest packet sent by attacker
            # Very large = data exfiltration attempt
            "fwd_pkt_len_max": float(
                row.get("Fwd Packet Length Max", 0)
            ),

            # From column: "Fwd Packet Length Min"
            # Smallest packet sent by attacker
            "fwd_pkt_len_min": float(
                row.get("Fwd Packet Length Min", 0)
            ),

            # From column: "Bwd Packet Length Max"
            # Largest response packet from target
            "bwd_pkt_len_max": float(
                row.get("Bwd Packet Length Max", 0)
            ),

            # From column: "Bwd Packet Length Min"
            # Smallest response packet from target
            "bwd_pkt_len_min": float(
                row.get("Bwd Packet Length Min", 0)
            ),
        }
    }


# ============================================================
# FUNCTION: normalize_cicids_file
# PURPOSE:  Reads entire CICIDS2017 CSV file and returns
#           list of normalized dicts ready for Elasticsearch
# ============================================================

def normalize_cicids_file(filepath: str) -> list:
    """
    Reads a CICIDS2017 CSV file and normalizes every row.

    Parameters:
        filepath (str): Path to the CSV file

    Returns:
        list: List of normalized dicts
    """
    normalized = []

    print(f"[CICIDS] Reading: {filepath}")

    # chunksize=10000 means read 10000 rows at a time
    # This prevents RAM crash on large files
    for chunk in pd.read_csv(filepath, chunksize=10000):

        # Remove spaces from column names
        # Fixes " Label" → "Label"
        chunk.columns = chunk.columns.str.strip()

        # Skip rows where Label column is empty
        chunk = chunk.dropna(subset=["Label"])

        # Normalize each row one by one
        for _, row in chunk.iterrows():
            normalized.append(
                normalize_cicids_row(row.to_dict())
            )

    print(f"[CICIDS] Done — {len(normalized)} records normalized")
    return normalized