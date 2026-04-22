"""
features/feature_extractor.py
==============================
Stateful network feature aggregator.

Consumes raw PyShark packets and maintains per-source-IP
traffic statistics. Exposes get_summary() for detection modules
and save_features_to_csv() for persistence on shutdown.
"""

import csv
import os
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# In-memory traffic stats (reset on process restart)                   #
# ------------------------------------------------------------------ #
# Structure per IP:
#   packet_count, total_bytes, protocols (set),
#   first_seen (datetime), last_seen (datetime)

_traffic_stats: Dict[str, dict] = defaultdict(lambda: {
    "packet_count": 0,
    "total_bytes": 0,
    "protocols": set(),
    "first_seen": None,
    "last_seen": None,
})


# ------------------------------------------------------------------ #
# Feature extraction                                                   #
# ------------------------------------------------------------------ #

def extract_features(packet) -> None:
    """
    Parse a single PyShark packet and update the IP stats table.
    Silently drops packets without an IP layer.
    """
    try:
        if not hasattr(packet, "ip"):
            return

        src_ip: str = packet.ip.src
        protocol: str = packet.highest_layer
        size: int = int(packet.length)
        now: datetime = datetime.now()

        stats = _traffic_stats[src_ip]

        if stats["first_seen"] is None:
            stats["first_seen"] = now

        stats["packet_count"] += 1
        stats["total_bytes"] += size
        stats["protocols"].add(protocol)
        stats["last_seen"] = now

    except Exception as exc:
        logger.debug(f"Feature extraction error: {exc}")


# ------------------------------------------------------------------ #
# Summary for detection modules                                        #
# ------------------------------------------------------------------ #

def get_summary() -> List[dict]:
    """
    Compute derived metrics for every tracked IP.

    Returns a list of feature dicts:
        ip, packet_count, avg_packet_size,
        packet_rate (pkts/sec), protocols (list),
        first_seen, last_seen
    """
    summaries = []

    for ip, stats in _traffic_stats.items():
        if stats["first_seen"] is None:
            continue

        duration = max(
            (stats["last_seen"] - stats["first_seen"]).total_seconds(),
            1  # avoid division by zero for single-packet bursts
        )

        avg_size = stats["total_bytes"] / stats["packet_count"]
        packet_rate = stats["packet_count"] / duration

        summaries.append({
            "ip": ip,
            "packet_count": stats["packet_count"],
            "avg_packet_size": round(avg_size, 2),
            "packet_rate": round(packet_rate, 4),
            "protocols": list(stats["protocols"]),
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
        })

    return summaries


# ------------------------------------------------------------------ #
# CSV persistence                                                      #
# ------------------------------------------------------------------ #

def save_features_to_csv(filename: str = "data/network_features.csv") -> None:
    """
    Save aggregated traffic stats to CSV.
    Called on graceful shutdown of the capture module.
    """
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)

    sorted_ips = sorted(
        _traffic_stats.items(),
        key=lambda x: x[1]["packet_count"],
        reverse=True,
    )

    with open(filename, mode="w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "source_ip", "packet_count", "avg_packet_size_bytes",
            "packet_rate_per_sec", "protocols", "first_seen", "last_seen"
        ])

        for ip, stats in sorted_ips:
            if stats["first_seen"] is None:
                continue

            duration = max(
                (stats["last_seen"] - stats["first_seen"]).total_seconds(), 1
            )
            avg_size = stats["total_bytes"] / stats["packet_count"]
            packet_rate = stats["packet_count"] / duration

            writer.writerow([
                ip,
                stats["packet_count"],
                round(avg_size, 2),
                round(packet_rate, 4),
                ",".join(stats["protocols"]),
                stats["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                stats["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            ])

    logger.info(f"Network features saved to {filename}")
    print(f"[+] Features saved to {filename}")