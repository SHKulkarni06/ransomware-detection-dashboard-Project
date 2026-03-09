from collections import defaultdict
from datetime import datetime
import csv
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

# Store behavior per source IP
traffic_stats = defaultdict(lambda: {
    "packet_count": 0,
    "total_bytes": 0,
    "protocols": set(),
    "first_seen": None,
    "last_seen": None
})

def extract_features(packet):
    """
    Extract real-time features from live PyShark packet
    """
    try:
        if not hasattr(packet, "ip"):
            return

        src_ip = packet.ip.src
        protocol = packet.highest_layer
        size = int(packet.length)
        now = datetime.now()

        stats = traffic_stats[src_ip]

        if stats["first_seen"] is None:
            stats["first_seen"] = now

        stats["packet_count"] += 1
        stats["total_bytes"] += size
        stats["protocols"].add(protocol)
        stats["last_seen"] = now

    except Exception:
        pass


def get_summary():
    """
    Returns live traffic behavior summary
    """
    summaries = []

    for ip, stats in traffic_stats.items():
        duration = (
            (stats["last_seen"] - stats["first_seen"]).total_seconds()
            if stats["first_seen"] and stats["last_seen"]
            else 1
        )

        avg_size = stats["total_bytes"] / stats["packet_count"]
        packet_rate = stats["packet_count"] / duration

        summaries.append({
            "ip": ip,
            "packet_count": stats["packet_count"],
            "avg_packet_size": round(avg_size, 2),
            "packet_rate": round(packet_rate, 2),
            "protocols": list(stats["protocols"]),
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"]
        })

    return summaries


def save_features_to_csv(filename="data/network_features.csv"):
    """
    Save learned behavior to CSV on exit
    """
    os.makedirs("data", exist_ok=True)

    sorted_ips = sorted(
        traffic_stats.items(),
        key=lambda x: x[1]["packet_count"],
        reverse=True
    )

    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Source IP",
            "Packet Count",
            "Average Packet Size",
            "Packet Rate",
            "Protocols Used",
            "First Seen",
            "Last Seen"
        ])

        for ip, stats in sorted_ips:
            duration = (
                (stats["last_seen"] - stats["first_seen"]).total_seconds()
                if stats["first_seen"] and stats["last_seen"]
                else 1
            )

            avg_size = stats["total_bytes"] / stats["packet_count"]
            packet_rate = stats["packet_count"] / duration

            writer.writerow([
                ip,
                stats["packet_count"],
                round(avg_size, 2),
                round(packet_rate, 2),
                ",".join(stats["protocols"]),
                stats["first_seen"],
                stats["last_seen"]
            ])

    print(f"[+] Features saved to {filename}")
