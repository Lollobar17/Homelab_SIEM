"""
siem/arachne_rules.py — Detection rules for ArachneC2 C2 simulator events.
"""

ARACHNE_RULES = [
    {
        "id": "ARC-001",
        "name": "ArachneC2: C2 Beacon Detected",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1071.001",
        "description": "Periodic C2 beacon over HTTP with jitter",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "c2_beacon"
        ),
    },
    {
        "id": "ARC-002",
        "name": "ArachneC2: Domain Fronting / Host Header Spoofing",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1090.004",
        "description": "C2 beacon using mimic domain in Host header",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "c2_beacon"
            and bool(e.get("fields", {}).get("mimic_domain"))
        ),
    },
    {
        "id": "ARC-003",
        "name": "ArachneC2: Successful C2 Channel Established",
        "severity": "CRITICAL",
        "category": "c2_communication",
        "mitre": "T1071.001",
        "description": "C2 beacon received HTTP 200 — active channel confirmed",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "c2_beacon"
            and e.get("fields", {}).get("success") is True
        ),
    },
    {
        "id": "ARC-004",
        "name": "ArachneC2: Encrypted C2 Message (NaCl/Ed25519)",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1573.001",
        "description": "Encrypted and signed C2 beacon",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "c2_beacon"
            and e.get("fields", {}).get("encrypted") is True
            and e.get("fields", {}).get("signed") is True
        ),
    },
    {
        "id": "ARC-005",
        "name": "ArachneC2: DHT Peer Discovery",
        "severity": "MEDIUM",
        "category": "c2_communication",
        "mitre": "T1090.003",
        "description": "Kademlia DHT peer discovery — decentralized C2",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "dht_discovery"
        ),
    },
    {
        "id": "ARC-006",
        "name": "ArachneC2: GossipSub Message Propagation",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1071",
        "description": "GossipSub PubSub — C2 commands through mesh network",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "gossipsub_message"
        ),
    },
    {
        "id": "ARC-007",
        "name": "ArachneC2: NAT Traversal / Hole Punching",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1090",
        "description": "libp2p hole punching — bypassing NAT/firewall",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "nat_traversal"
        ),
    },
    {
        "id": "ARC-008",
        "name": "ArachneC2: Circuit Relay Usage",
        "severity": "HIGH",
        "category": "c2_communication",
        "mitre": "T1090.003",
        "description": "libp2p circuit relay — C2 through relay nodes",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "nat_traversal"
            and "relay" in str(e.get("fields", {}).get("protocol", "")).lower()
        ),
    },
    {
        "id": "ARC-009",
        "name": "ArachneC2: P2P Heartbeat",
        "severity": "MEDIUM",
        "category": "c2_communication",
        "mitre": "T1090",
        "description": "P2P heartbeat between implant nodes",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "peer_communication"
            and e.get("fields", {}).get("message_type") == "heartbeat"
        ),
    },
    {
        "id": "ARC-010",
        "name": "ArachneC2: Lateral Movement Detected",
        "severity": "CRITICAL",
        "category": "c2_communication",
        "mitre": "T1021",
        "description": "C2 implant scanning internal network",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "lateral_movement"
        ),
    },
    {
        "id": "ARC-011",
        "name": "ArachneC2: Successful Lateral Movement",
        "severity": "CRITICAL",
        "category": "c2_communication",
        "mitre": "T1021",
        "description": "C2 implant successfully reached internal host",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "lateral_movement"
            and e.get("fields", {}).get("success") is True
        ),
    },
    {
        "id": "ARC-012",
        "name": "ArachneC2: Data Exfiltration in Progress",
        "severity": "CRITICAL",
        "category": "exfiltration",
        "mitre": "T1048",
        "description": "Chunked data exfiltration to external IP",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "data_exfiltration"
        ),
    },
    {
        "id": "ARC-013",
        "name": "ArachneC2: Large Exfiltration Campaign",
        "severity": "CRITICAL",
        "category": "exfiltration",
        "mitre": "T1048.003",
        "description": "Multi-chunk exfiltration — more than 3 chunks",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "data_exfiltration"
            and int(e.get("fields", {}).get("total_chunks", 0)) > 3
        ),
    },
    {
        "id": "ARC-014",
        "name": "ArachneC2: Exfiltration via Encrypted Channel",
        "severity": "CRITICAL",
        "category": "exfiltration",
        "mitre": "T1048.002",
        "description": "Exfiltration disguised as encrypted web traffic",
        "match": lambda e: (
            e.get("source") == "arachne_c2"
            and e.get("event_type") == "data_exfiltration"
            and e.get("fields", {}).get("mimetype") in [
                "application/octet-stream", "application/zip"
            ]
        ),
    },
]
