# AZURE_INTEGRATION.md
# Phase 1 — Azure NSG Flow Logs → HomeLab SIEM
# Complete integration guide

---

## Architecture

```
[Azure VM] → [NSG Flow Logs] → [Storage Account: homelabsiemflow]
                                          ↓
                               [azure_collector.py]
                                          ↓
                               POST /api/ingest
                                          ↓
                         [HomeLab SIEM — app.py]
                         parse_log_line() → analyze_event()
                         AZURE_RULES (azure/azure_rules.py)
                                          ↓
                         [Dashboard + SQLite + Discord]
```

---

## Resources created in Azure

| Resource | Name | Type |
|---|---|---|
| Resource Group | homelab-siem-rg | Container for all resources |
| Virtual Machine | homelab-vm | Ubuntu 24.04, Standard_D2s_v6 |
| Virtual Network | homelab-vm-vnet | West Europe |
| NSG | homelab-vm-nsg | Attached to VM NIC |
| Storage Account | homelabsiemflow | LRS, West Europe |
| Flow Log | homelab-vm-vnet-homelab-siem-rg-flowlog | VNet flow logging |
| Log Analytics | homelab-siem-workspace | Traffic Analytics |

---

## Project structure

```
Homelab_SIEM/
│
├── azure/
│   ├── __init__.py
│   ├── azure_collector.py      ← polls Blob Storage, sends to SIEM
│   ├── azure_rules.py          ← 7 CLOUD-* detection rules
│   └── docs/
│       └── AZURE_INTEGRATION.md
│
├── scripts/
│   ├── start_siem.sh
│   ├── stop_siem.sh
│   ├── start_azure_collector.sh
│   ├── health_check.sh
│   └── log_rotation.sh
│
├── azure_collector.py          ← entry point (imports from azure/)
└── config.json                 ← credentials and settings
```

---

## config.json required fields

```json
{
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "syslog_enabled": true,
  "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=homelabsiemflow;AccountKey=...;EndpointSuffix=core.windows.net",
  "AZURE_STORAGE_CONTAINER": "insights-logs-flowlogflowevent",
  "SIEM_INGEST_URL": "http://localhost:5000/api/v1/ingress",
  "AZURE_POLL_INTERVAL": "60"
}
```

---

## Integration in detector.py (2 lines only)

```python
# At the top of detector.py, after existing imports:
from azure.azure_rules import AZURE_RULES

# At the end of the RULES list:
RULES = RULES + AZURE_RULES
```

---

## Patch for app.py (recommended)

Modify `/api/ingest` to support pre-parsed events from azure_collector.py:

```python
@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    body = request.get_json(silent=True) or {}
    raw  = body.get("raw", "")
    if not raw:
        return jsonify({"error": "missing 'raw' field"}), 400

    # Use pre-parsed event if available (from azure_collector.py)
    pre_parsed = body.get("_pre_parsed")
    if pre_parsed and isinstance(pre_parsed, dict) and pre_parsed.get("category"):
        event = pre_parsed
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    else:
        from siem.collector import parse_log_line
        event = parse_log_line(raw, source=body.get("source", "api")) or {"fields": {}}

    alerts = analyze_event(event)
    event["alerts"] = alerts
    eid = store_event(event)
    return jsonify({"event_id": eid, "alerts": len(alerts)}), 201
```

---

## Running the stack

```bash
# Start everything
bash scripts/start_siem.sh

# Start SIEM only (no Azure collector)
bash scripts/start_siem.sh --no-azure

# Start Azure collector only
bash scripts/start_azure_collector.sh

# Stop everything
bash scripts/stop_siem.sh

# Health check
bash scripts/health_check.sh
```

---

## VM management

```powershell
# Connect to VM
ssh azureuser@74.234.142.100

# Stop VM (saves credit)
az vm deallocate --resource-group homelab-siem-rg --name homelab-vm

# Start VM
az vm start --resource-group homelab-siem-rg --name homelab-vm

# Check VM status
az vm show --resource-group homelab-siem-rg --name homelab-vm --show-details --query powerState
```

---

## Active detection rules

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CLOUD-001 | NSG: SSH REJECT from external IP | HIGH | T1110 |
| CLOUD-002 | NSG: SSH Brute Force (10+ in 5min) | CRITICAL | T1110 |
| CLOUD-003 | NSG: RDP Traffic Detected | HIGH | T1021.001 |
| CLOUD-004 | NSG: Port Scan (15+ REJECTs in 5min) | HIGH | T1046 |
| CLOUD-005 | NSG: Database Port Exposed | CRITICAL | T1190 |
| CLOUD-006 | NSG: Anomalous Outbound Volume | HIGH | T1048 |
| CLOUD-007 | NSG: Unexpected Inbound Port Allowed | MEDIUM | T1133 |

---

## Manual test (curl)

```bash
# Test CLOUD-001: SSH REJECT
curl -X POST http://localhost:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "raw": "FLOW_LOG action=REJECT src=185.220.101.45:54321 dst=10.0.0.4:22 proto=TCP direction=INBOUND nsg=homelab-vm-nsg rule=DenyAllInBound",
    "source": "azure:nsg_flow_logs",
    "_pre_parsed": {
      "category": "cloud",
      "source": "azure:nsg_flow_logs",
      "fields": {
        "src_ip": "185.220.101.45",
        "dst_port": 22,
        "action": "REJECT",
        "direction": "INBOUND",
        "protocol": "TCP",
        "nsg": "homelab-vm-nsg"
      }
    }
  }'
```

---

## AWS SAA alignment (Azure equivalent concepts)

| AWS SAA Topic | Azure Equivalent | Lab Implementation |
|---|---|---|
| Shared Responsibility Model | Shared Responsibility | Azure manages hardware, you manage NSG rules |
| IAM Least Privilege | RBAC / Service Principal | Storage account access key scoped to SIEM only |
| Security Groups (stateful) | NSG (stateful) | homelab-vm-nsg with SSH-only inbound rule |
| VPC Flow Logs | NSG Flow Logs | Enabled on homelab-vm-vnet |
| GuardDuty | Microsoft Defender for Cloud | Phase 3 |
| CloudTrail | Azure Activity Log / Monitor | Phase 2 |

---

## Next step — Phase 2

Once Flow Logs are flowing into the SIEM:
→ Enable Azure Activity Log (equivalent of CloudTrail)
→ New rule CLOUD-008: "NSG rule modified"
   MITRE: T1562.007 — Disable or Modify Cloud Firewall
