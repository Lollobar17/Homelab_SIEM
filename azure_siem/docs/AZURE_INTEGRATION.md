# AZURE_INTEGRATION.md
# Azure Cloud Integration — HomeLab SIEM
# Phase 1: VNet Flow Logs | Phase 2: Activity Log | Phase 3: Microsoft Sentinel

---

## Architecture

```
[Azure VM] ──→ [VNet Flow Logs] ──→ [Storage Account: homelabsiemflow]
                                              ↓
                                   [azure_collector.py]
                                              ↓
[Azure Activity Log] ──────────→ [Storage Account: homelabsiemflow]
                                              ↓
                                   [azure_activity_collector.py]
                                              ↓
[Microsoft Sentinel] ──────────→ [Log Analytics: homelab-siem-workspace]
                                              ↓
                                   [sentinel_collector.py]  ← KQL via REST API
                                              ↓
                              POST /api/ingest  |  POST /api/v1/ingress
                                              ↓
                                 [HomeLab SIEM — app.py]
                                 detector.py → 33 rules
                                              ↓
                            [Dashboard + SQLite + Discord]
```

---

## Azure Resources

| Resource | Name | Type |
|---|---|---|
| Resource Group | homelab-siem-rg | Container for all resources |
| Virtual Machine | homelab-vm | Ubuntu 24.04, Standard_D2s_v6, West Europe |
| Virtual Network | homelab-vm-vnet | West Europe |
| NSG | homelab-vm-nsg | Attached to VM NIC |
| Storage Account | homelabsiemflow | LRS, West Europe |
| Flow Log | homelab-vm-vnet-homelab-siem-rg-flowlog | VNet flow logging |
| Log Analytics | homelab-siem-workspace | Traffic Analytics + Sentinel |
| Diagnostic Setting | homelab-activity-logs | Admin + Security + Policy |
| Sentinel Workspace | homelab-siem-workspace | Connected to Defender portal |
| Service Principal | siem-sentinel-reader | Log Analytics Reader role |
| Sentinel Rule | homelab-vm-start | Scheduled KQL analytics rule |

---

## Project Structure

```
Homelab_SIEM/
├── azure_collector.py              ← Phase 1 entry point
├── azure_activity_collector.py     ← Phase 2 entry point
├── sentinel_collector.py           ← Phase 3 entry point
├── config.json                     ← credentials (git-ignored)
└── azure_siem/
    ├── __init__.py
    ├── azure_rules.py              ← CLOUD-001..007 (Flow Logs)
    ├── azure_activity_rules.py     ← CLOUD-008..014 (Activity Log)
    ├── sentinel/
    │   ├── __init__.py
    │   ├── sentinel_collector.py   ← KQL queries module
    │   └── sentinel_rules.py      ← SENT-001..007
    └── docs/
        └── AZURE_INTEGRATION.md
```

---

## config.json — All fields

```json
{
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "syslog_enabled": true,
  "SIEM_INGEST_URL": "http://localhost:5000/api/ingest",

  "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=homelabsiemflow;AccountKey=...;EndpointSuffix=core.windows.net",
  "AZURE_STORAGE_CONTAINER": "insights-logs-flowlogflowevent",
  "AZURE_POLL_INTERVAL": "60",

  "SENTINEL_TENANT_ID": "<your-tenant-id>",
  "SENTINEL_CLIENT_ID": "<app-registration-client-id>",
  "SENTINEL_CLIENT_SECRET": "<client-secret-value>",
  "SENTINEL_WORKSPACE_ID": "30d15ecc-8789-401c-a9bf-4a490e22b33d",
  "SENTINEL_POLL_INTERVAL": "120"
}
```

---

## Phase 1 — VNet Flow Logs

### What it does
Polls Azure Blob Storage every 60 seconds for VNet Flow Log blobs (flowLogVersion 4).
Parses ACCEPT/REJECT flows with INBOUND/OUTBOUND direction and sends structured
events to `/api/ingest`.

### Setup
1. Enable VNet Flow Logs on `homelab-vm-vnet` → destination `homelabsiemflow`
2. Add `AZURE_STORAGE_CONNECTION_STRING` to `config.json`
3. Run:
```bash
python azure_collector.py
```

### Detection rules

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CLOUD-001 | NSG: SSH REJECT from external IP | HIGH | T1110 |
| CLOUD-002 | NSG: SSH Brute Force (10+ in 5min) | CRITICAL | T1110 |
| CLOUD-003 | NSG: RDP Traffic Detected | HIGH | T1021.001 |
| CLOUD-004 | NSG: Port Scan Detected | HIGH | T1046 |
| CLOUD-005 | NSG: Database Port Exposed | CRITICAL | T1190 |
| CLOUD-006 | NSG: Anomalous Outbound Volume | HIGH | T1048 |
| CLOUD-007 | NSG: Unexpected Inbound Port Allowed | MEDIUM | T1133 |

### Manual test
```bash
curl -X POST http://localhost:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "raw": "FLOW_LOG action=REJECT src=185.220.101.45:54321 dst=10.0.0.4:22 proto=TCP direction=INBOUND nsg=homelab-vm-nsg",
    "source": "azure:nsg_flow_logs",
    "_pre_parsed": {
      "category": "cloud",
      "source": "azure:nsg_flow_logs",
      "fields": {"src_ip": "185.220.101.45", "dst_port": 22, "action": "REJECT", "direction": "INBOUND"}
    }
  }'
```

---

## Phase 2 — Azure Activity Log

### What it does
Polls `insights-activity-logs` container for NDJSON activity records.
Parses Administrative, Security and Policy categories with caller identity
extraction. Detects NSG modifications, storage key access, role assignments, etc.

### Setup
1. Create Diagnostic Setting in Azure Monitor → destination `homelabsiemflow`
   Categories: Administrative, Security, Policy
2. Run:
```bash
python azure_activity_collector.py
```

### Detection rules

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CLOUD-008 | Activity: NSG Rule Modified | HIGH | T1562.007 |
| CLOUD-009 | Activity: Storage Keys Listed | HIGH | T1552.005 |
| CLOUD-010 | Activity: Diagnostic Setting Deleted | CRITICAL | T1562.008 |
| CLOUD-011 | Activity: New Role Assignment | CRITICAL | T1098.003 |
| CLOUD-012 | Activity: VM Deleted | CRITICAL | T1485 |
| CLOUD-013 | Activity: VM Started | MEDIUM | T1078.004 |
| CLOUD-014 | Activity: API Brute Force | HIGH | T1110 |

---

## Phase 3 — Microsoft Sentinel

### What it does
Queries the Log Analytics workspace via REST API using KQL every 120 seconds.
Retrieves `SecurityAlert` and `SecurityIncident` tables generated by Sentinel
analytics rules and forwards them to the SIEM.

### Setup

#### 1. Enable Microsoft Sentinel
Portal Azure → Microsoft Sentinel → Add → select `homelab-siem-workspace`

#### 2. Connect Azure Activity data connector
Sentinel → Content hub → Data connectors → Azure Activity → Connect

#### 3. Create Service Principal
```bash
az ad app create --display-name siem-sentinel-reader
# Note the appId (CLIENT_ID)

az ad app credential reset --id <appId>
# Note the password (CLIENT_SECRET)

az role assignment create \
  --assignee <appId> \
  --role "Log Analytics Reader" \
  --scope /subscriptions/<subscription-id>/resourceGroups/homelab-siem-rg/providers/Microsoft.OperationalInsights/workspaces/homelab-siem-workspace
```

#### 4. Create Sentinel scheduled rule (PowerShell)
```powershell
$token = (az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

$body = @{
  kind = "Scheduled"
  properties = @{
    displayName = "HomeLab: VM Start Detected"
    severity = "Medium"
    enabled = $true
    query = "AzureActivity | where OperationNameValue == 'MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION'"
    queryFrequency = "PT1H"
    queryPeriod = "PT1H"
    triggerOperator = "GreaterThan"
    triggerThreshold = 0
    suppressionEnabled = $false
    suppressionDuration = "PT1H"
  }
} | ConvertTo-Json -Depth 5

$url = "https://management.azure.com/subscriptions/<subscription-id>/resourceGroups/homelab-siem-rg/providers/Microsoft.OperationalInsights/workspaces/homelab-siem-workspace/providers/Microsoft.SecurityInsights/alertRules/homelab-vm-start?api-version=2023-02-01"

Invoke-RestMethod -Uri $url -Method PUT -Headers @{Authorization = "Bearer $token"; "Content-Type" = "application/json"} -Body $body
```

#### 5. Add to config.json and run
```bash
pip install msal
python sentinel_collector.py
```

### Detection rules

| ID | Name | Severity | MITRE |
|---|---|---|---|
| SENT-001 | Sentinel: High/Critical Security Alert | HIGH | T1078 |
| SENT-002 | Sentinel: Critical Security Alert | CRITICAL | T1078 |
| SENT-003 | Sentinel: Security Incident Created | HIGH | T1078.004 |
| SENT-004 | Sentinel: Lateral Movement Detected | CRITICAL | T1021 |
| SENT-005 | Sentinel: Persistence Tactic Detected | CRITICAL | T1098 |
| SENT-006 | Sentinel: Exfiltration Tactic Detected | CRITICAL | T1048 |
| SENT-007 | Sentinel: Alert Storm (5+ in 5min) | CRITICAL | T1110 |

---

## Integration in detector.py

```python
# At the top of detector.py, after existing imports:
from azure_siem.azure_rules import AZURE_RULES
from azure_siem.azure_activity_rules import AZURE_ACTIVITY_RULES
from azure_siem.sentinel.sentinel_rules import SENTINEL_RULES

# At the end of the RULES list:
RULES = RULES + AZURE_RULES + AZURE_ACTIVITY_RULES + SENTINEL_RULES
```

---

## Running the stack

```bash
# Start everything (SIEM + all collectors)
bash scripts/bash/start_siem.sh

# Start SIEM only
bash scripts/bash/start_siem.sh --no-azure

# Start SIEM + Azure but skip Sentinel
bash scripts/bash/start_siem.sh --no-sentinel

# Stop everything
bash scripts/bash/stop_siem.sh

# Health check
bash scripts/bash/health_check.sh
```

---

## VM management

```powershell
# Connect to VM
ssh azureuser@74.234.142.100

# Stop VM (saves credit — use deallocate, not stop)
az vm deallocate --resource-group homelab-siem-rg --name homelab-vm

# Start VM
az vm start --resource-group homelab-siem-rg --name homelab-vm

# Check VM status
az vm show --resource-group homelab-siem-rg --name homelab-vm --show-details --query powerState
```

---

## AWS SAA / Security Pillar alignment

| AWS SAA Topic | Azure Equivalent | Lab Implementation |
|---|---|---|
| Shared Responsibility Model | Shared Responsibility | Azure manages hardware, you manage NSG rules |
| IAM Least Privilege | RBAC / Service Principal | siem-sentinel-reader with Log Analytics Reader only |
| Security Groups (stateful) | NSG (stateful) | homelab-vm-nsg with SSH-only inbound rule |
| VPC Flow Logs | NSG/VNet Flow Logs | Enabled on homelab-vm-vnet |
| GuardDuty | Microsoft Sentinel | Phase 3 — SecurityAlert + SecurityIncident via KQL |
| CloudTrail | Azure Activity Log | Phase 2 — NDJSON from insights-activity-logs |
| SIEM | HomeLab SIEM + Sentinel | Hybrid: local detection + cloud analytics correlation |
