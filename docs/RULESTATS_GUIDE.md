# Rule Statistics — HomeLab SIEM

The Rule Statistics feature provides insights into which detection rules are firing most often, helping SOC engineers identify noisy rules and tune their detection engine.

## Overview

The Rule Stats dashboard shows:
- **Total Rules** — Number of rules configured in the SIEM
- **Most Firing Rule** — The rule that triggered the most alerts
- **Rules Fired** — How many unique rules have generated alerts
- **Average Firing** — Mean alerts per rule

## API Endpoint

```
GET /api/rules/stats
```

Returns JSON array of rule statistics:

```json
[
  {
    "rule_id": "WEB-003",
    "rule_name": "SQL Injection Attempt",
    "severity": "HIGH",
    "firing_count": 1069
  },
  ...
]
```

## Usage

### 1. Navigate to Dashboard

Visit `http://localhost:5000/` and click **Rule Stats** in the sidebar (under Config).

### 2. View Statistics

The page loads automatically from `/api/rules/stats` and displays:
- KPI cards at the top
- Filterable table of all rules that have fired
- Effectiveness bars showing relative firing frequency

### 3. Filter by Severity

Click severity filter buttons (CRITICAL, HIGH, MEDIUM, LOW) to focus on specific severities.

## Implementation Details

### Backend

- **`siem/storage.py`**: `get_rule_stats()` queries the alerts table grouped by `rule_id`
- **`app.py`**: `/api/rules/stats` endpoint exposes API

### Frontend

- **`templates/dashboard.html`**: New "Rule Stats" tab with JavaScript functions:
  - `loadRuleStats()` — Fetches and renders statistics
  - `renderRuleStats()` — Renders the table
  - `filterRuleStats()` — Filters by severity

## Use Cases

1. **Rule Tuning** — Identify rules that fire too often (noise) and adjust thresholds
2. **Threat Hunting** — Focus on frequently-fired rules to find active campaigns
3. **Coverage Analysis** — Ensure all categories of rules are firing
4. **SOC Reporting** — Show executives which threats are most common

## Requirements

- Alerts must be generated for statistics to appear
- The SQLite database stores alert history in `data/siem.db`
