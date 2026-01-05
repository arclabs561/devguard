# Email History Persistence & Introspection

## Overview

The unified email system now preserves **all reasoning, metadata, and context** for long-term analysis and agent introspection. Nothing evaporates.

## What's Preserved

### Core Alert Information
- **Timestamp**: ISO 8601 format
- **Subject**: Email subject line
- **Author**: Source agent (guardian, sre-agent, watchdog, etc.)
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **Topic**: Normalized topic for threading
- **Thread ID**: For email threading
- **Message Preview**: First 500 characters of message

### Report Metadata
- **Summary**: Complete report summary
  - Critical vulnerabilities count
  - High findings count
  - Unhealthy deployments count
  - Total vulnerabilities
  - Failed checks
  - Total checks
- **Issues**: Top 5 issues per category
  - Critical vulnerabilities (package, version, CVE, severity)
  - Critical findings (title, resource, check_type)
  - High findings (title, resource, check_type)
  - Unhealthy deployments (platform, project, status)
- **Actionable**: Whether report had actionable issues

### LLM Reasoning (if enabled)
- **LLM Decision**: Complete LLM decision object
  - `should_send`: Boolean decision
  - `reasoning`: Explanation for decision
  - `priority`: Priority level (critical/high/medium/low)
  - `summary`: Executive summary
- **LLM Reasoning**: Detailed reasoning breakdown
  - Decision factors
  - Context considered
  - Alert fatigue analysis

### Alert Context
- **Occurrence Count**: How many times this topic alerted
- **Trend**: increasing/decreasing/stable
- **Recurring**: Whether this is a recurring issue
- **Last Alert**: Hours since last alert for this topic

### Report Details
- **Report Summary**: Full report statistics
- **Check Types**: List of check types run
- **Report Timestamp**: When report was generated
- **Message ID**: Email message ID for threading
- **In-Reply-To**: Threading reference

### Full Metadata
- **Complete metadata JSON**: Everything stored for deep analysis
  - All above fields
  - Any additional context from agents
  - Stigmergy signals (if available)
  - Colleague context (if available)

## Storage Locations

### 1. SQLite Database (Primary - when USE_SMART_EMAIL=true)

**Location**: `/data/smart_email.db` (or `SMART_EMAIL_DB` env var)

**Table**: `alert_history`

**Schema**:
```sql
CREATE TABLE alert_history (
    id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    severity TEXT,
    subject TEXT,
    sent_at TEXT NOT NULL,
    thread_id TEXT,
    occurrence_count INTEGER DEFAULT 1,
    resolved_at TEXT,
    author TEXT,
    message_preview TEXT,
    metadata_json TEXT  -- JSON with ALL metadata
)
```

**Indexes**:
- `idx_alert_topic` - Fast topic queries
- `idx_alert_sent` - Fast time-based queries
- `idx_alert_author` - Fast author-based queries

### 2. JSON File (Fallback - Guardian only)

**Location**: `.guardian-email-history.json` (or `EMAIL_HISTORY_FILE` env var)

**Format**: Array of email entries (last 100)

**Used when**: `USE_SMART_EMAIL=false` or smart_email unavailable

## Introspection Methods

### 1. Python API

```python
from guardian.reporting import Reporter
from guardian.config import get_settings

settings = get_settings()
reporter = Reporter(settings)

# Get recent history
history = reporter.get_email_history(limit=10)

# Each entry contains:
# - timestamp, subject, author, severity
# - summary, issues, llm_decision
# - message_preview, full_metadata
```

### 2. MCP Tools

```python
from guardian.mcp_server import get_email_history, get_unified_alert_history

# Guardian history (or unified if smart_email enabled)
history = await get_email_history(limit=10)

# Unified history (all agents + Guardian)
unified = await get_unified_alert_history(limit=20, topic="security_posture")
```

### 3. Direct SQLite Query

```python
import sqlite3
import json

conn = sqlite3.connect("/data/smart_email.db")

# Get all Guardian alerts with LLM reasoning
rows = conn.execute("""
    SELECT subject, sent_at, metadata_json
    FROM alert_history
    WHERE author = 'guardian'
    AND metadata_json LIKE '%llm_decision%'
    ORDER BY sent_at DESC
    LIMIT 10
""").fetchall()

for row in rows:
    subject, sent_at, metadata_json = row
    metadata = json.loads(metadata_json)
    llm_decision = metadata.get("llm_decision", {})
    print(f"{sent_at}: {subject}")
    print(f"  LLM Reasoning: {llm_decision.get('reasoning', 'N/A')}")
```

## Analysis Use Cases

### 1. Alert Pattern Analysis

```python
# Find recurring issues
conn.execute("""
    SELECT topic, COUNT(*) as count, 
           MIN(sent_at) as first_seen, 
           MAX(sent_at) as last_seen
    FROM alert_history
    GROUP BY topic
    HAVING count > 3
    ORDER BY count DESC
""")
```

### 2. LLM Decision Analysis

```python
# Analyze LLM decision quality
import json

rows = conn.execute("""
    SELECT metadata_json
    FROM alert_history
    WHERE metadata_json LIKE '%llm_decision%'
""").fetchall()

decisions = []
for row in rows:
    metadata = json.loads(row[0])
    llm = metadata.get("llm_decision", {})
    decisions.append({
        "should_send": llm.get("should_send"),
        "priority": llm.get("priority"),
        "reasoning": llm.get("reasoning"),
    })
```

### 3. Alert Fatigue Detection

```python
# Find topics with high alert frequency
conn.execute("""
    SELECT topic, 
           COUNT(*) as alert_count,
           COUNT(*) * 1.0 / 
           (JULIANDAY(MAX(sent_at)) - JULIANDAY(MIN(sent_at)) + 1) as alerts_per_day
    FROM alert_history
    WHERE sent_at >= datetime('now', '-7 days')
    GROUP BY topic
    HAVING alerts_per_day > 2
    ORDER BY alerts_per_day DESC
""")
```

### 4. Cross-Agent Analysis

```python
# Compare Guardian vs SRE Agent alerts
conn.execute("""
    SELECT author, 
           COUNT(*) as count,
           AVG(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_rate
    FROM alert_history
    WHERE sent_at >= datetime('now', '-30 days')
    GROUP BY author
""")
```

## Testing

Run the test script to verify persistence:

```bash
cd guardian
ALERT_EMAIL=your@email.com \
USE_SMART_EMAIL=true \
uv run python test_email_history.py
```

The script will:
1. Generate a test report
2. Send email (if configured)
3. Verify history is stored
4. Check all metadata is preserved
5. Test introspection methods

## Migration

Existing databases are automatically migrated:
- `author` column added if missing
- `message_preview` column added if missing
- Existing data preserved

## Data Retention

- **SQLite**: Unlimited (database grows over time)
- **JSON**: Last 100 entries (trimmed automatically)

For long-term analysis, use SQLite. For quick introspection, use JSON or MCP tools.

## Best Practices

1. **Always use SQLite** when `USE_SMART_EMAIL=true` for complete history
2. **Query by author** to filter by source agent
3. **Use metadata_json** for deep analysis (contains everything)
4. **Index on sent_at** for time-based queries
5. **Archive old data** periodically if database grows too large

## Example Queries

### Find all alerts with LLM reasoning

```sql
SELECT subject, sent_at, 
       json_extract(metadata_json, '$.llm_decision.reasoning') as reasoning
FROM alert_history
WHERE metadata_json LIKE '%llm_decision%'
ORDER BY sent_at DESC;
```

### Analyze alert trends

```sql
SELECT 
    DATE(sent_at) as date,
    COUNT(*) as alerts,
    COUNT(DISTINCT topic) as unique_topics,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
FROM alert_history
WHERE sent_at >= datetime('now', '-30 days')
GROUP BY DATE(sent_at)
ORDER BY date DESC;
```

### Find unresolved issues

```sql
SELECT topic, 
       MAX(sent_at) as last_alert,
       COUNT(*) as alert_count,
       json_extract(metadata_json, '$.summary.critical_vulnerabilities') as critical_vulns
FROM alert_history
WHERE resolved_at IS NULL
GROUP BY topic
HAVING last_alert >= datetime('now', '-7 days')
ORDER BY alert_count DESC;
```

