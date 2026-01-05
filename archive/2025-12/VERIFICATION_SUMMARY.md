# Email System Verification Summary

## What Was Enhanced

### 1. Comprehensive Metadata Storage

**Before**: Only basic context (occurrence counts, trends) was stored.

**After**: Complete preservation of:
- ✅ LLM decisions and reasoning
- ✅ Full report summaries
- ✅ All issue details (top 5 per category)
- ✅ Message previews (first 500 chars)
- ✅ Author attribution
- ✅ Report timestamps
- ✅ Check types run
- ✅ Actionable issue flags
- ✅ Complete metadata JSON for deep analysis

### 2. Database Schema Enhancement

**Added columns**:
- `author` - Source agent (guardian, sre-agent, etc.)
- `message_preview` - First 500 chars for quick reference

**Migration**: Automatic - existing databases upgraded on first use.

### 3. Rich Metadata Parameter

**New parameter**: `rich_metadata` in `smart_send_alert()`

Allows passing additional context:
- LLM decisions
- Report summaries
- Reasoning traces
- Stigmergy signals
- Colleague context

### 4. Enhanced Introspection

**MCP Tools**:
- `get_email_history()` - Returns full metadata including LLM reasoning
- `get_unified_alert_history()` - Returns all alerts with complete metadata

**Python API**:
- `Reporter.get_email_history()` - Returns entries with `full_metadata` field

**Direct SQLite**:
- Query `metadata_json` column for complete data
- Indexed on `author`, `topic`, `sent_at` for fast queries

## Verification Checklist

### ✅ Metadata Preservation

- [x] LLM decisions stored in `metadata_json`
- [x] Report summaries preserved
- [x] Issue details (top 5) stored
- [x] Message previews saved
- [x] Author attribution recorded
- [x] Full metadata JSON available

### ✅ Database Schema

- [x] `author` column added
- [x] `message_preview` column added
- [x] Migration handles existing databases
- [x] Indexes created for fast queries

### ✅ Introspection Methods

- [x] Python API (`Reporter.get_email_history()`)
- [x] MCP tools (`get_email_history`, `get_unified_alert_history`)
- [x] Direct SQLite queries
- [x] JSON fallback (Guardian only)

### ✅ Cross-System Integration

- [x] Guardian writes to SQLite when `USE_SMART_EMAIL=true`
- [x] Agents can read Guardian history
- [x] Guardian can read agent history
- [x] Unified query interface

## Testing

Run the test script:

```bash
cd guardian
ALERT_EMAIL=your@email.com \
USE_SMART_EMAIL=true \
EMAIL_LLM_ENABLED=true \
ANTHROPIC_API_KEY=sk-ant-... \
uv run python test_email_history.py
```

Expected output:
- ✓ Report generated
- ✓ History retrieved (before/after)
- ✓ Metadata preserved
- ✓ LLM decision stored
- ✓ Unified history accessible

## Example: Querying History

### Get all Guardian alerts with LLM reasoning

```python
import sqlite3
import json

conn = sqlite3.connect("/data/smart_email.db")

rows = conn.execute("""
    SELECT subject, sent_at, metadata_json
    FROM alert_history
    WHERE author = 'guardian'
    AND metadata_json LIKE '%llm_decision%'
    ORDER BY sent_at DESC
    LIMIT 10
""").fetchall()

for subject, sent_at, metadata_json in rows:
    metadata = json.loads(metadata_json)
    llm = metadata.get("llm_decision", {})
    print(f"{sent_at}: {subject}")
    print(f"  Should send: {llm.get('should_send')}")
    print(f"  Reasoning: {llm.get('reasoning')}")
    print(f"  Priority: {llm.get('priority')}")
```

### Analyze alert patterns

```python
# Find recurring issues
rows = conn.execute("""
    SELECT topic, 
           COUNT(*) as count,
           json_extract(metadata_json, '$.summary.critical_vulnerabilities') as critical_vulns
    FROM alert_history
    WHERE sent_at >= datetime('now', '-30 days')
    GROUP BY topic
    HAVING count > 3
    ORDER BY count DESC
""").fetchall()
```

### Cross-agent analysis

```python
# Compare Guardian vs SRE Agent
rows = conn.execute("""
    SELECT author,
           COUNT(*) as total,
           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical
    FROM alert_history
    WHERE sent_at >= datetime('now', '-7 days')
    GROUP BY author
""").fetchall()
```

## Data Retention

- **SQLite**: Unlimited (grows over time)
- **JSON**: Last 100 entries (auto-trimmed)

For long-term analysis, use SQLite. It preserves everything forever.

## Next Steps

1. **Run test script** to verify in your environment
2. **Enable in production**: Set `USE_SMART_EMAIL=true`
3. **Query history** to analyze patterns
4. **Build dashboards** using SQLite data
5. **Archive old data** periodically if needed

## Files Modified

- `ops/agent/smart_email.py` - Enhanced metadata storage
- `guardian/guardian/reporting.py` - Comprehensive metadata recording
- `guardian/guardian/mcp_server.py` - Enhanced introspection tools
- `guardian/test_email_history.py` - Test script
- `guardian/HISTORY_PERSISTENCE.md` - Documentation

