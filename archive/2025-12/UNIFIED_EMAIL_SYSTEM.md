# Unified Email Alerting System

## Overview

The email alerting system has been unified to eliminate the dual SMTP/SNS architecture. Guardian now optionally uses the `smart_email` system (SNS) with full feature parity, while maintaining SMTP as a fallback.

## What Changed

### 1. Shared LLM Service (`ops/agent/llm_service.py`)

- Extracted LLM functionality to shared location
- Used by both Guardian and smart_email
- Supports Anthropic, OpenAI, and OpenRouter
- Provides: send decisions, subject generation, executive summaries

### 2. Guardian Integration with smart_email

- **New config option**: `USE_SMART_EMAIL=true` to enable SNS-based alerting
- **Automatic fallback**: Falls back to SMTP if smart_email fails
- **LLM support**: Guardian's LLM features work with smart_email
- **Unified history**: Guardian writes to smart_email SQLite when enabled

### 3. smart_email LLM Enhancement

- **Optional LLM subject generation**: `use_llm=True` parameter
- **Uses shared LLMService**: Consistent LLM integration
- **Backward compatible**: Existing code continues to work

### 4. Unified History Storage

- **SQLite-based**: Both systems use same database when `USE_SMART_EMAIL=true`
- **Cross-system queries**: Guardian can see agent alerts, agents can see Guardian alerts
- **JSON fallback**: Guardian still maintains JSON history for backward compatibility

### 5. Enhanced MCP Tools

- **`get_email_history()`**: Returns Guardian history (or unified if smart_email enabled)
- **`get_unified_alert_history()`**: Returns all alerts from all sources (Guardian + agents)

## Configuration

### Enable Unified System

```bash
# Guardian configuration
USE_SMART_EMAIL=true
SMART_EMAIL_DB_PATH=/data/smart_email.db  # Optional, defaults to env var
EMAIL_LLM_ENABLED=true  # Optional, enables LLM features
SNS_TOPIC_ARN=arn:aws:sns:...  # Required for SNS

# LLM API keys (for LLM features)
ANTHROPIC_API_KEY=sk-ant-...  # or OPENAI_API_KEY, OPENROUTER_API_KEY
```

### Fallback to SMTP

If `USE_SMART_EMAIL=false` or smart_email fails, Guardian uses SMTP:

```bash
SMTP_HOST=smtp.example.com
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=guardian@example.com
```

## Benefits

### Before (Dual Systems)

- ❌ Guardian: SMTP only, no batching, no deduplication
- ❌ Agents: SNS only, no LLM features
- ❌ Separate threading (emails don't group)
- ❌ Separate history (can't learn from all alerts)
- ❌ Feature asymmetry (each system missing features)

### After (Unified System)

- ✅ Guardian: Can use SNS (smart_email) with all features
- ✅ Agents: Can use LLM features via shared service
- ✅ Unified threading (all emails thread together)
- ✅ Unified history (cross-system learning)
- ✅ Feature parity (batching + LLM + rich formatting)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    UNIFIED EMAIL SYSTEM                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  GUARDIAN                                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Reporter.report()                                    │  │
│  │   ├─> LLM Decision? (shared LLMService)            │  │
│  │   ├─> smart_email? (if USE_SMART_EMAIL=true)       │  │
│  │   │    └─> smart_send_alert()                       │  │
│  │   │         ├─> LLM Subject? (optional)             │  │
│  │   │         ├─> Batching/Dedup                      │  │
│  │   │         └─> SNS                                 │  │
│  │   └─> SMTP (fallback)                               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  AGENTS                                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ send_sns_alert()                                     │  │
│  │   └─> smart_send_alert()                            │  │
│  │        ├─> LLM Subject? (optional)                   │  │
│  │        ├─> Batching/Dedup                           │  │
│  │        └─> SNS                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  SHARED SERVICES                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ LLMService (ops/agent/llm_service.py)                │  │
│  │   ├─> should_send_email()                           │  │
│  │   ├─> generate_subject_line()                       │  │
│  │   └─> generate_executive_summary()                  │  │
│  │                                                      │  │
│  │ smart_email SQLite DB                                │  │
│  │   ├─> alert_history (unified)                       │  │
│  │   ├─> email_threads                                 │  │
│  │   └─> pending_alerts                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Migration Path

### Phase 1: Enable smart_email (Optional)

```bash
# Set environment variable
export USE_SMART_EMAIL=true

# Guardian will automatically use smart_email
# Falls back to SMTP if smart_email unavailable
```

### Phase 2: Enable LLM Features (Optional)

```bash
# Set LLM API key
export ANTHROPIC_API_KEY=sk-ant-...

# Enable LLM features
export EMAIL_LLM_ENABLED=true
```

### Phase 3: Verify Unified History

```python
# Via MCP tool
from guardian.mcp_server import get_unified_alert_history

history = await get_unified_alert_history(limit=20)
# Returns alerts from Guardian + all agents
```

## Testing

### Test Guardian with smart_email

```bash
cd guardian
USE_SMART_EMAIL=true \
SNS_TOPIC_ARN=arn:aws:sns:... \
ALERT_EMAIL=your@email.com \
uv run python -m guardian.cli
```

### Test LLM Features

```bash
USE_SMART_EMAIL=true \
EMAIL_LLM_ENABLED=true \
ANTHROPIC_API_KEY=sk-ant-... \
uv run python -m guardian.cli
```

### Verify Unified History

```python
from guardian.reporting import Reporter
from guardian.config import get_settings

settings = get_settings()
settings.use_smart_email = True
reporter = Reporter(settings)

# Should read from SQLite if smart_email enabled
history = reporter.get_email_history(limit=10)
```

## Backward Compatibility

- ✅ **SMTP still works**: If `USE_SMART_EMAIL=false`, Guardian uses SMTP as before
- ✅ **JSON history preserved**: Guardian maintains JSON history file for compatibility
- ✅ **Existing agents unchanged**: smart_email API unchanged, existing code works
- ✅ **Gradual migration**: Can enable feature-by-feature

## Key Files

- `ops/agent/llm_service.py` - Shared LLM service
- `ops/agent/smart_email.py` - Enhanced with LLM support
- `guardian/guardian/reporting.py` - Updated to use smart_email
- `guardian/guardian/config.py` - New config options
- `guardian/guardian/mcp_server.py` - Unified history tools

## Next Steps

1. **Enable in production**: Set `USE_SMART_EMAIL=true` on alakazam
2. **Monitor**: Check that emails thread properly
3. **Verify history**: Confirm unified history is working
4. **Deprecate JSON**: Once confident, can remove JSON history (optional)

