# Email Alerting Design Issues

## SNS Involvement

**Yes, SNS is involved** - but only for agent alerts, not Guardian.

### Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DUAL EMAIL SYSTEMS                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  GUARDIAN (guardian/guardian/reporting.py)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ • Direct SMTP (aiosmtplib)                           │  │
│  │ • Custom threading (Message-ID, In-Reply-To)        │  │
│  │ • JSON history file (.guardian-email-history.json)   │  │
│  │ • LLM-powered decisions (optional)                   │  │
│  │ • HTML + plain text formatting                       │  │
│  │ • Rule-based deduplication                           │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  AGENTS (ops/agent/smart_email.py)                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ • SNS (AWS Simple Notification Service)              │  │
│  │ • SQLite threading (email_threads table)              │  │
│  │ • SQLite history (alert_history table)               │  │
│  │ • Batching (60s window)                             │  │
│  │ • Semantic deduplication (topic normalization)       │  │
│  │ • Daily digest mode                                  │  │
│  │ • Escalation tracking                                │  │
│  │ • No LLM integration                                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Who Uses What?

| Component | Email System | Transport | Threading | History | LLM |
|-----------|-------------|-----------|-----------|---------|-----|
| **Guardian Reporter** | Direct SMTP | SMTP | File-based | JSON file | ✅ Yes |
| **SRE Agent** | smart_email | SNS | SQLite | SQLite | ❌ No |
| **Watchdog Agent** | Direct SNS | SNS | None | None | ❌ No |
| **Alerting Agent** | Direct SNS | SNS | None | Cache | ❌ No |

## Design Issues

### 1. **Dual Email Systems (SMTP vs SNS)**

**Problem**: Guardian uses SMTP directly, while agents use SNS. This creates:
- **Inconsistent delivery**: SMTP can fail silently; SNS has retries/queuing
- **Different reliability**: SNS is more robust (AWS managed)
- **Configuration complexity**: Two different credential systems
- **No unified interface**: Can't easily switch between systems

**Impact**: 
- Guardian emails might not arrive if SMTP is down
- Agents can't leverage Guardian's LLM features
- Guardian can't leverage smart_email's batching/deduplication

**Better Design**: 
- Guardian should optionally use SNS (via smart_email) instead of direct SMTP
- Or: smart_email should support SMTP as a transport option
- Unified interface: `send_alert(report, transport="sns"|"smtp")`

### 2. **Inconsistent Threading Mechanisms**

**Problem**: Two separate threading systems that don't interoperate:

**Guardian**:
- Uses email headers: `Message-ID`, `In-Reply-To`, `References`
- Stores last message ID in `.guardian-email-thread` file
- Threads by report type (all Guardian reports = one thread)

**smart_email**:
- Uses SQLite `email_threads` table
- Threads by topic (normalized topic = thread_id)
- Weekly thread boundaries (same topic, same week = same thread)

**Impact**:
- Guardian emails don't thread with agent alerts (even if about same issue)
- Email clients see separate threads for related issues
- No cross-system threading awareness

**Better Design**:
- Unified threading: both systems should use same thread_id format
- Cross-system awareness: Guardian should check smart_email threads before creating new ones
- Or: smart_email should handle Guardian emails too

### 3. **Separate History Systems**

**Problem**: Two history stores that don't share data:

**Guardian**:
- JSON file: `.guardian-email-history.json`
- Stores: summary, top 5 issues per category, LLM decisions
- Last 100 entries
- Agent-accessible via MCP tool

**smart_email**:
- SQLite: `alert_history` table
- Stores: topic, severity, subject, thread_id, occurrence_count
- Unlimited history
- Not exposed to agents

**Impact**:
- LLM in Guardian can't see agent alert history (and vice versa)
- No unified view of all alerts
- Duplicate alerts possible across systems
- Can't learn from cross-system patterns

**Better Design**:
- Unified history: both systems write to same store (SQLite or S3)
- Cross-system queries: Guardian LLM should see agent alerts
- Or: smart_email should expose history via MCP tool

### 4. **Feature Asymmetry**

**Problem**: Each system has features the other lacks:

**Guardian has**:
- ✅ LLM-powered send decisions
- ✅ LLM-generated subjects
- ✅ LLM executive summaries
- ✅ Rich HTML formatting
- ✅ Visual hierarchy (badges, cards, progress bars)

**smart_email has**:
- ✅ Batching (consolidate multiple alerts)
- ✅ Semantic deduplication (topic normalization)
- ✅ Daily digest mode
- ✅ Escalation tracking ("still unresolved after 4 hours")
- ✅ Occurrence counting ("3rd alert this week")
- ✅ SNS reliability (retries, queuing)

**Impact**:
- Guardian can't batch multiple reports
- smart_email can't use LLM for smarter decisions
- No system has all features

**Better Design**:
- Guardian should use smart_email as backend (with LLM layer on top)
- Or: smart_email should add LLM integration
- Unified feature set: batching + LLM + rich formatting

### 5. **No Unified Alerting Interface**

**Problem**: No common API for sending alerts:

- Guardian: `Reporter.report()` → `_send_email()`
- SRE Agent: `send_sns_alert()` → `smart_send_alert()`
- Watchdog: `send_sns_alert()` → direct SNS
- Alerting Agent: `send_alert()` → direct SNS

**Impact**:
- Each component implements alerting differently
- Hard to add features consistently
- No shared deduplication logic
- Inconsistent alert formats

**Better Design**:
- Unified `AlertService` class:
  ```python
  class AlertService:
      def send(self, alert: Alert, transport: str = "sns") -> bool:
          # Unified logic: threading, dedup, batching, LLM
  ```
- All components use same service
- Consistent behavior across system

### 6. **Deduplication Strategies Don't Align**

**Problem**: Different deduplication logic:

**Guardian**:
- Rule-based: `_has_actionable_issues()` check
- LLM-based: `should_send_email()` (if enabled)
- No cross-run deduplication (each run is independent)

**smart_email**:
- Content hashing: SHA256 of `severity + headline + top 3 alerts`
- Time-based: 12-hour window
- Topic-based: Same normalized topic = same alert
- Occurrence counting: Tracks how many times topic alerted

**Impact**:
- Guardian might send duplicate emails if same issue persists
- smart_email might suppress legitimate new alerts
- No coordination between systems

**Better Design**:
- Unified deduplication: both systems check same store
- Cross-system awareness: Guardian checks smart_email history
- Smarter logic: LLM-based deduplication (recognizes semantic similarity)

### 7. **LLM Integration Only in Guardian**

**Problem**: smart_email has no LLM features:

- Can't make intelligent send decisions
- Can't generate contextual subjects
- Can't create executive summaries
- Can't recognize semantic duplicates

**Impact**:
- Agent alerts are less intelligent
- More noise (can't filter effectively)
- Less contextual information

**Better Design**:
- smart_email should use LLMService (same as Guardian)
- Or: Guardian's LLM should be extracted to shared module
- Consistent LLM integration across all alerting

### 8. **Configuration Fragmentation**

**Problem**: Different config systems:

**Guardian**:
- Environment variables: `SMTP_HOST`, `SMTP_USER`, `EMAIL_LLM_ENABLED`, etc.
- Pydantic Settings: `Settings` class in `config.py`

**smart_email**:
- Environment variables: `SNS_TOPIC_ARN`, `SMART_EMAIL_DB`, `BATCH_WINDOW_SECONDS`
- No Settings class (direct `os.getenv()`)

**Impact**:
- Inconsistent config management
- Hard to validate settings
- No type safety for smart_email config

**Better Design**:
- Unified Settings class (Pydantic)
- Shared config validation
- Type-safe configuration

## Recommended Improvements

### Priority 1: Unify Transport Layer

**Option A**: Guardian uses SNS (via smart_email)
- Guardian calls `smart_send_alert()` instead of direct SMTP
- Benefits: batching, deduplication, reliability
- Trade-off: Requires SNS setup (but already exists)

**Option B**: smart_email supports SMTP
- Add SMTP transport option to smart_email
- Benefits: Can use existing SMTP config
- Trade-off: Less reliable than SNS

**Recommendation**: Option A (Guardian → SNS via smart_email)

### Priority 2: Unified History

- Both systems write to same SQLite DB (or S3)
- Expose unified history via MCP tool
- LLM can see all alerts (Guardian + agents)

### Priority 3: Shared LLM Service

- Extract `LLMService` to shared module (`ops/agent/llm_service.py`)
- smart_email uses same LLM for decisions
- Consistent LLM integration

### Priority 4: Unified Alerting Interface

- Create `AlertService` class
- All components use same interface
- Consistent behavior, easier to maintain

## Migration Path

1. **Phase 1**: Guardian optionally uses smart_email (feature flag)
   - Add `USE_SMART_EMAIL=true` config
   - Guardian calls `smart_send_alert()` if enabled
   - Keep SMTP as fallback

2. **Phase 2**: Unified history
   - Migrate Guardian JSON history to SQLite
   - smart_email exposes history via MCP
   - Cross-system queries work

3. **Phase 3**: Shared LLM
   - Extract `LLMService` to shared module
   - smart_email uses LLM for decisions
   - Consistent intelligence

4. **Phase 4**: Unified interface
   - Create `AlertService` class
   - Migrate all components
   - Deprecate old interfaces

## Current State Summary

**What Works**:
- ✅ Guardian emails are well-formatted (HTML, visual hierarchy)
- ✅ smart_email has good features (batching, dedup, threading)
- ✅ LLM integration in Guardian is useful
- ✅ SNS is reliable for agent alerts

**What Doesn't Work Well**:
- ❌ Two separate systems (no interoperability)
- ❌ Inconsistent threading (emails don't group properly)
- ❌ No unified history (can't learn from all alerts)
- ❌ Feature asymmetry (each system missing features)
- ❌ No shared deduplication (duplicate alerts possible)
- ❌ LLM only in Guardian (agents can't use it)

**Biggest Issue**: Guardian and agents operate in isolation, despite reporting on related infrastructure issues. They should be unified.

