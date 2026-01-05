# Guardian Reporting Architecture

## Reporting Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    GUARDIAN REPORTING FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Guardian Check Execution                                    │
│     └─> Runs all checkers (npm, gh, swarm, aws, etc.)           │
│                                                                  │
│  2. Report Generation                                           │
│     └─> GuardianReport with checks, summary, findings           │
│                                                                  │
│  3. Reporter.report()                                           │
│     ├─> Console output (rich formatting)                        │
│     ├─> Webhook (if configured)                                  │
│     └─> Email (if configured)                                   │
│                                                                  │
│  4. Email Decision (if EMAIL_LLM_ENABLED=true)                  │
│     ├─> LLM analyzes: report + email history                    │
│     ├─> Determines: should_send, priority, reasoning            │
│     └─> Generates: contextual subject line                      │
│                                                                  │
│  5. Email Sending                                               │
│     ├─> Threading: Message-ID, In-Reply-To, References         │
│     ├─> HTML + Plain text formats                               │
│     └─> History recorded for agent introspection                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Integration

### Guardian Agent (`ops/agent/guardian/run_guardian_agent.py`)

**Purpose**: LLM-powered security analysis of Guardian findings

**Location**: Runs on **alakazam** (AWS t4g.small, 24/7)

**Schedule**: 
- Docker Swarm: Every 15 minutes (via `agents-stack.yml`)
- Manual: `just guardian-agent`

**What It Does**:
1. Collects Guardian snapshot (`guardian-snapshot.json`)
2. Analyzes with LLM (Ollama qwen2.5:0.5b or OpenRouter)
3. Generates prioritized recommendations
4. Outputs: `guardian-agent-report.json` + `.txt`
5. Tracks known vulnerabilities in memory

**Not the same as Guardian's built-in reporting**:
- Guardian's `Reporter` class handles email/webhook/console
- Guardian Agent adds LLM analysis layer on top

### SRE Agent (`ops/agent/continuous_agent.py`)

**Purpose**: 24/7 infrastructure monitoring

**Location**: Runs on **alakazam** (Docker Swarm)

**Reporting**:
- Uses `smart_email.py` for intelligent alerting
- Sends via SNS (AWS Simple Notification Service)
- Deduplication, batching, threading
- Alert fatigue detection

**Integration with Guardian**:
- Can query Guardian reports via HTTP
- May trigger alerts based on Guardian findings
- Uses stigmergy markers for coordination

## Infrastructure Topology

### Node Fleet (Pokemon Naming, RFC 1178)

```
┌─────────────────────────────────────────────────────────────────┐
│                      TAILSCALE MESH NETWORK                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  HOME LAN (192.168.1.x)              AWS VPC (172.31.x.x)       │
│  ┌─────────────────────┐             ┌─────────────────────┐   │
│  │                     │             │                     │   │
│  │  CHARIZARD          │◄────────────►│  ALAKAZAM           │   │
│  │  (MacBook Pro)      │   Tailscale  │  (t4g.small, 2GB)  │   │
│  │  100.116.189.39     │   DERP       │  100.100.175.57     │   │
│  │                     │             │                     │   │
│  │  Role: Dev          │             │  Role: Agent Hub     │   │
│  │  - Ollama (llama3.2)│             │  - Docker Swarm Mgr │   │
│  │  - Finance Agent    │             │  - SRE Agent        │   │
│  │  - Dossier          │             │  - Guardian Agent   │   │
│  │  - L3-L4 data       │             │  - Chat API          │   │
│  │                     │             │  - Ollama (qwen2.5) │   │
│  │      │              │             │      │              │   │
│  │      │ DIRECT       │             │      │ DIRECT       │   │
│  │      │ (LAN)        │             │      │ (VPC)        │   │
│  │      ▼              │             │      ▼              │   │
│  │  SNORLAX            │             │  GYARADOS           │   │
│  │  (Synology NAS)     │             │  (t4g.nano, 0.5GB)  │   │
│  │  100.115.71.60      │             │  100.85.116.41      │   │
│  │  22TB storage       │             │  Exit Node          │   │
│  │                     │             │  Swarm Worker       │   │
│  └─────────────────────┘             └─────────────────────┘   │
│                                                                  │
│  INTERMITTENT NODES                                             │
│  ┌─────────────────────┐                                       │
│  │  METAGROSS          │  Mac mini, home server                │
│  │  KADABRA            │  iPhone, mobile                        │
│  └─────────────────────┘                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Node Details

| Node | Type | RAM | Role | Availability | Guardian Role |
|------|------|-----|------|--------------|--------------|
| **alakazam** | AWS t4g.small | 2GB+2GB swap | Agent Hub, Swarm Manager | Always-on | Runs Guardian checks, Guardian Agent |
| **gyarados** | AWS t4g.nano | 0.5GB | Exit Node, Swarm Worker | Always-on | Metrics collection |
| **charizard** | MacBook Pro | 32GB | Development | Intermittent | Local Guardian runs, Finance Agent |
| **snorlax** | Synology NAS | ? | Storage/Archive | Intermittent | Backup storage |
| **metagross** | Mac mini | 8GB | Home server | Intermittent | Offline |
| **kadabra** | iPhone | - | Mobile | Intermittent | Mobile access |

### Docker Swarm Cluster

**Always-on nodes form Swarm**:
- **alakazam**: Manager (runs 24/7 agents)
- **gyarados**: Worker (exit node, data services)

**Services on alakazam**:
- `sre-agent`: Continuous monitoring (every 5min)
- `guardian-agent`: Security analysis (every 15min)
- `chat-api`: Human interface
- `watchdog-agent`: Meta-observation

**Placement Constraints**:
- `node.hostname == alakazam`: 24/7 agents
- `node.hostname == gyarados`: Data services

## Reporting Agents Summary

### Who Reports What?

| Component | What It Reports | How | Where |
|-----------|----------------|-----|-------|
| **Guardian Reporter** | Security findings, vulnerabilities, deployments | Email, webhook, console | Built into Guardian |
| **Guardian Agent** | LLM analysis of Guardian findings | JSON files to S3 | Runs on alakazam |
| **SRE Agent** | Infrastructure health, costs, alerts | SNS, smart_email | Runs on alakazam |
| **Watchdog Agent** | Agent health, stale reports | SNS | Runs on alakazam |

### Email Reporting Flow

```
Guardian Check
    │
    ▼
GuardianReport
    │
    ▼
Reporter.report()
    │
    ├─> Console (rich formatting)
    ├─> Webhook (if configured)
    └─> Email (if configured)
         │
         ├─> LLM Decision? (if EMAIL_LLM_ENABLED=true)
         │    └─> Analyzes history, decides if should send
         │
         ├─> Subject Generation
         │    ├─> LLM-powered (if enabled)
         │    └─> Rule-based (fallback)
         │
         ├─> Email Formatting
         │    ├─> HTML (modern, responsive)
         │    └─> Plain text
         │
         ├─> Threading Headers
         │    ├─> Message-ID
         │    ├─> In-Reply-To
         │    └─> References
         │
         └─> History Recording
              └─> .guardian-email-history.json (for agent introspection)
```

## Data Classification & Privacy

| Level | Description | Where Processed | Guardian Email Content |
|-------|-------------|-----------------|----------------------|
| **L1** | Public | Any node | Full details OK |
| **L2** | Internal | alakazam, charizard | Summary metrics, node names |
| **L3** | Confidential | charizard only | Never in emails |
| **L4** | Restricted | charizard only | Never in emails |

**Guardian emails are L2** - include operational details but not sensitive data.

## LLM Integration Points

1. **Email Send Decision**: `LLMService.should_send_email()`
   - Analyzes report + history
   - Prevents alert fatigue
   - Returns reasoning

2. **Subject Generation**: `LLMService.generate_subject_line()`
   - Context-aware subjects
   - Highlights critical issues

3. **Executive Summary**: `LLMService.generate_executive_summary()`
   - 2-3 sentence summaries
   - Actionable context

4. **Guardian Agent Analysis**: `run_guardian_agent.py`
   - LLM triage of vulnerabilities
   - Prioritized recommendations
   - Known issue tracking

## Configuration

```bash
# Enable Guardian email reporting
ALERT_EMAIL=your@email.com
SMTP_HOST=smtp.example.com
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=guardian@example.com

# Enable LLM-powered judgements
EMAIL_LLM_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-...  # or OPENAI_API_KEY, OPENROUTER_API_KEY

# Email behavior
EMAIL_ONLY_ON_ISSUES=true  # Skip "all clear" emails
EMAIL_THREAD_ID_FILE=.guardian-email-thread
EMAIL_HISTORY_FILE=.guardian-email-history.json
```

## Agent Access to Email History

Agents can introspect email history via:

1. **MCP Tool**: `get_email_history(limit=10)`
   - Returns recent emails with summaries
   - Useful for pattern analysis

2. **Direct File Access**: `.guardian-email-history.json`
   - JSON format, last 100 emails
   - Includes LLM decisions, issues, summaries

3. **Programmatic**: `Reporter.get_email_history(limit=10)`
   - Python API for agent scripts

## Key Insights

1. **Guardian Reporter** = Built-in email/webhook/console (no agent needed)
2. **Guardian Agent** = LLM analysis layer (runs separately on alakazam)
3. **SRE Agent** = Infrastructure monitoring (uses smart_email for alerts)
4. **LLM Integration** = Optional enhancement for better email decisions
5. **History Tracking** = Enables agent introspection and learning

