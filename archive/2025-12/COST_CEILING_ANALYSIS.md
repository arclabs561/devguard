# AWS Cost Ceiling Analysis & Memory System Critique

## Problem: Inconsistent Cost Ceilings Across Codebase

### Current State

| Location | Value | Type | Notes |
|---------|-------|------|-------|
| `ops/scripts/infra/check-cost-spend-ceiling.sh` | **$600** | Default | `MAX_MONTHLY_USD="${MAX_MONTHLY_USD:-600}"` |
| `ops/agent/config/agent-config.yaml` | **$600** | Hardcoded | `mtd_critical: 600.00` |
| `ops/agent/cost_agent.py` | **$600** | Hardcoded | `MONTHLY_BUDGET = float(os.getenv("MONTHLY_BUDGET", "600.0"))` |
| `ops/scripts/portal/refresh-cost-trends.sh` | **$600** | Hardcoded | `BUDGET=600` |
| `guardian/guardian/config.py` | **$100** | Default | `aws_monthly_cost_ceiling: float = Field(100.0, ...)` |
| `guardian/.env` | **$600** | Override | `AWS_MONTHLY_COST_CEILING=600.0` |

### The Memory System Issue

**Memory Created:** [[memory:12665967]]
> "The AWS $100/month ceiling in Guardian's AWSCostChecker is outdated for December 2025. Current MTD spend is ~$550-600, which includes infrastructure for agent fleet, Swarm cluster, and other services. The ceiling should be reviewed/updated in guardian/guardian/checkers/aws_cost.py (MONTHLY_CEILING constant) or the alert should be acknowledged as expected for this month's infrastructure buildout."

**Problems with this memory:**
1. **Outdated assumption**: Says to update `MONTHLY_CEILING` constant, but we already made it configurable
2. **Incomplete**: Doesn't mention the $600 is used everywhere else
3. **No action plan**: Doesn't suggest standardizing across codebase
4. **Temporary thinking**: Frames it as "this month" when $600 appears to be the actual budget

### Root Cause Analysis

1. **Guardian was added later** - Other tools already used $600
2. **No single source of truth** - Each tool has its own hardcoded value
3. **Memory system doesn't track codebase state** - Only captures human knowledge, not code reality

### Recommendations

#### Short-term (Fix Guardian)
- ✅ Already done: Made ceiling configurable
- ✅ Already done: Set to $600 in `.env`
- ⚠️ **TODO**: Update default in `config.py` from $100 to $600 to match rest of codebase

#### Medium-term (Standardize)
1. **Create single source of truth**: `ops/config/budget.yaml`
   ```yaml
   aws:
     monthly_ceiling: 600.0
     daily_warn: 30.0
     daily_critical: 50.0
   ```

2. **Update all tools to read from config**:
   - `check-cost-spend-ceiling.sh`: Source from YAML
   - `cost_agent.py`: Read from YAML
   - `refresh-cost-trends.sh`: Read from YAML
   - `agent-config.yaml`: Reference same value
   - Guardian: Read from YAML or env (env takes precedence)

#### Long-term (Memory System Improvements)
1. **Code-aware memories**: When creating memories about code, include:
   - Current code state (not just "should be updated")
   - Where else the value appears
   - Whether it's a bug or intentional divergence

2. **Memory validation**: Periodically check if memories are still accurate:
   - "Memory says X should be updated, but code shows Y"
   - Flag stale memories for review

3. **Cross-reference**: When memory mentions a file/constant, search codebase for related values

## Docker Swarm Placement Constraints

### Current State

**SwarmChecker** monitors:
- ✅ Node health (Ready/Active)
- ✅ Service replica counts
- ❌ **Missing**: Placement constraint compliance

**Services use constraints:**
- `node.hostname == alakazam` (24/7 agents)
- `node.hostname == ip-172-31-62-87.ec2.internal` (gyarados data services)
- `node.hostname == charizard` (intermittent privacy agent)

### Gap Analysis

**What SwarmChecker should verify:**
1. Services with `node.hostname == alakazam` are actually running on alakazam
2. Services with `node.hostname == gyarados` are actually running on gyarados
3. Services aren't running on wrong nodes (security/compliance issue)

**Docker Swarm doesn't have "taints"** (that's Kubernetes), but:
- **Placement constraints** = Swarm's equivalent
- **Node labels** = Can be used for more complex placement
- **Service placement** = Can be queried via `docker service ps`

### Implementation Plan

Add to `SwarmChecker`:
1. Query service placement: `docker service ps <service> --format json`
2. Extract actual node hostname from task placement
3. Compare against expected constraints from `agents-stack.yml` / `services-stack.yml`
4. Alert if service is on wrong node

