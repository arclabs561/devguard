# Guardian Triage: Priority Ranking

**Generated:** 2025-12-26  
**Current Status:** 14 checkers active, 5 findings, 5 unhealthy deployments, 1 failed check

## 🔴 CRITICAL (Fix Immediately)

### 1. Domain Checker Failing
**Status:** `domain: success=False, findings=3, errors=0`  
**Impact:** SSL certificate monitoring broken  
**Root Cause:** Need to investigate why domain checks are failing  
**Action:**
- Check domain checker error handling
- Verify SSL certificate checking logic
- Fix failing domains: `trackweave.fm`, `music.attobop.net`, `trackweave.fly.dev`

### 2. Unhealthy Deployments Not Resolved
**Status:** 5 unhealthy deployments  
**Impact:** Production services may be down  
**Deployments:**
- `fly/trackweave: unknown`
- `tailscale/Ash's MacBook Air: unknown` (stale device?)
- `domain/trackweave.fm: unhealthy`
- `domain/music.attobop.net: unhealthy`
- `domain/trackweave.fly.dev: unhealthy`

**Action:**
- Investigate Fly.io trackweave status
- Remove or fix "Ash's MacBook Air" Tailscale device
- Fix SSL issues on domains

## 🟠 HIGH PRIORITY (This Week)

### 3. Cost Ceiling Standardization
**Status:** Guardian default updated to $600, but other tools still hardcoded  
**Impact:** Inconsistent budget enforcement across tools  
**Action:**
- Create `ops/config/budget.yaml` as single source of truth
- Update all tools to read from shared config:
  - `check-cost-spend-ceiling.sh`
  - `cost_agent.py`
  - `refresh-cost-trends.sh`
  - `agent-config.yaml`

### 4. Swarm Placement Constraint Verification
**Status:** Code added but needs testing  
**Impact:** Security/compliance - services could run on wrong nodes  
**Action:**
- Test placement constraint checking on actual swarm
- Verify it works when run on manager node (alakazam)
- Add to CI/CD if possible

### 5. API Usage Checker Gaps
**Status:** Only monitors 2 providers (OpenRouter, Groq)  
**Impact:** Missing visibility into Anthropic, OpenAI, Perplexity usage  
**Action:**
- Fix Anthropic Admin API integration (requires sk-ant-admin key)
- Fix OpenAI Usage API integration (403 errors)
- Fix Perplexity API endpoint (404 errors)
- Add usage tracking for all configured providers

### 6. JSON Reporting Bug
**Status:** `unhealthy_deployments` returns int instead of list in summary  
**Impact:** JSON output parsing fails  
**Action:**
- Fix `core.py` line 200: `"unhealthy_deployments": len(...)` should be count
- Verify all summary fields are consistent types

## 🟡 MEDIUM PRIORITY (This Month)

### 7. README Outdated
**Status:** Missing new checkers (Swarm, API Usage, Domain, Tailscale, AWS Cost)  
**Impact:** Users don't know about new features  
**Action:**
- Update README with all 14 checkers
- Document new configuration options
- Add examples for new checkers

### 8. Missing Test Coverage
**Status:** New checkers (Swarm, API Usage, Domain) lack unit tests  
**Impact:** Risk of regressions  
**Action:**
- Add tests for `SwarmChecker`
- Add tests for `APIUsageChecker`
- Add tests for `DomainChecker`
- Test placement constraint verification

### 9. MCP Server Limitations
**Status:** Comment in code: "This is a bit of a hack, we should probably support running specific checkers in core"  
**Impact:** MCP integration incomplete  
**Action:**
- Add ability to run specific checkers via MCP
- Improve MCP server error handling
- Document MCP capabilities

### 10. Discovery System Gaps
**Status:** Multiple "not yet implemented" warnings in discovery.py  
**Impact:** Limited discovery capabilities  
**Action:**
- Implement API method for discovery rules
- Implement custom method handlers
- Add more discovery patterns

## 🟢 LOW PRIORITY (Nice to Have)

### 11. Dashboard Enhancements
**Status:** Basic dashboard exists but could show more  
**Impact:** Limited visibility  
**Action:**
- Add API usage visualization
- Add cost trends chart
- Add swarm topology view
- Add historical trends

### 12. Alerting Improvements
**Impact:** Limited alerting options  
**Action:**
- Add Slack webhook support
- Add PagerDuty integration
- Add alert deduplication
- Add alert severity routing

### 13. Performance Optimizations
**Status:** All checkers run sequentially  
**Impact:** Slow check times  
**Action:**
- Parallelize independent checkers
- Add caching for API responses
- Add incremental checking (only changed resources)

### 14. Documentation Gaps
**Status:** Missing architecture docs, deployment guides  
**Impact:** Harder to maintain/extend  
**Action:**
- Create ARCHITECTURE.md
- Create DEPLOYMENT.md
- Document checker extension patterns
- Add troubleshooting guide

## 📊 Current Metrics

```
Total Checkers: 14
  ✓ Working: 12
  ✗ Failing: 1 (domain)
  ⚠️ Partial: 1 (api_usage - some providers fail)

Findings: 5
  Critical: 0
  High: 0
  Medium: 0
  Warning: 5

Unhealthy Deployments: 5
Failed Checks: 1
```

## 🎯 Recommended Next Steps (Priority Order)

1. **Fix domain checker** - Investigate and fix SSL certificate checking
2. **Fix JSON reporting bug** - Ensure consistent types in summary
3. **Test swarm placement constraints** - Verify on actual swarm manager
4. **Update README** - Document all 14 checkers
5. **Standardize cost ceiling** - Create shared config file
6. **Add missing tests** - Cover new checkers
7. **Fix API usage providers** - Get all providers working

## 🔍 Technical Debt

- **Hardcoded values:** Cost ceilings, thresholds scattered across codebase
- **Error handling:** Many checkers swallow errors silently (logger.debug)
- **Type consistency:** Some summary fields return different types
- **Discovery system:** Incomplete implementation with many TODOs
- **MCP server:** Limited functionality, needs refactoring

