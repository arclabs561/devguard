# Guardian Fixes Completed - 2025-12-26

## ✅ Critical Issues Fixed

### 1. Domain Checker Improvements
**Status:** ✅ Fixed  
**Changes:**
- Added `expected_online` flag to domain config
- Domains marked as `expected_online=False` now show as WARNING instead of HIGH severity
- Better error messages for SSL/DNS failures
- Success logic only requires expected-online domains to be healthy

**Result:** 
- `trackweave.fm` and `music.attobop.net` now show as WARNING (expected offline)
- `trackweave.fly.dev` correctly identified as unhealthy (real SSL issue)

### 2. JSON Reporting Type Consistency
**Status:** ✅ Fixed  
**Changes:**
- Added comment clarifying `unhealthy_deployments` is a count, not a list
- Verified JSON output structure is consistent

### 3. Cost Ceiling Standardization
**Status:** ✅ Fixed  
**Changes:**
- Created `ops/config/budget.yaml` as single source of truth
- Updated `AWSCostChecker` to read from budget.yaml with fallback to settings
- Guardian default now $600 (matches rest of codebase)

**Files:**
- `ops/config/budget.yaml` (new)
- `guardian/guardian/checkers/aws_cost.py` (updated)

## ✅ High Priority Issues Fixed

### 4. API Usage Checker Improvements
**Status:** ✅ Fixed  
**Changes:**
- OpenAI: Try `/v1/usage` first, then `/v1/organization/usage`
- OpenAI: Support `OPENAI_ORG_ID` env var for organization header
- Perplexity: Try `/models` endpoint, fallback to chat/completions
- Better error handling for all providers

**Result:** More providers should work when properly configured

### 5. Swarm Placement Constraint Verification
**Status:** ✅ Verified Working  
**Changes:**
- Placement constraint checking code added in previous commit
- Tested on actual swarm: `sre-agent` correctly running on `alakazam`
- Verifies services with `node.hostname == alakazam` are actually on alakazam

**Result:** Security/compliance check working correctly

### 6. README Updates
**Status:** ✅ Updated  
**Changes:**
- Added all 14 checkers to overview
- Documented new checkers: Swarm, API Usage, Domain, Tailscale, AWS Cost

## ⚠️ Remaining Issues (Not Bugs - Real Problems)

### 1. trackweave.fly.dev SSL Issues
**Status:** Real issue identified  
**Problem:** SSL connection timeout/handshake failure  
**Action Required:** Investigate Fly.io app configuration or network issues

### 2. Fly.io trackweave App Status Unknown
**Status:** May be intentional  
**Problem:** App may be scaled to zero or suspended  
**Action Required:** Verify if app should be running

### 3. Tailscale "Ash's MacBook Air" Device
**Status:** Stale device  
**Problem:** Unknown offline device in Tailscale mesh  
**Action Required:** Remove from Tailscale if no longer needed

## 📊 Current Metrics

```
Total Checkers: 14
  ✓ Working: 13
  ✗ Failing: 1 (domain - but only trackweave.fly.dev has real issue)

Findings: 5
  Critical: 0
  High: 1 (trackweave.fly.dev SSL)
  Medium: 0
  Warning: 4 (expected-offline domains, API usage)

Unhealthy Deployments: 5
  - 3 domains (2 expected offline, 1 real issue)
  - 1 Fly.io app (may be scaled to zero)
  - 1 Tailscale device (stale)
```

## 🎯 Next Steps (Medium Priority)

1. **Investigate trackweave.fly.dev** - Fix SSL connection issues
2. **Verify Fly.io trackweave** - Check if app should be running
3. **Clean up Tailscale** - Remove stale "Ash's MacBook Air" device
4. **Add tests** - Unit tests for new checkers (Swarm, API Usage, Domain)
5. **Update other tools** - Make them read from `ops/config/budget.yaml`

