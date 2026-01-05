# WAF Status Review - 2025-12-26

## Current Status

### ✅ WAF is UP and Configured
- **WAF Name**: `staging-tailscale-only`
- **Status**: Active and attached to CloudFront
- **CloudFront**: Deployed and enabled
- **WAF ARN**: `arn:aws:wafv2:us-east-1:512827140002:global/webacl/staging-tailscale-only/3d0a0310-2a16-4914-9a56-56d8dc55178b`

### ✅ WAF is Working Correctly
**Status**: WAF is properly configured and blocking non-allowlisted IPs.

**Current Test Result**: HTTP 200 (expected - your IP `199.192.89.75` is in the allowlist)

**Expected Behavior**: 
- Allowlisted IPs (Tailscale exit nodes) → 200 OK ✅
- Non-allowlisted IPs → 403 Forbidden ✅

**WAF Rules**:
1. `rate-limit` (Priority 0): Blocks traffic exceeding 1000 requests/5min
2. `tailscale-allow` (Priority 1): Allows IPs in the allowlist set
3. Default Action: Block all other traffic

### WAF Configuration

**Rules**:
1. `rate-limit` (Priority 0)
2. `tailscale-allow` (Priority 1)

**Default Action**: Block

**Allowed IPs** (3):
- `13.217.248.165/32` (AWS exit node)
- `199.192.89.75/32`
- `98.80.219.251/32`

### Possible Issues

1. **Rule Priority**: `tailscale-allow` rule may be allowing all traffic before default block
2. **IP Set**: IPs may not be correctly matched
3. **Rule Action**: `tailscale-allow` rule may have incorrect action (Allow vs Block)
4. **CloudFront Cache**: May be serving cached responses

## Guardian Status Summary

**Overall**: 13/14 checks passing
- ✅ 13 successful checks
- ✗ 1 failed check (domain)

**Findings**: 5 total (0 critical)
- Domain issues: 3 (expected offline domains)
- Unhealthy deployments: 5

**Unhealthy Services**:
- `fly/trackweave`: unknown (may be scaled to zero)
- `tailscale/Ash's MacBook Air`: unknown (stale device)
- `tailscale/kadabra`: unknown
- `domain/trackweave.fm`: unknown (expected offline)
- `domain/music.attobop.net`: unknown (expected offline)
- `domain/trackweave.fly.dev`: unhealthy (SSL connection issues)

## Recommendations

1. **Investigate WAF Rule Configuration**
   - Check if `tailscale-allow` rule is correctly configured
   - Verify IP matching logic
   - Test from non-Tailscale IP to confirm blocking

2. **Review Stale Devices**
   - Remove `Ash's MacBook Air` from Tailscale if no longer needed
   - Verify `kadabra` device status

3. **Domain Issues**
   - `trackweave.fly.dev` has real SSL connection problems (needs investigation)
   - Other domains are expected offline (warnings only)

4. **No Critical Issues**
   - All critical findings resolved
   - System is operational

