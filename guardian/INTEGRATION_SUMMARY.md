# npm Security Analysis Integration Summary

## Overview

The deep npm package security analysis from `guardian/scripts/redteam_npm_packages.py` has been integrated into the main Guardian monitoring system as a new checker.

## Changes Made

### 1. New Checker: `NpmSecurityChecker`

**File:** `guardian/checkers/npm_security.py`

- Integrates deep security analysis into Guardian's checker architecture
- Converts security findings to Guardian `Vulnerability` objects
- Reports findings through the standard Guardian reporting system
- Uses analysis functions from `guardian/scripts/redteam_npm_packages.py`

**Features:**
- Secret detection (API keys, tokens, passwords)
- Obfuscated code detection
- Sensitive file detection
- Git history detection
- Missing .npmignore detection
- Suspicious install script detection
- Dependency vulnerability checking

### 2. Configuration

**File:** `guardian/config.py`

Added new setting:
```python
npm_security_enabled: bool = Field(
    False, description="Enable deep security analysis of npm packages"
)
```

**Default:** `False` (disabled by default due to resource intensity)

### 3. Core Integration

**File:** `guardian/core.py`

- Added `NpmSecurityChecker` to Guardian's checker initialization
- Runs when `npm_security_enabled=true` and packages are configured
- Executes alongside other checkers in parallel

### 4. CLI Updates

**File:** `guardian/cli.py`

- Updated `config` command to show npm security analysis status

### 5. Documentation

**File:** `README.md`

- Added section on "Deep npm Package Security Analysis"
- Documented configuration and usage
- Explained resource considerations

## Usage

### Enable Deep npm Security Analysis

```bash
# In .env file
NPM_SECURITY_ENABLED=true
NPM_PACKAGES_TO_MONITOR=package1,package2
```

### Run Guardian Checks

```bash
guardian check
```

The deep security analysis will run automatically and report findings as vulnerabilities in the standard Guardian report format.

## Architecture

```
Guardian.run_checks()
    ↓
[NpmChecker.check()]          # Basic vulnerability checking (npm audit)
[NpmSecurityChecker.check()]  # Deep security analysis (secrets, obfuscation, etc.)
    ↓
GuardianReport (unified results)
    ↓
Reporter.report()
```

## Benefits

1. **Unified Reporting**: All security findings appear in the same Guardian report
2. **Integration**: Works with existing Guardian features (webhooks, email alerts, dashboard)
3. **Metrics**: Security findings tracked in Prometheus metrics
4. **Consistency**: Uses same vulnerability model as other checkers

## Differences from Standalone Scripts

- **Standalone scripts** (`guardian/scripts/redteam_npm_packages.py`): 
  - Run independently
  - Generate detailed JSON/Markdown reports
  - Useful for one-off deep analysis
  
- **Integrated checker** (`guardian/checkers/npm_security.py`):
  - Runs as part of Guardian monitoring
  - Reports through Guardian's unified system
  - Integrates with alerts, dashboard, metrics
  - Better for continuous monitoring

## Future Enhancements

- Add caching to avoid re-downloading packages on every check
- Add rate limiting for package downloads
- Support for analyzing specific versions
- Integration with CI/CD pipelines
- Historical tracking of security findings


