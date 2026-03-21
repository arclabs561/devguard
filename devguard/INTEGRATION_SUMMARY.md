# npm Security Analysis Integration Summary

## Overview

The deep npm package security analysis from `devguard/scripts/redteam_npm_packages.py` has been integrated into the main devguard monitoring system as a new checker.

## Changes Made

### 1. New Checker: `NpmSecurityChecker`

**File:** `devguard/checkers/npm_security.py`

- Integrates deep security analysis into devguard's checker architecture
- Converts security findings to devguard `Vulnerability` objects
- Reports findings through the standard devguard reporting system
- Uses analysis functions from `devguard/scripts/redteam_npm_packages.py`

**Features:**
- Secret detection (API keys, tokens, passwords)
- Obfuscated code detection
- Sensitive file detection
- Git history detection
- Missing .npmignore detection
- Suspicious install script detection
- Dependency vulnerability checking

### 2. Configuration

**File:** `devguard/config.py`

Added new setting:
```python
npm_security_enabled: bool = Field(
    False, description="Enable deep security analysis of npm packages"
)
```

**Default:** `False` (disabled by default due to resource intensity)

### 3. Core Integration

**File:** `devguard/core.py`

- Added `NpmSecurityChecker` to devguard's checker initialization
- Runs when `npm_security_enabled=true` and packages are configured
- Executes alongside other checkers in parallel

### 4. CLI Updates

**File:** `devguard/cli.py`

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

### Run devguard Checks

```bash
devguard check
```

The deep security analysis will run automatically and report findings as vulnerabilities in the standard devguard report format.

## Architecture

```
devguard.run_checks()
    ↓
[NpmChecker.check()]          # Basic vulnerability checking (npm audit)
[NpmSecurityChecker.check()]  # Deep security analysis (secrets, obfuscation, etc.)
    ↓
devguardReport (unified results)
    ↓
Reporter.report()
```

## Benefits

1. **Unified Reporting**: All security findings appear in the same devguard report
2. **Integration**: Works with existing devguard features (webhooks, email alerts, dashboard)
3. **Metrics**: Security findings tracked in Prometheus metrics
4. **Consistency**: Uses same vulnerability model as other checkers

## Differences from Standalone Scripts

- **Standalone scripts** (`devguard/scripts/redteam_npm_packages.py`): 
  - Run independently
  - Generate detailed JSON/Markdown reports
  - Useful for one-off deep analysis
  
- **Integrated checker** (`devguard/checkers/npm_security.py`):
  - Runs as part of devguard monitoring
  - Reports through devguard's unified system
  - Integrates with alerts, dashboard, metrics
  - Better for continuous monitoring

## Future Enhancements

- Add caching to avoid re-downloading packages on every check
- Add rate limiting for package downloads
- Support for analyzing specific versions
- Integration with CI/CD pipelines
- Historical tracking of security findings


