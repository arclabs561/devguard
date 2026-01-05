# Guardian NPM Security Scripts

Comprehensive security analysis and remediation tools for npm packages.

## Scripts

### `redteam_npm_packages.py`

Deep red team security analysis of published npm packages.

**Features:**
- **Secret Detection:**
  - API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)
  - Tokens and passwords
  - Database URLs
  - OAuth secrets
  - JWT secrets
  - Base64/hex encoded secrets (with decoding)
  
- **Code Analysis:**
  - Context-aware obfuscated code detection (eval, Function, atob, etc.)
  - Suspicious script patterns
  - Placeholder values
  - Secrets in comments
  
- **File Analysis:**
  - Sensitive file names
  - Git history detection
  - Lock files
  - CI/CD configs
  - Source maps
  - Large files
  - File permissions
  
- **Package Configuration:**
  - Missing .npmignore
  - Files field analysis
  - Suspicious install scripts (postinstall/preinstall)
  - Dependency risk assessment
  - Package name typosquatting detection
  
- **Dependency Security:**
  - npm audit integration
  - Vulnerability severity assessment
  - CVE tracking

**Usage:**
```bash
uv run python guardian/scripts/redteam_npm_packages.py
```

**Output:**
- Detailed per-package analysis with severity ratings
- Summary statistics
- Prioritized actionable recommendations

### `generate_npmignore.py`

Generate `.npmignore` files based on npm best practices.

**Usage:**
```bash
# Generate for all packages in default location (~/Documents/dev)
uv run python guardian/scripts/generate_npmignore.py

# Generate for specific directory
uv run python guardian/scripts/generate_npmignore.py /path/to/packages
```

**Features:**
- Excludes test files
- Excludes CI/CD configs
- Excludes sensitive files
- Excludes lock files
- Creates backups of existing files
- Customizable based on package structure

### `generate_security_report.py`

Generate comprehensive JSON and Markdown security reports.

**Usage:**
```bash
uv run python guardian/scripts/generate_security_report.py
```

**Output:**
- `npm_security_report.json` - Detailed JSON report with all findings
- `npm_security_report.md` - Human-readable Markdown report
- Summary statistics
- Prioritized recommendations (HIGH/MEDIUM/LOW)

### `auto_fix_recommendations.py`

Generate automated fix commands based on security analysis.

**Usage:**
```bash
uv run python guardian/scripts/auto_fix_recommendations.py
```

**Features:**
- Analyzes security report
- Generates fix commands
- Optionally applies fixes automatically
- Prioritizes by severity

## Best Practices

1. **Run analysis before publishing:**
   ```bash
   uv run python guardian/scripts/redteam_npm_packages.py
   ```

2. **Generate .npmignore files:**
   ```bash
   uv run python guardian/scripts/generate_npmignore.py
   ```

3. **Review install scripts** - Especially `postinstall` and `preinstall` scripts

4. **Use `files` field** in package.json instead of `.npmignore` when possible (more secure allowlist)

5. **Never publish:**
   - `.env` files
   - `.git` directory
   - Lock files
   - CI/CD configs with secrets
   - Test files with real credentials

6. **Regular audits:**
   ```bash
   npm audit
   npm audit fix
   ```

## Integration

Add to your `package.json` scripts:

```json
{
  "scripts": {
    "prepublishOnly": "python guardian/scripts/redteam_npm_packages.py",
    "check:security": "python guardian/scripts/redteam_npm_packages.py",
    "fix:security": "python guardian/scripts/auto_fix_recommendations.py"
  }
}
```

## Security Checks Performed

### Secret Detection
- API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, etc.)
- Tokens and passwords
- Database URLs
- OAuth secrets
- JWT secrets
- Base64/hex encoded secrets (with automatic decoding)

### Code Analysis
- Context-aware obfuscated code detection
- Suspicious script patterns
- Placeholder values
- Secrets in comments
- Install script security risks

### File Analysis
- Sensitive file names
- Git history
- Lock files
- CI/CD configs
- Source maps
- Large files
- File permissions

### Package Configuration
- Missing .npmignore
- Files field issues
- Suspicious install scripts
- Dependency risks
- Repository exposure
- Package name typosquatting

### Dependency Security
- npm audit integration
- Vulnerability severity assessment
- CVE tracking
- Critical/High severity prioritization

## Continuous Improvement

The analysis continuously improves with:
- New secret patterns
- Better false positive filtering
- Additional security checks
- Enhanced reporting
- Context-aware detection

Run regularly to catch issues before they're published!

## Workflow

1. **Before publishing:**
   ```bash
   uv run python guardian/scripts/redteam_npm_packages.py
   ```

2. **Fix issues:**
   ```bash
   uv run python guardian/scripts/auto_fix_recommendations.py
   ```

3. **Generate reports:**
   ```bash
   uv run python guardian/scripts/generate_security_report.py
   ```

4. **Review and commit fixes**

5. **Publish with confidence!**
