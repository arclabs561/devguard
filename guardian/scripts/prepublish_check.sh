#!/bin/bash
# Pre-publish security check hook for npm packages
# Add to package.json: "prepublishOnly": "./guardian/scripts/prepublish_check.sh"

set -e

echo "🔍 Running pre-publish security checks..."

# Check if guardian scripts are available
if ! command -v python3 &> /dev/null; then
    echo "⚠️  Python3 not found, skipping security checks"
    exit 0
fi

# Run red team analysis
if [ -f "guardian/scripts/redteam_npm_packages.py" ]; then
    echo "Running security analysis..."
    python3 guardian/scripts/redteam_npm_packages.py || {
        echo "❌ Security checks failed!"
        echo "Review the findings above before publishing."
        exit 1
    }
else
    echo "⚠️  Security scripts not found, skipping checks"
fi

echo "✅ Pre-publish checks passed!"


