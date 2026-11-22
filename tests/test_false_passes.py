from pathlib import Path

from devguard.sweeps.false_passes import find_false_passes


def test_known_false_passes_and_controls(tmp_path: Path) -> None:
    samples = {
        "cost.ts": "const tiers: TierCosts = { fast: cost, balanced: cost, best: cost };",
        "tier.ts": "const tiers = { fast: flashCost, balanced: flashCost, best: proCost };",
        "broken.py": "#!/usr/bin/env python3 import sys def main(): return 42\n",
        "ok.py": "#!/usr/bin/env python3\n# documentation only\n",
        "clean.sh": "#!/bin/sh\nrm -f temp || true\npython3 -m pytest || status=$?\n",
        "test.sh": "#!/bin/sh\npython3 -m pytest -q || true\n",
        "check.sh": 'n=$(rg -c "sample" missing.rs 2>/dev/null || echo "0")\n',
        "example.sh": "cat <<'EOF'\npython3 -m pytest || true\nEOF\n",
        "same.py": "if method == 'bca':\n    q = percentile(x)\nelse:\n    q = percentile(x)\n",
        "different.py": "if method == 'bca':\n    q = bca(x)\nelse:\n    q = percentile(x)\n",
    }
    for name, content in samples.items():
        (tmp_path / name).write_text(content)
    assert find_false_passes(tmp_path, list(samples)) == {
        "aliased_tier_costs": ["cost.ts"],
        "flattened_python": ["broken.py"],
        "masked_test_command": ["test.sh"],
        "masked_search_error": ["check.sh"],
        "identical_method_branches": ["same.py"],
    }
