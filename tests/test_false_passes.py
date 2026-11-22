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


def test_local_copy_must_not_be_the_only_subject(tmp_path: Path) -> None:
    helper = 'def mirror(x):\n    """Mirrors the logic from pkg.merge."""\n    return x + 1\n'
    cases = {
        "test_copy.py": helper + "def test_result():\n    assert mirror(1) == 2\n",
        "test_oracle.py": helper
        + "from pkg import merge as real\ndef test_result():\n    assert mirror(1) == real(1)\n",
        "test_unused.py": helper + "def test_result():\n    assert 1 == 1\n",
        "helper.py": helper + "def test_result():\n    assert mirror(1) == 2\n",
    }
    for name, content in cases.items():
        (tmp_path / name).write_text(content)
    assert find_false_passes(tmp_path, list(cases)) == {"copied_test_subject": ["test_copy.py"]}


def test_empty_scan_documents(tmp_path: Path) -> None:
    cases = {
        "array.sh": """ast-grep scan --json target > out || echo '[]' > out""",
        "results.sh": """opengrep scan --json --output out target || echo '{"results":[]}' > out""",
        "group.sh": """cargo geiger --output-format json > raw || {\n    echo "{}" > raw\n}""",
        "status.sh": """cargo geiger --output-format json > raw || echo "unavailable" >&2""",
        "unrelated.sh": """cat optional.json > out || echo '{}' > out""",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source)
    assert find_false_passes(tmp_path, list(cases)) == {
        "fabricated_scan_report": ["array.sh", "results.sh", "group.sh"]
    }


def test_explicit_placeholder_trait_preserves_markers(tmp_path: Path) -> None:
    cases = {
        "empty.rs": "/// Placeholder for a future visitor.\npub trait Visitor {\n // TODO: define visit.\n}\n",
        "marker.rs": "/// Marks validated inputs.\npub trait Checked {}\n",
        "extension.rs": "/// Placeholder policy for optional calls.\npub trait Policy {\n // TODO: defaults.\n fn name(&self);\n}\n",
        "compat.rs": '/// Placeholder from v1.\n#[deprecated(note = "retained for compatibility")]\npub trait Previous {}\n',
    }
    for name, src in cases.items():
        (tmp_path / name).write_text(src)
    assert find_false_passes(tmp_path, list(cases)) == {"placeholder_rust_trait": ["empty.rs"]}
