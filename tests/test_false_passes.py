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
        "select_backend.py": "if backend == 'disk':\n    return_value = memory()\nelse:\n    return_value = memory()\n",
        "side_effect.py": "if probe() == 'disk':\n    f()\nelse:\n    f()\n",
        "stubs.py": "if backend == 'disk':\n    pass\nelse:\n    pass\n",
        "same.py": "if method == 'bca':\n    q = percentile(x)\nelse:\n    q = percentile(x)\n",
        "different.py": "if method == 'bca':\n    q = bca(x)\nelse:\n    q = percentile(x)\n",
    }
    for name, content in samples.items():
        (tmp_path / name).write_text(content)
    assert find_false_passes(tmp_path, list(samples)) == {
        "flattened_python": ["broken.py"],
        "masked_test_command": ["test.sh"],
        "masked_search_error": ["check.sh"],
        "identical_method_branches": ["select_backend.py", "same.py"],
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


def test_assertion_exception_must_reach_a_silent_handler(tmp_path: Path) -> None:
    cases = {
        "test_caught.py": "async def test_it():\n    try:\n        assert await go()\n    except (ValueError, Exception):\n        pass",
        "test_bare.py": "class TestValue:\n    def test_it(self):\n        try:\n            if ready():\n                assert go()\n        except:\n            pass",
        "test_specific.py": "def test_it():\n    try:\n        assert go()\n    except ValueError:\n        pass",
        "test_order.py": "def test_it():\n    try:\n        assert go()\n    except AssertionError:\n        raise\n    except Exception:\n        pass",
        "test_inner.py": "def test_it():\n    try:\n        with pytest.raises(AssertionError):\n            assert go()\n    except Exception:\n        pass",
        "test_nested.py": "def test_it():\n    try:\n        def inner():\n            assert go()\n    except Exception:\n        pass",
        "test_helper.py": "def helper():\n    try:\n        assert go()\n    except Exception:\n        pass",
        "test_skip.py": "def test_it():\n    try:\n        assert go()\n    except AssertionError:\n        pytest.skip('external fixture')",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source)
    assert find_false_passes(tmp_path, list(cases)) == {
        "swallowed_test_assertion": ["test_caught.py", "test_bare.py"]
    }


def test_pre_commit_only_checks_shell_commands_in_local_hook_entries(tmp_path: Path) -> None:
    import yaml

    path = tmp_path / ".pre-commit-config.yaml"

    def check(entry, repo="local"):
        path.write_text(yaml.safe_dump({"repos": [{"repo": repo, "hooks": [{"entry": entry}]}]}))
        return find_false_passes(tmp_path, [path.name])

    assert check("""bash -c 'cd src/ml && uv run pytest -m "not slow" || true'""") == {
        "masked_test_command": [path.name]
    }
    assert check("sh -c 'cargo test||:'") == {"masked_test_command": [path.name]}
    assert check("""bash -c 'echo "cd src/ml && pytest || true"'""") == {}
    assert check("bash -c 'pytest || exit 1'") == {}
    assert check("bash -c 'pytest && cleanup || true'") == {"masked_test_command": [path.name]}
    assert check("bash -c 'pytest || exit 1; cleanup || true'") == {}
    assert check("bash -c 'pytest || true'", repo="https://example.org/upstream") == {}
    assert check("echo 'pytest || true'") == {}


def test_partial_flattening_must_be_a_comment_token(tmp_path: Path) -> None:
    fragment = (
        " class Cache: def get(self, k): return self.data[k] def count(self): return len(self.data)"
    )
    comment = "# " + fragment * 5
    cases = {
        "partial.py": "class Price:\n    amount: float  " + comment,
        "manual.py": '"""Example: ' + comment + '"""',
        "string.py": "payload = " + repr(comment),
        "long.py": "# " + "padding " * 50 + " def one(): pass",
    }
    for name, source in cases.items():
        (tmp_path / name).write_text(source)
    assert find_false_passes(tmp_path, list(cases)) == {"flattened_python": ["partial.py"]}


def test_always_true_or_and_broad_skip(tmp_path: Path) -> None:
    cases = {
        "test_yes.py": "def test_it():\n    assert result() or True",
        "test_conditional.py": "def test_it():\n    assert result() or optional()",
        "test_skip.py": "def test_it():\n    try:\n        assert ready()\n    except Exception:\n        pytest.skip('service')",
        "test_setup.py": "def test_it():\n    try:\n        fixture = get_fixture()\n    except Exception:\n        pytest.skip('service')\n    assert fixture.ready",
    }
    for path, source in cases.items():
        (tmp_path / path).write_text(source)
    assert find_false_passes(tmp_path, list(cases)) == {
        "tautological_test_assertion": ["test_yes.py"],
        "swallowed_test_assertion": ["test_skip.py"],
    }


def test_subprocess_capture_conflicts_with_explicit_streams(tmp_path: Path) -> None:
    cases = {
        "bad.py": "import subprocess as sp\nsp.run(cmd, capture_output=True, stderr=sp.DEVNULL)",
        "stdout.py": "import subprocess\nsubprocess.run(cmd, stdout=subprocess.PIPE, capture_output=True)",
        "valid.py": "import subprocess\nsubprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)",
        "disabled.py": "import subprocess\nsubprocess.run(cmd, capture_output=False, stderr=subprocess.PIPE)",
        "none.py": "import subprocess\nsubprocess.run(cmd, capture_output=True, stderr=None)",
        "other.py": "from custom import subprocess\nsubprocess.run(cmd, capture_output=True, stderr=subprocess.PIPE)",
    }
    for path, source in cases.items():
        (tmp_path / path).write_text(source)
    assert find_false_passes(tmp_path, list(cases)) == {
        "conflicting_subprocess_output": ["bad.py", "stdout.py"]
    }


def test_root_justfile_names_missing_literal_scripts(tmp_path: Path) -> None:
    (tmp_path / "justfile").write_text(
        "check:\n    @bash scripts/lost.sh\n    uv run python tests/ok.py\n"
        "    ./scripts/absent.py arg\n    echo 'bash scripts/example.sh'\n"
        "    cd sub && bash scripts/other.sh\n    bash scripts/{{name}}.sh\n"
        "custom:\n    #!/bin/sh\n    cd sub\n    bash scripts/elsewhere.sh\n"
    )
    assert find_false_passes(tmp_path, ["justfile", "tests/ok.py"]) == {
        "missing_just_script": ["justfile -> scripts/absent.py", "justfile -> scripts/lost.sh"]
    }
    (tmp_path / "justfile").write_text(
        '[working-directory: "sub"]\nrun:\n    bash scripts/local.sh'
    )
    assert find_false_passes(tmp_path, ["justfile"]) == {}


def test_workflow_run_body_and_swallowed_shell_command(tmp_path: Path) -> None:
    workflow = ".github/workflows/ci.yml"
    path = tmp_path / workflow
    path.parent.mkdir(parents=True)
    path.write_text("jobs:\n  test:\n    steps:\n      - run: |\n          pytest || true\n")
    script = tmp_path / "fix.sh"
    script.write_text('#!/bin/bash\nset -euo pipefail echo "Starting" # python3 fix.py\n')
    assert find_false_passes(tmp_path, [workflow, script.name]) == {
        "masked_test_command": [workflow],
        "flattened_shell": [script.name],
    }
    path.write_text("jobs:\n  test:\n    steps:\n      - run: echo 'pytest || true'\n")
    script.write_text("set -euo pipefail; echo ok\n")
    assert not find_false_passes(tmp_path, [workflow, script.name])
