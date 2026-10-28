"""Exercise documented command targets without running documented commands."""

from pathlib import Path

import pytest

from devguard.sweeps.doc_commands import check_doc_commands


def scan(tmp_path: Path, body: str):
    (tmp_path / "README.md").write_text(body)
    return check_doc_commands(tmp_path, ["README.md"])


def test_npm_missing_script_and_existing_script(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"check":"touch SHOULD_NOT_EXIST"}}')
    report = scan(tmp_path, "```sh\nnpm run lint\nnpm run check\nnpm run env\n```\n")
    assert report["commands_checked"] == 3
    assert report["findings"] == [
        {
            "check": "doc_command_target",
            "severity": "low",
            "file": "README.md",
            "line": 2,
            "engine": "npm",
            "target": "lint",
            "manifest": "package.json",
            "message": "Documented command target is absent from the selected local package",
        }
    ]
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
    assert scan(tmp_path, "```sh\nnpm run check -- --if-present\n```\n")["findings"] == []


@pytest.mark.parametrize(
    "command",
    [
        "npm run missing --if-present",
        "npm --prefix other run missing",
        "npm run missing --workspace other",
        "npm run $TASK",
        "npm run missing && echo yes",
        "npm run `echo missing`",
        "npm run <task>",
        "npm run missing \\\n--if-present",
        "cd other\nnpm run missing",
        "source env.sh\nnpm run missing",
        "cargo run -p other --example missing",
        "cargo run --manifest-path other/Cargo.toml --example missing",
        "cargo run --example 'bad*'",
        "echo npm run missing",
        "npm run 'unterminated",
    ],
)
def test_unsupported_commands_do_not_become_false_findings(tmp_path, command):
    (tmp_path / "package.json").write_text('{"scripts":{}}')
    report = scan(tmp_path, f"```sh\n{command}\n```\n")
    assert report["findings"] == []
    assert report["commands_checked"] == 0
    assert len(report["skipped"]) == 1


def test_cargo_explicit_and_automatic_examples(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\nedition="2021"\n'
        '[[example]]\nname="declared"\npath="elsewhere.rs"\n'
    )
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "simple.rs").write_text("fn main() {}")
    (tmp_path / "examples" / "nested").mkdir()
    (tmp_path / "examples" / "nested" / "main.rs").write_text("fn main() {}")
    report = scan(
        tmp_path,
        "```bash\ncargo run --example declared\ncargo test --example simple\ncargo build --release --example nested\ncargo run --example missing -- --option\n```\n",
    )
    assert report["commands_checked"] == 4
    assert [item["target"] for item in report["findings"]] == ["missing"]


def test_cargo_autoexamples_disabled(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="demo"\nedition="2021"\nautoexamples=false\n'
    )
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "present.rs").write_text("fn main() {}")
    report = scan(tmp_path, "```sh\ncargo run --example present\n```\n")
    assert report["findings"][0]["target"] == "present"


@pytest.mark.parametrize(
    "manifest", ["[workspace]\nmembers=[]", '[package]\nname="demo"', "[broken"]
)
def test_unknown_cargo_target_set_is_skipped(tmp_path, manifest):
    (tmp_path / "Cargo.toml").write_text(manifest)
    report = scan(tmp_path, "```sh\ncargo run --example missing\n```\n")
    assert report["findings"] == []
    assert report["commands_checked"] == 0
    assert len(report["skipped"]) == 1


def test_fences_prompts_and_line_numbers(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{}}')
    report = scan(
        tmp_path, "```text\nnpm run ignored\n```\n\n~~~~sh\n# comment\n$ npm run missing\n~~~~\n"
    )
    assert report["findings"][0]["line"] == 7
    assert report["commands_checked"] == 1
    assert scan(tmp_path, "```sh\nnpm run missing\n")["commands_checked"] == 0


def test_explicit_package_scope(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text('{"scripts":{"check":"true"}}')
    (tmp_path / "README.md").write_text("```sh\nnpm run check\n```\n")
    report = check_doc_commands(tmp_path, ["README.md"], package_root="sub")
    assert report["commands_checked"] == 1
    assert report["findings"] == []
    assert report["scope"]["package_root"] == "sub"


def test_owner_boundary_and_symlinks(tmp_path):
    owner = tmp_path / "owner"
    owner.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "README.md").write_text("```sh\nnpm run missing\n```\n")
    (outside / "package.json").write_text('{"scripts":{}}')
    (owner / "link").symlink_to(outside, target_is_directory=True)
    (owner / "README.md").symlink_to(outside / "README.md")
    report = check_doc_commands(
        owner, ["README.md", "link/README.md", "../outside/README.md", outside / "README.md"]
    )
    assert len(report["skipped"]) == 4
    assert report["commands_checked"] == 0
    assert str(outside) not in str(report)
    with pytest.raises(ValueError):
        check_doc_commands(owner, [], package_root="link")


def test_symlink_manifest_is_not_read(tmp_path):
    (tmp_path / "data.json").write_text('{"scripts":{}}')
    (tmp_path / "package.json").symlink_to(tmp_path / "data.json")
    report = scan(tmp_path, "```sh\nnpm run missing\n```\n")
    assert report["commands_checked"] == 0
    assert len(report["skipped"]) == 1


@pytest.mark.parametrize("manifest", ["[]", '{"scripts":[]}', '{"scripts":{"check":3}}', "{"])
def test_malformed_npm_manifest_not_clean(tmp_path, manifest):
    (tmp_path / "package.json").write_text(manifest)
    report = scan(tmp_path, "```sh\nnpm run missing\n```\n")
    assert report["commands_checked"] == 0
    assert report["skipped"]


def test_symlink_example_inventory_cannot_establish_absence(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname="demo"\nedition="2021"\n')
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "linked.rs").symlink_to(tmp_path / "outside.rs")
    report = scan(tmp_path, "```sh\ncargo run --example missing\n```\n")
    assert report["commands_checked"] == 0
    assert report["findings"] == []
    assert len(report["skipped"]) == 1


def test_document_and_manifest_byte_limits(tmp_path):
    report = scan(tmp_path, "x" * (256 * 1024 + 1))
    assert report["commands_checked"] == 0
    assert len(report["skipped"]) == 1
    (tmp_path / "package.json").write_text(" " * (256 * 1024 + 1))
    report = scan(tmp_path, "```sh\nnpm run missing\n```\n")
    assert report["commands_checked"] == 0
    assert len(report["skipped"]) == 1


def test_no_document_command_or_package_manager_execution(tmp_path, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        pytest.fail("the checker must not execute programs or access the network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    (tmp_path / "package.json").write_text('{"scripts":{"check":"curl example.invalid"}}')
    report = scan(tmp_path, "```sh\nnpm run check\nnpm run missing\n```\n")
    assert report["commands_checked"] == 2
    assert len(report["findings"]) == 1
