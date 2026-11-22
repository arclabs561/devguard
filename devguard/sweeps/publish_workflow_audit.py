"""Publish workflow audit: static checks on publish and release GitHub workflows.

Checks:
- tag_push_without_credentials (error): a step runs `git push` after
  `actions/checkout` with `persist-credentials: false`, and no step in the job
  configures a token-bearing remote or auth header.
- msrv_pins_missing (warning): ci.yml pins dependencies with
  `cargo update --precise` for its MSRV job, but a publish job that installs
  an MSRV toolchain lacks some of those pins.
- semver_checks_all_features (warning): `cargo-semver-checks-action` runs with
  its default all-features group in a crate that has platform-only features or
  target-specific dependencies, which fail to build on the Linux runner.
- unpinned_action_ref (note): an action ref is not a full commit SHA while
  other workflows in the repo pin SHAs.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from devguard.sweeps._common import contained_file, iter_git_repos, utc_now

DEFAULT_WORKFLOW_GLOBS = ["publish*.yml", "publish*.yaml", "release*.yml", "release*.yaml"]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
_GIT_PUSH_RE = re.compile(r"\bgit\s+(?:-C\s+\S+\s+)?push\b")
_TOKEN_REMOTE_RE = re.compile(
    r"x-access-token|https://[^\s/]*@github\.com|extraheader|git\s+remote\s+(?:set-url|add)\b.*\$\{\{"
    r"|gh\s+auth\s+setup-git",
    re.IGNORECASE,
)
_PRECISE_RE = re.compile(r"cargo\s+update\b[^\n]*?--precise\s+\S+")
_MSRV_TOOLCHAIN_RE = re.compile(
    r"rust-toolchain@1\.\d+|toolchain:\s*['\"]?1\.\d+|rustup\s+(?:toolchain\s+install|default|override\s+set)\s+1\.\d+"
    r"|cargo\s+\+1\.\d+|\bmsrv\b",
    re.IGNORECASE,
)
_PLATFORM_FEATURE_RE = re.compile(
    r"metal|cuda|objc|coreml|accelerate|\bmps\b|vulkan|rocm|directml|macos|windows|ios|android",
    re.IGNORECASE,
)
_OS_CFG_RE = re.compile(r"target_os|target_vendor|target_family|\bwindows\b|\bunix\b")
_PLATFORM_DEP_RE = re.compile(r"^(objc2.*|metal.*|cudarc|cuda.*|core-foundation.*|windows.*)$")


def _finding(
    check: str,
    severity: str,
    workflow: str,
    message: str,
    *,
    job: str | None = None,
    step: int | None = None,
) -> dict[str, Any]:
    return {
        **({"job": job} if job is not None else {}),
        **({"step": step} if step is not None else {}),
        "check": check,
        "severity": severity,
        "file": f".github/workflows/{workflow}",
        "message": f"{workflow}: {message}",
    }


def _normalize_precise(cmd: str) -> str:
    return " ".join(cmd.split())


def _jobs(doc: Any) -> dict[str, Any]:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def _is_checkout(step: dict[str, Any]) -> bool:
    return str(step.get("uses", "")).startswith("actions/checkout@")


def _persist_false(step: dict[str, Any]) -> bool:
    val = (step.get("with") or {}).get("persist-credentials")
    return val is False or str(val).strip().lower() == "false"


def _check_tag_push(name: str, doc: Any) -> list[dict[str, Any]]:
    out = []
    for job_id, job in _jobs(doc).items():
        steps = [s for s in (job or {}).get("steps") or [] if isinstance(s, dict)]
        no_creds = False
        authed = False
        for index, step in enumerate(steps, start=1):
            run = str(step.get("run") or "")
            if _is_checkout(step):
                no_creds = _persist_false(step)
                authed = False
                continue
            if _TOKEN_REMOTE_RE.search(run):
                authed = True
            if no_creds and not authed and _GIT_PUSH_RE.search(run):
                label = step.get("name") or run.strip().splitlines()[0][:60]
                out.append(
                    _finding(
                        "tag_push_without_credentials",
                        "error",
                        name,
                        f"job '{job_id}' step '{label}' runs git push after checkout with "
                        "persist-credentials: false and no token-bearing remote",
                        job=job_id,
                        step=index,
                    )
                )
    return out


def _check_msrv_pins(name: str, text: str, ci_pins: set[str]) -> list[dict[str, Any]]:
    if not ci_pins or not _MSRV_TOOLCHAIN_RE.search(text):
        return []
    have = {_normalize_precise(m) for m in _PRECISE_RE.findall(text)}
    missing = sorted(ci_pins - have)
    if not missing:
        return []
    return [
        _finding(
            "msrv_pins_missing",
            "warning",
            name,
            f"MSRV toolchain step without ci.yml pins: {'; '.join(missing)}",
        )
    ]


def _platform_only(manifest: Path) -> list[str]:
    try:
        data = tomllib.loads(manifest.read_text())
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    reasons = []
    target = data.get("target")
    if isinstance(target, dict):
        # Only OS/vendor-specific optional deps: a feature can enable them, and
        # all-features then compiles platform code on the Linux runner.
        for cfg, tables in target.items():
            deps = tables.get("dependencies") if isinstance(tables, dict) else None
            if not isinstance(deps, dict) or not _OS_CFG_RE.search(cfg):
                continue
            if any(isinstance(d, dict) and d.get("optional") for d in deps.values()):
                reasons.append(f"optional target-specific dependencies ({cfg})")
                break
    feats = [f for f in (data.get("features") or {}) if _PLATFORM_FEATURE_RE.search(f)]
    if feats:
        reasons.append(f"platform features: {', '.join(sorted(feats)[:5])}")
    deps = [d for d in (data.get("dependencies") or {}) if _PLATFORM_DEP_RE.match(d)]
    if deps:
        reasons.append(f"platform dependencies: {', '.join(sorted(deps)[:5])}")
    return reasons


def _crate_manifests(repo: Path) -> list[Path]:
    found = [repo / "Cargo.toml"] + sorted(repo.glob("crates/*/Cargo.toml"))
    return [p for p in found if contained_file(p, repo)]


def _check_semver_features(name: str, doc: Any, repo: Path) -> list[dict[str, Any]]:
    out = []
    for job_id, job in _jobs(doc).items():
        for step in (job or {}).get("steps") or []:
            if not isinstance(step, dict):
                continue
            if "cargo-semver-checks-action" not in str(step.get("uses", "")):
                continue
            with_ = step.get("with") or {}
            if any(k in with_ for k in ("feature-group", "features")):
                continue
            reasons = [r for m in _crate_manifests(repo) for r in _platform_only(m)]
            if reasons:
                out.append(
                    _finding(
                        "semver_checks_all_features",
                        "warning",
                        name,
                        f"job '{job_id}' runs cargo-semver-checks-action without feature-group "
                        f"or features; crate has {reasons[0]}",
                        job=job_id,
                    )
                )
    return out


def _action_refs(text: str) -> list[str]:
    return [u for u in _USES_RE.findall(text) if "@" in u and not u.startswith(("./", "docker://"))]


def _check_unpinned(name: str, text: str, repo_pins_shas: bool) -> list[dict[str, Any]]:
    if not repo_pins_shas:
        return []
    loose = sorted({u for u in _action_refs(text) if not _SHA_RE.match(u.rsplit("@", 1)[1])})
    if not loose:
        return []
    return [
        _finding(
            "unpinned_action_ref",
            "note",
            name,
            f"action refs not pinned to a commit SHA (other workflows pin): {', '.join(loose[:8])}",
        )
    ]


def _privileged_refs(name: str, doc: Any) -> list[dict[str, Any]]:
    findings = []
    for job_id, job in _jobs(doc).items():
        if not isinstance(job, dict):
            continue
        permissions = job.get("permissions", doc.get("permissions"))
        writable = permissions == "write-all" or (
            isinstance(permissions, dict) and "write" in permissions.values()
        )
        context = json.dumps([doc.get("env", {}), job], default=str)
        secrets = job.get("secrets") == "inherit" or bool(
            re.search(r"\bsecrets\s*(?:\.|\[)", context, re.I)
        )
        if not writable and not secrets:
            continue
        steps = [job, *(job.get("steps") or [])]
        refs = set()
        for step in steps:
            ref = step.get("uses") if isinstance(step, dict) else None
            if isinstance(ref, str) and "@" in ref and not ref.startswith(("./", "docker://")):
                if not _SHA_RE.fullmatch(ref.rsplit("@", 1)[1]):
                    refs.add(ref)
        if refs:
            findings.append(
                _finding(
                    "privileged_unpinned_action",
                    "error",
                    name,
                    f"job '{job_id}' uses mutable refs with write permissions or secrets: {', '.join(sorted(refs))}",
                    job=job_id,
                )
            )
    return findings


_EVENT_CODE = re.compile(
    r"\$\{\{[^}]*\bgithub\.(?:head_ref\b|event\.(?:pull_request\.head|client_payload|workflow_run\.head_(?:sha|branch|repository))\b)",
    re.I,
)
_EVENT_TEXT = re.compile(
    r"\$\{\{[^}]*\bgithub\.(?:head_ref\b|event\.(?:(?:pull_request|issue)\.(?:title|body)|(?:review|comment)\.body|head_commit\.message)\b)",
    re.I,
)
_EVENT_DESTINATION = re.compile(r"\$\{\{[^}]*\bgithub\.event\.client_payload\b", re.I)
_SECRET_REF = re.compile(r"\$\{\{[^}]*\bsecrets\s*[.\[]", re.I)
_TRUSTED_CONTEXT_EVENTS = {
    "pull_request_target",
    "workflow_run",
    "repository_dispatch",
    "issue_comment",
}


_SECURITY_COMMAND = re.compile(
    r"^\s*(?:cargo\s+audit|cargo\s+test\b[^|&#\n]*\bsecret_scanning\b|gitleaks\s+(?:git|dir|detect)|trufflehog\s+(?:git|filesystem)"
    r"|npm\s+run\s+(?:test:security|check:secrets:ci))(?:\s|$)"
)
_IGNORE_EXIT = re.compile(
    r"""\|\|\s*(?:true|:|echo\s+(?:"[^"$`]*"|'[^']*'|[\w .()-]+))\s*(?:#.*)?$"""
)


def _owner_event_only(condition: Any) -> bool:
    # Recognize the simple owner-only job guard. Compound conditions need review.
    value = str(condition).strip().removeprefix("${{").removesuffix("}}").strip()
    terms = [part.strip().lower() for part in value.split("==")]
    return sorted(terms) == ["github.event.repository.owner.id", "github.event.sender.id"]


_EVENT_TEST = re.compile(r"github\.event_name\s*(==|!=)\s*'([a-z_]+)'", re.I)
_GUARD_TOKEN = re.compile(r"'(?:[^']|'')*'|'|[()]|&&|\|\|")


def _can_run_on_pr(condition: Any) -> bool:
    """Exclude a job only when each top-level alternative rules out PRs.

    Functions and grouped expressions are opaque. They can add a review
    prompt, but cannot suppress one. Quoted operators are data.
    """
    expr = str(condition).strip().removeprefix("${{").removesuffix("}}").strip().lower()
    start = depth = 0
    possible = True
    for token in [*_GUARD_TOKEN.finditer(expr), None]:
        op = token.group() if token else ""
        if op == "(":
            depth += 1
        elif op == ")":
            depth -= 1
            if depth < 0:
                return True
        elif op == "'":
            return True  # Unclosed string.
        elif not depth and op in {"&&", "||", ""}:
            term = expr[start : token.start() if token else len(expr)].strip()
            test = _EVENT_TEST.fullmatch(term)
            if term == "false" or (test and (test[1] == "==") != (test[2] == "pull_request")):
                possible = False
            if op != "&&":
                if possible or not token:
                    return possible
                possible = True
            if token:
                start = token.end()
    return True


def _workflow_trust(name: str, doc: Any) -> list[dict[str, Any]]:
    """Flag direct data flows. A trigger name alone cannot establish misuse."""
    if not isinstance(doc, dict):
        return []
    # PyYAML's YAML 1.1 loader reads an unquoted 'on' as True.
    trigger = doc.get("on", doc.get(True)) or []
    events = (
        {trigger}
        if isinstance(trigger, str)
        else {event for event in trigger if isinstance(event, str)}
        if isinstance(trigger, (list, dict))
        else set()
    )
    trusted_context = bool(events & _TRUSTED_CONTEXT_EVENTS)
    findings = []
    for job_id, job in _jobs(doc).items():
        if not isinstance(job, dict):
            continue
        permissions = job.get("permissions", doc.get("permissions"))
        oidc_write = permissions == "write-all" or (
            isinstance(permissions, dict) and permissions.get("id-token") == "write"
        )
        runs_on_pr = "pull_request" in events and _can_run_on_pr(job.get("if"))
        if runs_on_pr and "permissions" not in job and "permissions" not in doc:
            findings.append(
                _finding(
                    "implicit_pr_token_permissions",
                    "warning",
                    name,
                    f"job '{job_id}' inherits the repository's default GITHUB_TOKEN permissions "
                    "on pull requests. Declare the permissions required by this job or workflow.",
                )
                | {"job": job_id}
            )
        if runs_on_pr and oidc_write:
            findings.append(
                _finding(
                    "review_pr_oidc_permission",
                    "warning",
                    name,
                    f"job '{job_id}' may grant OIDC token access on pull requests. "
                    "Check the cloud role's trust policy and scope the permission to a trusted job.",
                    job=job_id,
                )
            )
        pr_write = permissions == "write-all" or (
            isinstance(permissions, dict) and permissions.get("pull-requests") == "write"
        )
        if "pull_request_target" in events and pr_write and not _owner_event_only(job.get("if")):
            findings.append(
                _finding(
                    "review_pr_target_write",
                    "warning",
                    name,
                    f"job '{job_id}' can write PR metadata on pull_request_target. "
                    "Verify which senders may start it and whose contributions it may edit.",
                    job=job_id,
                )
            )
        steps = [step for step in job.get("steps") or [] if isinstance(step, dict)]
        for index, step in enumerate(steps, start=1):
            label = f"job '{job_id}', step {index}"
            action = str(step.get("uses", "")).split("@")[0].lower()
            inputs = step.get("with") or {}
            if not isinstance(inputs, dict):
                continue
            if (
                trusted_context
                and action == "actions/checkout"
                and any(
                    _EVENT_CODE.search(str(inputs.get(key, ""))) for key in ("ref", "repository")
                )
            ):
                findings.append(
                    _finding(
                        "event_selected_checkout",
                        "error",
                        name,
                        f"{label} selects checkout code from the event in a trusted workflow context. "
                        "Check out the trusted revision or verify its provenance first.",
                        job=job_id,
                        step=index,
                    )
                )
            script = str(step.get("run") or "")
            if action == "actions/github-script":
                script = str(inputs.get("script") or "")
            commands = [line for line in script.splitlines() if _SECURITY_COMMAND.match(line)]
            if commands and (
                step.get("continue-on-error") is True
                or job.get("continue-on-error") is True
                or any(_IGNORE_EXIT.search(line) for line in commands)
            ):
                findings.append(
                    _finding(
                        "nonblocking_security_check",
                        "warning",
                        name,
                        f"{label} can report success after its security check fails. "
                        "Propagate the scanner's exit status or document the advisory-only policy.",
                        job=job_id,
                        step=index,
                    )
                )
            if _EVENT_TEXT.search(script):
                findings.append(
                    _finding(
                        "event_text_in_script",
                        "error",
                        name,
                        f"{label} interpolates contributor-controlled text into a script. "
                        "Pass the value through an environment variable or read the event as data.",
                        job=job_id,
                        step=index,
                    )
                )
            if "repository_dispatch" not in events or not script:
                continue
            env = {}
            for scope in (doc, job, step):
                if isinstance(scope.get("env"), dict):
                    env.update(scope["env"])
            if not _SECRET_REF.search(json.dumps([env, script], default=str)):
                continue
            for key, value in env.items():
                if not re.search(r"(?:^|_)(?:URL|URI|ORIGIN|HOST|ENDPOINT)$", str(key), re.I):
                    continue
                if not _EVENT_DESTINATION.search(str(value)):
                    continue
                if re.search(
                    r"\$(?:\{" + re.escape(str(key)) + r"\}|" + re.escape(str(key)) + r"\b)", script
                ) or re.search(r"\b(?:pytest|npm|node|python3?)\b", script):
                    findings.append(
                        _finding(
                            "dispatch_destination_with_credentials",
                            "error",
                            name,
                            f"{label} passes an event-selected destination ({key}) to a credentialed command. "
                            "Use a configured origin or validate it against an independently trusted allowlist.",
                            job=job_id,
                            step=index,
                        )
                    )
                    break
    return findings


def _shape_error(doc: Any) -> str | None:
    jobs = _jobs(doc)
    if not jobs:
        return "expected a nonempty jobs mapping"
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            return f"expected a mapping for job '{job_id}'"
        if "uses" in job and "steps" not in job:
            continue  # Reusable workflow.
        steps = job.get("steps")
        if not isinstance(steps, list) or not all(isinstance(step, dict) for step in steps):
            return f"expected a list of steps for job '{job_id}'"
        if any("with" in step and not isinstance(step["with"], dict) for step in steps):
            return f"expected a step inputs mapping for job '{job_id}'"
    return None


def _add_source_lines(text: str, findings: list[dict[str, Any]]) -> None:
    """Resolve YAML job/step positions from the scanned input, including quoted job IDs."""
    indexed = [f for f in findings if f.get("job") and "line" not in f]
    if not indexed:
        return

    def mapping(node: yaml.Node | None) -> dict[str, yaml.Node]:
        return (
            {key.value: value for key, value in node.value}
            if isinstance(node, yaml.MappingNode)
            else {}
        )

    jobs = mapping(yaml.compose(text)).get("jobs")
    if not isinstance(jobs, yaml.MappingNode):
        return
    positions = {key.value: (key, value) for key, value in jobs.value}
    for finding in indexed:
        entry = positions.get(finding["job"])
        if entry is None:
            continue
        key, job = entry
        point = key.start_mark
        steps = mapping(job).get("steps")
        index = finding.get("step")
        if (
            isinstance(steps, yaml.SequenceNode)
            and isinstance(index, int)
            and 1 <= index <= len(steps.value)
        ):
            step = steps.value[index - 1]
            point = step.start_mark
            step_id = mapping(step).get("id")
            if isinstance(step_id, yaml.ScalarNode):
                finding["step_id"] = step_id.value
        finding["line"] = point.line + 1


def _scan_workflows(
    repo: Path, workflow_globs: list[str] | None
) -> tuple[list[dict[str, Any]], int, int]:
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.resolve().is_relative_to(repo.resolve()):
        raise OSError("workflow directory outside repository")
    try:
        entries = sorted(wf_dir.iterdir())
    except FileNotFoundError:
        return [], 0, 0
    paths = [p for p in entries if p.suffix in (".yml", ".yaml") and not p.is_dir()]
    globs = workflow_globs or DEFAULT_WORKFLOW_GLOBS
    texts = {}
    findings = []
    for path in paths:
        try:
            if not contained_file(path, repo):
                raise OSError("not a regular file inside the repository")
            texts[path.name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.append(
                _finding("workflow_read_error", "warning", path.name, type(exc).__name__)
            )

    ci_text = texts.get("ci.yml") or texts.get("ci.yaml") or ""
    ci_pins = {_normalize_precise(m) for m in _PRECISE_RE.findall(ci_text)}
    # Mixed pinning is the signal: the repo already pins SHAs somewhere.
    repo_pins_shas = any(
        _SHA_RE.match(u.rsplit("@", 1)[1]) for t in texts.values() for u in _action_refs(t)
    )

    scanned = 0
    for name, text in texts.items():
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            findings.append(_finding("workflow_parse_error", "warning", name, "YAML parse error"))
            continue
        if problem := _shape_error(doc):
            findings.append(_finding("workflow_parse_error", "warning", name, problem))
            continue
        scanned += 1
        current = _privileged_refs(name, doc) + _workflow_trust(name, doc)
        if any(fnmatch.fnmatch(name, g) for g in globs):
            current += _check_tag_push(name, doc)
            current += _check_msrv_pins(name, text, ci_pins)
            current += _check_semver_features(name, doc, repo)
            current += _check_unpinned(name, text, repo_pins_shas)
        _add_source_lines(text, current)
        findings.extend(current)
    return findings, len(paths), scanned


def audit_workflows(repo: Path, workflow_globs: list[str] | None = None) -> list[dict[str, Any]]:
    """Audit the workflows of one repository."""
    findings, _, _ = _scan_workflows(repo, workflow_globs)
    return findings


def audit_publish_workflows(
    *,
    dev_root: Path,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    workflow_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    globs = exclude_repo_globs or []
    repos = [
        r
        for r in sorted(iter_git_repos(dev_root, max_depth=max_depth))
        if not any(fnmatch.fnmatch(str(r), g) for g in globs)
    ]
    results: list[dict[str, Any]] = []
    discovered = scanned = 0
    for repo in repos:
        try:
            findings, listed, checked = _scan_workflows(repo, workflow_globs)
            discovered += listed
            scanned += checked
        except (OSError, RuntimeError) as exc:
            errors.append(f"{repo.name}: workflow discovery failed ({type(exc).__name__})")
            continue
        errors.extend(
            f"{repo.name}: {f['message']}"
            for f in findings
            if f["check"] in {"workflow_parse_error", "workflow_read_error"}
        )
        if findings:
            results.append({"repo_path": str(repo), "findings": findings})
    sev: dict[str, int] = {"error": 0, "warning": 0, "note": 0}
    for r in results:
        for f in r["findings"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    results.sort(key=lambda r: (-len(r["findings"]), r["repo_path"]))
    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "scope": {
            "dev_root": str(dev_root),
            "repos_scanned": len(repos),
            "workflows_discovered": discovered,
            "workflows_scanned": scanned,
        },
        "summary": {
            "repos_with_findings": len(results),
            "total_findings": sum(sev.values()),
            "total_errors": sev["error"],
            "severity_counts": sev,
        },
        "repos": results,
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
