"""Read Git objects and describe configured push effects without running workflow code."""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import typer
import yaml  # type: ignore[import-untyped]


def _git(repo: Path, *args: str) -> bytes:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if p.returncode:
        raise ValueError(f"Git could not {args[0]} the requested local revisions")
    return p.stdout


def _tree(repo: Path, rev: str) -> dict[str, str]:
    entries = _git(repo, "ls-tree", "-rz", rev, "--", ".github/workflows").split(b"\0")
    files = {}
    for entry in filter(None, entries):
        meta, raw = entry.split(b"\t", 1)
        path = raw.decode(errors="surrogateescape")
        if path.count("/") == 2 and path.endswith((".yml", ".yaml")):
            mode, _, oid = meta.decode().split()
            if mode not in {"100644", "100755"}:
                raise ValueError("non-regular workflow file in revision")
            files[path] = oid
    return files


def _locations(node: yaml.Node, path: tuple = (), seen: set[int] | None = None) -> dict[tuple, int]:
    if seen is None:
        seen = set()
    if id(node) in seen:
        raise ValueError("Aliased workflow structure requires review")
    seen.add(id(node))
    result = {path: node.start_mark.line + 1}
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode):
                result.update(_locations(value, (*path, key.value), seen))
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            result.update(_locations(child, (*path, i), seen))
    return result


def _match(value: str, patterns: Any) -> bool | None:
    # GitHub uses ordered positive and negative patterns. Only model simple
    # path segments and ** here. Other pattern syntax keeps the effect uncertain.
    if not isinstance(patterns, list):
        return None
    selected = False
    for raw in patterns:
        if not isinstance(raw, str) or re.search(r"[?+\[\]\\]", raw):
            return None
        pat = raw.removeprefix("!")
        if pat == "**":
            match = True
        elif pat.endswith("/**") and not any(c == "*" for c in pat[:-3]):
            match = value.startswith(pat[:-2])
        elif "**" in pat:
            return None
        else:
            parts = value.split("/")
            mask = pat.split("/")
            match = len(parts) == len(mask) and all(
                fnmatch.fnmatchcase(p, m) for p, m in zip(parts, mask, strict=True)
            )
        if match:
            selected = not raw.startswith("!")
    return selected


def _trigger(events: Any, branch: str, changes: list[str] | None) -> tuple[str, str]:
    if isinstance(events, str):
        events = {events: None}
    if isinstance(events, list):
        events = dict.fromkeys(events)
    if not isinstance(events, dict):
        return "uncertain", "Unrecognized event declarations"
    if "push" not in events:
        return "excluded", "No push trigger (" + ", ".join(map(str, events)) + ")"
    p = events["push"] or {}
    if not isinstance(p, dict):
        return "uncertain", "Unrecognized push filters"
    if ("tags" in p or "tags-ignore" in p) and not {"branches", "branches-ignore"} & p.keys():
        return "excluded", "Tag-only push trigger"
    for name in ["branches", "branches-ignore"]:
        if name in p:
            match = _match(branch, p[name])
            if match is None:
                return "uncertain", "Unresolved branch pattern"
            if match == name.endswith("-ignore"):
                return "excluded", "Branch filter excludes target"
    for name in ["paths", "paths-ignore"]:
        if name in p:
            if changes is None:
                return "uncertain", "Exact paths of the resulting push are unknown"
            if len(changes) > 300:
                return "uncertain", "Changed files exceed GitHub's path evaluation limit"
            matches = [_match(path, p[name]) for path in changes]
            if None in matches:
                return "uncertain", "Unresolved path pattern"
            if not any(m != name.endswith("-ignore") for m in matches):
                return "excluded", "Path filters exclude changed files"
    return "eligible", "Default-branch push matches the declared event filters"


def _guard(value: Any, branch: str) -> tuple[str, str] | None:
    if value is None or value is True:
        return None
    s = str(value).strip().removeprefix("${{").removesuffix("}}").strip()
    if s in {"always()", "success()", "true"}:
        return None
    if s == "False" or s == "false":
        return "excluded", "Condition is false"
    comparisons = {
        "github.event_name": "push",
        "github.ref": f"refs/heads/{branch}",
        "github.ref_name": branch,
        "github.ref_type": "branch",
    }
    for name, expected in comparisons.items():
        m = re.fullmatch(re.escape(name) + r"""\s*(==|!=)\s*(['"])([^'"]+)\2""", s)
        if m:
            if (expected == m[3]) == (m[1] == "=="):
                return None
            return "excluded", "Condition excludes the target branch push"
    if (
        re.fullmatch(
            r"github\.ref\s*==\s*format\('refs/heads/\{0\}',\s*github\.event\.repository\.default_branch\)",
            s,
        )
        or s == "github.ref_name == github.event.repository.default_branch"
    ):
        return None
    return "uncertain", "Runtime condition requires evaluation"


_SHELL_PART = re.compile(r"""(?:'[^']*'|"(?:(?:\\.)|[^"\\])*"|\\.|[^;&|'"\\#]+|[;&|]+|#.*)""")


def _segments(line: str) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    pos = 0
    for match in _SHELL_PART.finditer(line):
        if pos != match.start():
            return [line]  # Unbalanced quotes or an unsupported shell escape.
        pos = match.end()
        part = match[0]
        if part.startswith("#"):
            pos = len(line)
            break
        if re.fullmatch(r"[;&|]+", part):
            chunks.append("".join(current))
            current = []
        else:
            current.append(part)
    if pos != len(line):
        return [line]
    chunks.append("".join(current))
    return [chunk.strip() for chunk in chunks if chunk.strip()]


def _npm_publish_mode(args: list[str], scopes: tuple[dict, ...]) -> str:
    # npm CLI flags take precedence over environment configuration. GitHub
    # overlays step environment variables on the job and workflow scopes.
    env: dict[str, str] = {}
    for scope in scopes:
        values = scope.get("env")
        if values is None:
            continue
        if not isinstance(values, dict):
            return "unresolved-publish-mode"
        env.update(
            {
                k: str(v).lower()
                for k, v in values.items()
                if isinstance(k, str) and k.lower() == "npm_config_dry_run"
            }
        )
    settings = set(env.values()) or {"false"}
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg == "--dry-run" and args[i + 1 : i + 2] in (["true"], ["false"]):
            settings = {args[i + 1]}
        elif arg in {"--dry-run", "--no-dry-run"}:
            settings = {"true" if arg == "--dry-run" else "false"}
        elif arg.startswith("--dry-run="):
            settings = {arg.partition("=")[2].lower()}
    if settings == {"true"}:
        return "dry-run"
    if settings == {"false"}:
        return "publish"
    return "unresolved-publish-mode"


def _classify(line: str, scopes: tuple[dict, ...]) -> tuple[str, str] | None:
    try:
        args = shlex.split(line, comments=True)
    except ValueError:
        return None
    if not args or args[0] in {"echo", "printf", "#"}:
        return None
    if args[0] in {"npx", "uvx"}:
        args = args[1:]
    if len(args) < 2:
        return None
    tool, command = args[0].rsplit("/", 1)[-1], args[1]
    if (tool, command) == ("npm", "publish"):
        return _npm_publish_mode(args[2:], scopes), tool
    if (tool, command) in {("cargo", "publish"), ("twine", "upload")}:
        return ("dry-run", tool) if "--dry-run" in args else ("publish", tool)
    if tool == "vercel" and command == "deploy":
        if "--prod" in args or "--target=production" in args:
            return "production-deploy", "Vercel"
        if "--target" in args:
            pos = args.index("--target") + 1
            if pos < len(args) and args[pos] in {"preview", "production"}:
                return (
                    "production-deploy" if args[pos] == "production" else "preview-deploy",
                    "Vercel",
                )
            return "unresolved-deploy-target", "Vercel"
        if any(a.startswith(("--target=", "--prod=")) and a != "--target=preview" for a in args):
            return "unresolved-deploy-target", "Vercel"
        if any("$" in a and "token" not in a.lower() for a in args[2:]):
            return "unresolved-deploy-target", "Vercel"
        return "preview-deploy", "Vercel"
    return None


def _dependency_guard(
    jobs: dict, job: dict, branch: str, visited: set[str]
) -> tuple[str, str] | None:
    needs = job.get("needs")
    if not needs or str(job.get("if", "")).strip() in {"always()", "${{ always() }}"}:
        return None
    if isinstance(needs, str):
        needs = [needs]
    if not isinstance(needs, list):
        return "uncertain", "Unrecognized job dependencies"
    for name in needs:
        if not isinstance(name, str) or name in visited or not isinstance(jobs.get(name), dict):
            return "uncertain", "Job dependency could not be resolved"
        parent = jobs[name]
        parent_state = _guard(parent.get("if"), branch) or _dependency_guard(
            jobs, parent, branch, visited | {name}
        )
        if parent_state:
            if parent_state[0] == "excluded" and job.get("if") is None:
                return "excluded", "A required job is skipped on this push"
            return "uncertain", "A required job may be skipped on this push"
    return None


def _workflow(text: str, path: str, branch: str, changes: list[str] | None) -> list[dict]:
    doc = yaml.safe_load(text)
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(doc, dict) or node is None or not isinstance(doc.get("jobs"), dict):
        raise ValueError("Unrecognized workflow structure")
    loc = _locations(node)
    trigger = _trigger(doc.get("on", doc.get(True)), branch, changes)
    effects = []
    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            raise ValueError("Invalid job")
        job_path = ("jobs", str(job_id))
        job_guard = _guard(job.get("if"), branch)
        dependency_guard = _dependency_guard(doc["jobs"], job, branch, {str(job_id)})
        env = job.get("environment")
        if isinstance(env, dict):
            env = env.get("name")

        def add(
            kind: str,
            dst: str | None,
            line: int,
            condition: Any = None,
            *,
            shell_conditional: bool = False,
        ) -> None:
            states = [trigger, job_guard, dependency_guard, _guard(condition, branch)]
            if shell_conditional:
                states.append(("uncertain", "Command is in conditional shell code"))
            status, reason = next(
                (s for wanted in ("excluded", "uncertain") for s in states if s and s[0] == wanted),
                trigger,
            )
            uncertainty = {
                "unresolved-publish-mode": "npm dry-run configuration requires runtime values",
                "unresolved-deploy-target": "Deployment target needs runtime values",
                "unresolved-command": "Command behavior is outside the recognized direct operations",
                "unresolved-action": "Action implementation has not been analyzed",
                "unresolved-reusable-workflow": "Reusable workflow implementation has not been analyzed",
            }.get(kind)
            if status == "eligible" and "if" in job:
                reason += "; job condition allows this push"
            effects.append(
                dict(
                    event="push",
                    trigger_line=loc.get(("on", "push"), loc.get(("on",))),
                    job_condition_line=loc.get((*job_path, "if")),
                    ref=f"refs/heads/{branch}",
                    job=str(job_id),
                    environment=env if isinstance(env, str) else None,
                    destination=dst,
                    effect=kind,
                    status=status,
                    reason=reason,
                    uncertainty=uncertainty,
                    path=path,
                    line=line,
                )
            )

        if "uses" in job:
            add("unresolved-reusable-workflow", None, loc[(*job_path, "uses")])
        for i, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                raise ValueError("Invalid workflow step")
            key = (*job_path, "steps", i)
            run = step.get("run")
            if isinstance(run, str):
                source = loc[(*key, "run")]
                # A block scalar starts after its indicator; folded/aliased bodies
                # are cited at the YAML field rather than a guessed shell line.
                row = text.splitlines()[source - 1]
                literal = bool(re.search(r"\brun:\s*\|[-+\d]*\s*(?:#.*)?$", row))
                control = bool(
                    re.search(
                        r"(?:^|\n)\s*(?:if |while |until |for |case |function |[\w-]+\s*\(\))|<<",
                        run,
                    )
                )
                for offset, line in enumerate(run.splitlines()):
                    for command in _segments(line):
                        found = _classify(command, (doc, job, step))
                        if found:
                            add(
                                *found,
                                source + 1 + offset if literal else source,
                                step.get("if"),
                                shell_conditional=control or "||" in line,
                            )
                        elif not command.startswith(("echo ", "printf ")):
                            add("unresolved-command", None, source, step.get("if"))
            elif isinstance(step.get("uses"), str):
                action = step["uses"].split("@", 1)[0]
                if action in {"pypa/gh-action-pypi-publish", "softprops/action-gh-release"}:
                    add("publish", action, loc[(*key, "uses")], step.get("if"))
                elif action != "actions/checkout":
                    add("unresolved-action", None, loc[(*key, "uses")], step.get("if"))
    return list({json.dumps(e, sort_keys=True): e for e in effects}.values())


def _sha(repo: Path, rev: str) -> str:
    return (
        _git(repo, "rev-parse", "--verify", "--end-of-options", rev + "^{commit}").decode().strip()
    )


def hypothetical_report(
    repo: Path, base: str, branch: str, changed_paths: list[str] | None = None
) -> dict:
    """Inspect an explicitly hypothetical push against one branch snapshot."""
    base = _sha(repo, base)
    tree = _tree(repo, base)
    return _analyze(repo, base, None, branch, changed_paths, tree, tree, tree)


def report(repo: Path, base: str, head: str, branch: str) -> dict:
    """Overlay changed workflow blobs on the base, keeping divergent edits unknown."""
    base, head = _sha(repo, base), _sha(repo, head)
    if base == head:
        raise ValueError("Base and head are identical; use --hypothetical to inspect a branch")
    ancestor = _git(repo, "merge-base", base, head).decode().strip()
    paths = _git(repo, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", ancestor, head)
    changes = [p.decode(errors="surrogateescape") for p in paths.split(b"\0") if p]
    original, target, proposed = (_tree(repo, rev) for rev in (ancestor, base, head))
    result = _analyze(
        repo, base, head, branch, changes if ancestor == base else None, original, target, proposed
    )
    result["pr_changed_paths"] = changes
    return result


def _analyze(
    repo: Path,
    base: str,
    head: str | None,
    branch: str,
    changes: list[str] | None,
    original: dict[str, str],
    target: dict[str, str],
    proposed: dict[str, str],
) -> dict:
    effects, errors = [], []
    for path in sorted(target.keys() | proposed.keys()):
        a, b, h = original.get(path), target.get(path), proposed.get(path)
        if h == a or h == b:
            blob = b
        elif b == a:
            blob = h
        else:
            errors.append({"path": path, "reason": "Both branches changed this workflow"})
            continue
        if blob:
            try:
                content = _git(repo, "cat-file", "blob", blob).decode()
                effects.extend(_workflow(content, path, branch, changes))
            except (ValueError, KeyError, TypeError, yaml.YAMLError, RecursionError):
                errors.append({"path": path, "reason": "Workflow could not be analyzed"})
    return dict(
        base=base,
        head=head,
        scenario="hypothetical" if head is None else "proposed-merge",
        branch=branch,
        changed_paths=changes,
        effects=effects,
        errors=errors,
        status="partial" if errors else "analyzed",
        scope="Configured workflow effects on a push to the stated default branch. Runtime success and external deployment integrations are unknown.",
    )


def _render(result: dict) -> str:
    lines = [f"{result['scenario']} on {result['branch']}"]
    counts: Counter[str] = Counter()
    for e in result["effects"]:
        if e["status"] == "eligible" and not e["effect"].startswith("unresolved"):
            destination = f" ({e['destination']})" if e["destination"] else ""
            lines.append(f"{e['effect']}{destination} in {e['job']} at {e['path']}:{e['line']}")
        elif e["status"] == "excluded":
            counts[f"Excluded: {e['reason']}"] += 1
        elif e["uncertainty"]:
            counts[e["uncertainty"]] += 1
        else:
            counts[e["reason"]] += 1
    if len(lines) == 1:
        lines.append("No recognized eligible deployment or publishing operation.")
    lines.extend(f"{why}: {n}" for why, n in sorted(counts.items()))
    lines.extend(f"{e['path']}: {e['reason']}" for e in result["errors"])
    lines.append(result["scope"])
    return "\n".join(lines)


def merge_effects(
    repo: Path,
    json_output: bool = typer.Option(
        False, "--json", help="Include evidence for each workflow step."
    ),
    base: str = typer.Option(...),
    head: str | None = typer.Option(None),
    hypothetical: bool = typer.Option(False, "--hypothetical"),
    changed_path: list[str] | None = typer.Option(
        None, "--changed-path", help="Hypothetical path, repeatable."
    ),
    branch: str = typer.Option(..., help="Name of the target default branch."),
) -> None:
    """Describe configured effects of merging two local revisions (JSON)."""
    try:
        if hypothetical and head is None:
            result = hypothetical_report(repo, base, branch, changed_path or None)
        elif not hypothetical and head is not None and not changed_path:
            result = report(repo, base, head, branch)
        else:
            raise ValueError(
                "Choose --head or --hypothetical; --changed-path requires --hypothetical"
            )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    typer.echo(json.dumps(result, indent=2) if json_output else _render(result))
    if result["errors"]:
        raise typer.Exit(3)
