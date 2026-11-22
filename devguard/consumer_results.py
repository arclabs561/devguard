"""Import caller-supplied first-party consumer evidence without opening its references."""

import json
from pathlib import Path
from typing import Annotated, Literal, Self

import typer
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Revision = Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]


class EvidenceModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")


class Artifact(EvidenceModel):
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    package: Text | None = None
    version: Text | None = None
    registry: Text | None = None


class Observation(EvidenceModel):
    revision: Revision
    outcome: Literal["pass", "fail", "skip", "error"]
    exit_code: int | None = None
    evidence: Text
    command: list[Text] | None = None
    reason: Text | None = None
    artifact: Artifact | None = None

    @model_validator(mode="after")
    def explain_unavailable(self) -> Self:
        if self.outcome in ("skip", "error") and not self.reason:
            raise ValueError("skip and error observations require a reason")
        return self


class Case(EvidenceModel):
    fixture: Text
    assertion: Text
    tool: Text
    base: Observation | None = None
    head: Observation


class Evidence(EvidenceModel):
    schema_version: int = Field(ge=1, le=1)
    repository: Text
    cases: list[Case] = Field(min_length=1)

    @model_validator(mode="after")
    def distinct_cases(self) -> Self:
        keys = [(case.fixture, case.assertion) for case in self.cases]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate fixture and assertion")
        return self


def _decision(case: Case, head: str, base: str | None) -> tuple[str, str]:
    if case.head.revision != head:
        return "inconclusive", "Head evidence is stale for the requested revision."
    if base is not None and case.base is None:
        return "inconclusive", "Missing evidence for the requested base."
    if case.base is not None:
        if base is None:
            return (
                "inconclusive",
                "Supply the expected base revision to compare these observations.",
            )
        if case.base.revision != base:
            return "inconclusive", "Base evidence is stale for the requested revision."
        if base == head and case.base.outcome != case.head.outcome:
            return "inconclusive", "Conflicting observations at the same revision."
        if case.base.artifact and case.head.artifact:
            for field in ("package", "registry"):
                old = getattr(case.base.artifact, field)
                new = getattr(case.head.artifact, field)
                if old and new and old != new:
                    return "inconclusive", f"Compared artifacts identify different {field} values."
        if case.base.outcome != "pass":
            return "inconclusive", f"Base {case.base.outcome}: {case.base.reason or case.assertion}"
    if case.head.outcome in ("skip", "error"):
        return "inconclusive", f"Head {case.head.outcome}: {case.head.reason}"
    if case.base is None:
        return f"observed_{case.head.outcome}", "Single-revision observation."
    if case.head.outcome == "fail":
        return "regression", "The same assertion passed on base and failed on head."
    return "pass", "The assertion passed on both revisions."


class Scope(EvidenceModel):
    repository: Text
    head: Revision
    base: Revision | None = None


def import_results(evidence: Evidence, scope: Scope) -> dict:
    results = []
    for case in evidence.cases:
        if evidence.repository != scope.repository:
            decision, reason = (
                "inconclusive",
                "The evidence repository differs from the requested one.",
            )
        else:
            decision, reason = _decision(case, scope.head, scope.base)
        results.append(
            {**case.model_dump(exclude_none=True), "decision": decision, "reason": reason}
        )
    return {
        "schema_version": 1,
        "repository": evidence.repository,
        "requested": scope.model_dump(exclude_none=True),
        "cases": results,
    }


def consumer_results(
    report: Path = typer.Argument(..., help="JSON evidence from a trusted producer."),
    repository: str = typer.Option(..., "--repository", help="Expected repository identifier."),
    head: str = typer.Option(..., "--head", help="Expected full head or combined-tree commit ID."),
    base: str | None = typer.Option(None, "--base", help="Expected full comparison commit ID."),
) -> None:
    """Compare recorded consumer assertions at explicit revisions and emit JSON."""
    try:
        scope = Scope(repository=repository, head=head, base=base)
        evidence = Evidence.model_validate_json(report.read_bytes())
    except (ValueError, OSError) as error:
        if isinstance(error, ValidationError):
            messages = [
                ".".join(map(str, item["loc"])) + ": " + item["msg"]
                for item in error.errors(include_input=False, include_url=False)
            ]
        else:
            messages = ["Could not read evidence file."]
        typer.echo(json.dumps({"errors": messages}))
        raise typer.Exit(code=3) from None

    result = import_results(evidence, scope)
    typer.echo(json.dumps(result, indent=2))
    decisions = {case["decision"] for case in result["cases"]}
    if decisions & {"regression", "observed_fail"}:
        raise typer.Exit(code=1)
    if "inconclusive" in decisions:
        raise typer.Exit(code=3)
