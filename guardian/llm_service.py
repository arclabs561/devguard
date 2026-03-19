"""LLM service for Guardian judgements and content generation."""

import json
import logging
from typing import Any

from guardian.config import Settings

logger = logging.getLogger(__name__)


class LLMService:
    """Service for LLM-powered judgements and content generation."""

    def __init__(self, settings: Settings):
        """Initialize LLM service with settings."""
        self.settings = settings
        self._client = None

    def _get_client(self):
        """Get LLM client (Anthropic, OpenAI, or OpenRouter)."""
        if self._client is not None:
            return self._client

        # Prefer Anthropic if available
        if self.settings.anthropic_api_key:
            try:
                import anthropic

                self._client = (
                    "anthropic",
                    anthropic.Anthropic(api_key=str(self.settings.anthropic_api_key)),
                )
                return self._client
            except ImportError:
                logger.debug("anthropic package not installed")
            except Exception as e:
                logger.debug(f"Failed to initialize Anthropic client: {e}")

        # Fallback to OpenAI
        if self.settings.openai_api_key:
            try:
                import openai

                self._client = ("openai", openai.OpenAI(api_key=str(self.settings.openai_api_key)))
                return self._client
            except ImportError:
                logger.debug("openai package not installed")
            except Exception as e:
                logger.debug(f"Failed to initialize OpenAI client: {e}")

        # Fallback to OpenRouter
        if self.settings.openrouter_api_key:
            try:
                import openai

                self._client = (
                    "openrouter",
                    openai.OpenAI(
                        api_key=str(self.settings.openrouter_api_key),
                        base_url="https://openrouter.ai/api/v1",
                    ),
                )
                return self._client
            except ImportError:
                logger.debug("openai package not installed for OpenRouter")
            except Exception as e:
                logger.debug(f"Failed to initialize OpenRouter client: {e}")

        return None

    async def should_send_email(
        self, report: dict[str, Any], email_history: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Use LLM to determine if email should be sent based on report and history.

        Returns:
            {
                "should_send": bool,
                "reasoning": str,
                "priority": "critical" | "high" | "medium" | "low",
                "summary": str
            }
        """
        client_info = self._get_client()
        if not client_info:
            # Fallback to rule-based decision
            return {
                "should_send": self._rule_based_should_send(report),
                "reasoning": "LLM not available, using rule-based decision",
                "priority": "high"
                if report.get("summary", {}).get("critical_vulnerabilities", 0) > 0
                else "medium",
                "summary": "Rule-based analysis",
            }

        provider, client = client_info

        # Build context from recent history
        recent_history = email_history[-5:] if email_history else []
        history_context = ""
        if recent_history:
            history_context = "\nRecent email history:\n"
            for entry in recent_history:
                history_context += (
                    f"- {entry.get('timestamp', 'unknown')}: {entry.get('subject', 'N/A')}\n"
                )
                history_context += f"  Issues: {entry.get('summary', {})}\n"

        prompt = f"""You are a security operations analyst deciding whether to send an alert email.

Current report summary:
- Critical vulnerabilities: {report.get("summary", {}).get("critical_vulnerabilities", 0)}
- High priority findings: {report.get("summary", {}).get("high_findings", 0)}
- Critical findings: {report.get("summary", {}).get("critical_findings", 0)}
- Unhealthy deployments: {report.get("summary", {}).get("unhealthy_deployments", 0)}
- Failed checks: {report.get("summary", {}).get("failed_checks", 0)}
- Total vulnerabilities: {report.get("summary", {}).get("total_vulnerabilities", 0)}

{history_context}

Top issues:
{json.dumps(report.get("issues", {}), indent=2)[:1000]}

Analyze whether an email alert should be sent. Consider:
1. Severity and urgency of issues
2. Whether similar issues were recently reported (avoid alert fatigue)
3. Whether issues are new or ongoing
4. Business impact

Respond with JSON:
{{
    "should_send": true/false,
    "reasoning": "brief explanation",
    "priority": "critical" | "high" | "medium" | "low",
    "summary": "one sentence executive summary"
}}"""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.content[0].text
            elif provider in ("openai", "openrouter"):
                model = "gpt-4o-mini" if provider == "openai" else "anthropic/claude-3.5-sonnet"
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"} if provider == "openai" else None,
                )
                content = response.choices[0].message.content
            else:
                raise ValueError(f"Unknown provider: {provider}")

            # Parse JSON response
            result = json.loads(content)
            return {
                "should_send": result.get("should_send", True),
                "reasoning": result.get("reasoning", "LLM analysis"),
                "priority": result.get("priority", "medium"),
                "summary": result.get("summary", ""),
            }
        except Exception as e:
            logger.warning(f"LLM decision failed: {e}, falling back to rule-based")
            return {
                "should_send": self._rule_based_should_send(report),
                "reasoning": f"LLM error: {str(e)}",
                "priority": "high"
                if report.get("summary", {}).get("critical_vulnerabilities", 0) > 0
                else "medium",
                "summary": "Rule-based fallback",
            }

    def _rule_based_should_send(self, report: dict[str, Any]) -> bool:
        """Fallback rule-based decision."""
        summary = report.get("summary", {})
        return (
            summary.get("critical_vulnerabilities", 0) > 0
            or summary.get("critical_findings", 0) > 0
            or summary.get("high_findings", 0) > 0
            or summary.get("unhealthy_deployments", 0) > 0
            or summary.get("failed_checks", 0) > 0
        )

    async def generate_subject_line(self, report: dict[str, Any], priority: str = "medium") -> str:
        """Generate contextual subject line using LLM."""
        client_info = self._get_client()
        if not client_info:
            return self._generate_subject_fallback(report)

        provider, client = client_info

        prompt = f"""Generate a concise, actionable email subject line for a security monitoring alert.

Report summary:
- Priority: {priority}
- Critical vulnerabilities: {report.get("summary", {}).get("critical_vulnerabilities", 0)}
- High findings: {report.get("summary", {}).get("high_findings", 0)}
- Unhealthy deployments: {report.get("summary", {}).get("unhealthy_deployments", 0)}

Top issues:
{json.dumps(report.get("issues", {}), indent=2)[:500]}

Generate a subject line that:
1. Starts with "Guardian Security Report -"
2. Indicates urgency level
3. Highlights the most critical issue(s)
4. Is under 100 characters
5. Is actionable and specific

Respond with ONLY the subject line, no quotes or explanation."""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=100,
                    messages=[{"role": "user", "content": prompt}],
                )
                subject = response.content[0].text.strip().strip('"').strip("'")
            elif provider in ("openai", "openrouter"):
                model = "gpt-4o-mini" if provider == "openai" else "anthropic/claude-3.5-sonnet"
                response = client.chat.completions.create(
                    model=model, messages=[{"role": "user", "content": prompt}], max_tokens=100
                )
                subject = response.choices[0].message.content.strip().strip('"').strip("'")
            else:
                raise ValueError(f"Unknown provider: {provider}")

            # Ensure it starts with prefix
            if not subject.startswith("Guardian Security Report"):
                subject = f"Guardian Security Report - {subject}"

            return subject[:120]  # Safety limit
        except Exception as e:
            logger.warning(f"LLM subject generation failed: {e}, using fallback")
            return self._generate_subject_fallback(report)

    def _generate_subject_fallback(self, report: dict[str, Any]) -> str:
        """Fallback subject line generation."""
        summary = report.get("summary", {})
        critical = summary.get("critical_vulnerabilities", 0)
        unhealthy = summary.get("unhealthy_deployments", 0)

        if critical > 0 or unhealthy > 0:
            return f"Guardian Security Report - URGENT: {critical} critical, {unhealthy} unhealthy"
        elif summary.get("total_vulnerabilities", 0) > 0:
            return f"Guardian Security Report - ALERT: {summary.get('total_vulnerabilities', 0)} vulnerabilities"
        else:
            return "Guardian Security Report - Status: All systems healthy"

    async def generate_executive_summary(
        self, report: dict[str, Any], priority: str = "medium"
    ) -> str:
        """Generate executive summary using LLM."""
        client_info = self._get_client()
        if not client_info:
            return self._generate_summary_fallback(report)

        provider, client = client_info

        prompt = f"""Generate a concise executive summary (2-3 sentences) for a security monitoring report.

Priority: {priority}

Report summary:
{json.dumps(report.get("summary", {}), indent=2)}

Top issues:
{json.dumps(report.get("issues", {}), indent=2)[:800]}

Write a brief, actionable summary that:
1. States the overall security posture
2. Highlights the most critical issues requiring attention
3. Provides context on urgency

Respond with ONLY the summary text, no markdown or formatting."""

        try:
            if provider == "anthropic":
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=200,
                    messages=[{"role": "user", "content": prompt}],
                )
                summary = response.content[0].text.strip()
            elif provider in ("openai", "openrouter"):
                model = "gpt-4o-mini" if provider == "openai" else "anthropic/claude-3.5-sonnet"
                response = client.chat.completions.create(
                    model=model, messages=[{"role": "user", "content": prompt}], max_tokens=200
                )
                summary = response.choices[0].message.content.strip()
            else:
                raise ValueError(f"Unknown provider: {provider}")

            return summary
        except Exception as e:
            logger.warning(f"LLM summary generation failed: {e}, using fallback")
            return self._generate_summary_fallback(report)

    def _generate_summary_fallback(self, report: dict[str, Any]) -> str:
        """Fallback summary generation."""
        summary = report.get("summary", {})
        critical = summary.get("critical_vulnerabilities", 0)
        unhealthy = summary.get("unhealthy_deployments", 0)

        if critical > 0:
            return f"Critical security issues detected: {critical} critical vulnerabilities and {unhealthy} unhealthy deployments require immediate attention."
        elif unhealthy > 0:
            return f"Infrastructure issues detected: {unhealthy} unhealthy deployments need investigation."
        elif summary.get("total_vulnerabilities", 0) > 0:
            return f"Security vulnerabilities detected: {summary.get('total_vulnerabilities', 0)} total vulnerabilities found across monitored systems."
        else:
            return "All systems are operating normally with no critical security issues detected."

    async def analyze_project_flaudit(
        self,
        prompt: str,
        model_id: str = "google/gemini-2.5-flash",
        severity_guidance: str | None = None,
        public_repo_mode: bool = False,
    ) -> str:
        """Analyze project files (README/impl/tests) for flaws via OpenRouter + Gemini.

        Prefers OpenRouter when model_id is a Google model (google/*) and
        openrouter_api_key is set. Falls back to Anthropic/OpenAI otherwise.

        severity_guidance: optional custom guidance; if unset, a default calibration is used.
        public_repo_mode: use a stricter prompt for public crates (higher bar for docs/API/quality).

        Returns raw LLM response text (JSON expected).
        """
        default_severity = (
            "Severity calibration: Reserve **critical** for security issues with a clear "
            "exploit path (e.g. command injection with **external** user-controlled input). "
            "Use **high** for correctness bugs or major doc/impl drift. Use **medium** for "
            "doc gaps, test coverage, refactor suggestions. Use **low** for style, minor "
            "duplication, or unverified concerns. Do NOT use critical for: internal scripts, "
            "trusted inputs, or theoretical risks without an exploit path."
        )
        severity_block = severity_guidance if severity_guidance else default_severity

        if public_repo_mode:
            system_prompt = f"""You are a **critical** code quality auditor for **public** open-source crates. Your job is to be as strict as possible so maintainers can improve public-facing quality. Assume a first-time user will rely on the README and published API; any drift or missing step is a real failure.

Find flaws in these categories:
1. **readme_impl_drift**: README claims, quickstart steps, or API descriptions that do not match the implementation. Flag if the README example would not compile/run as written, or if documented functions/signatures are wrong or missing.
2. **readme_tests_mismatch**: Tests cover behavior not documented in README, or README describes behavior not tested. Public API surface should be both documented and tested.
3. **rules_violation**: Code or README disobeys project/workspace rules (e.g. no emojis, no marketing tone, truth boundary). Set **rule_ref** to the rule filename (e.g. user-core.mdc).
4. **other**: Missing or vague doc comments on public items, Cargo.toml/crate metadata inconsistent with README, security or safety considerations not mentioned, unclear error handling contract, or anything that would confuse or mislead a public user.

Be **critical**: prefer flagging a possible issue (medium/low) over missing a real one. If the README quickstart is incomplete (e.g. missing use statement or wrong path), that is at least **high**. If public API has no doc comment, that is at least **medium**. Do not be lenient because the crate is small.

{severity_block}

Respond with JSON only:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "category": "readme_impl_drift|readme_tests_mismatch|rules_violation|other",
      "description": "concise description of the flaw",
      "file_ref": "path or section reference if applicable",
      "suggestion": "optional fix suggestion",
      "rule_ref": "for rules_violation only: rule filename e.g. user-core.mdc"
    }}
  ]
}}

If no flaws found, return {{"findings": []}}.
Return at most 16 findings, prioritized by severity (critical > high > medium > low). Keep each description to one sentence. Be concrete: cite file paths and line references."""
        else:
            system_prompt = f"""You are a code quality auditor. Analyze the provided project files (README, implementation, tests, and optional rules).

Find flaws in these categories:
1. **readme_impl_drift**: README claims or describes behavior that does not match the implementation.
2. **readme_tests_mismatch**: Tests cover behavior not documented in README, or README describes behavior not tested.
3. **rules_violation**: Code or README disobeys project/workspace rules (e.g. invariants: no emojis, no marketing tone, truth boundary, etc.). When citing a rules_violation, set **rule_ref** to the rule filename (e.g. user-core.mdc).
4. **other**: Other quality issues (missing tests, unclear docs, etc.).

{severity_block}

Respond with JSON only:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "category": "readme_impl_drift|readme_tests_mismatch|rules_violation|other",
      "description": "concise description of the flaw",
      "file_ref": "path or section reference if applicable",
      "suggestion": "optional fix suggestion",
      "rule_ref": "for rules_violation only: rule filename e.g. user-core.mdc"
    }}
  ]
}}

If no flaws found, return {{"findings": []}}.
Return at most 12 findings, prioritized by severity (critical > high > medium > low). Keep each description to one sentence.
Be concrete: cite specific file paths and line references when possible."""

        # Prefer OpenRouter for Google models when key is available
        use_openrouter = (
            model_id.startswith("google/")
            and self.settings.openrouter_api_key is not None
        )
        if use_openrouter:
            try:
                import openai
                client = openai.OpenAI(
                    api_key=str(self.settings.openrouter_api_key.get_secret_value()),
                    base_url="https://openrouter.ai/api/v1",
                )
                kwargs = {
                    "model": model_id,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 8000,
                }
                # Try JSON mode first; fallback if model doesn't support it
                try:
                    response = client.chat.completions.create(
                        **kwargs,
                        response_format={"type": "json_object"},
                    )
                except Exception:
                    response = client.chat.completions.create(**kwargs)
                return response.choices[0].message.content or "{}"
            except Exception as e:
                logger.warning(f"OpenRouter flaudit call failed: {e}")
                return json.dumps({"findings": [], "error": str(e)})

        client_info = self._get_client()
        if not client_info:
            return json.dumps({"findings": [], "error": "No LLM API key configured"})

        provider, client = client_info
        try:
            if provider == "openrouter":
                response = client.chat.completions.create(
                    model=model_id,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=8000,
                    response_format={"type": "json_object"},
                )
                return response.choices[0].message.content or "{}"
            elif provider == "anthropic":
                response = client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=4000,
                    messages=[
                        {"role": "user", "content": f"{system_prompt}\n\n---\n\n{prompt}"},
                    ],
                )
                return response.content[0].text if response.content else "{}"
            elif provider == "openai":
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=4000,
                )
                return response.choices[0].message.content or "{}"
            else:
                return json.dumps({"findings": [], "error": f"Unknown provider: {provider}"})
        except Exception as e:
            logger.warning(f"Project flaudit LLM call failed: {e}")
            return json.dumps({"findings": [], "error": str(e)})




