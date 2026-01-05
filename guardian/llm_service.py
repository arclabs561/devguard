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






