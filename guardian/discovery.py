"""Agnostic discovery engine based on spec rules."""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from guardian.spec import DiscoveryRule, MonitorSpec

logger = logging.getLogger(__name__)


def _parse_json_robustly(output: str) -> Any | None:
    """Parse JSON from CLI output, handling common issues like update banners.

    Many CLI tools (npm, gh, etc.) print non-JSON text like "Update available!"
    before or after the actual JSON. This function extracts the JSON portion.
    """
    output = output.strip()
    if not output:
        return None

    # Try direct parse first (fast path)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass

    # Find JSON object or array boundaries
    # Look for first { or [ and matching last } or ]
    obj_start = output.find("{")
    arr_start = output.find("[")

    if obj_start == -1 and arr_start == -1:
        return None

    # Determine which comes first
    if obj_start == -1:
        start_char, end_char = "[", "]"
        start_idx = arr_start
    elif arr_start == -1:
        start_char, end_char = "{", "}"
        start_idx = obj_start
    else:
        if obj_start < arr_start:
            start_char, end_char = "{", "}"
            start_idx = obj_start
        else:
            start_char, end_char = "[", "]"
            start_idx = arr_start

    # Find the matching end
    end_idx = output.rfind(end_char)
    if end_idx == -1 or end_idx <= start_idx:
        return None

    json_str = output[start_idx : end_idx + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        logger.debug(f"Failed to parse extracted JSON: {json_str[:100]}...")
        return None


class DiscoveryResult:
    """Results from auto-discovery."""

    def __init__(self):
        self.resources: dict[str, list[Any]] = {}
        self.errors: list[str] = []
        self.metadata: dict[str, Any] = {}

    def add_resource(self, resource_type: str, value: Any) -> None:
        """Add a discovered resource."""
        if resource_type not in self.resources:
            self.resources[resource_type] = []
        if value not in self.resources[resource_type]:
            self.resources[resource_type].append(value)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "resources": self.resources,
            "errors": self.errors,
            "metadata": self.metadata,
        }


async def execute_cli_command(
    command: str, parser: str, extract_path: str | None, timeout: int, username: str | None = None
) -> list[Any]:
    """Execute a CLI command and parse results."""
    results = []

    # Replace {username} placeholder if present
    if username and "{username}" in command:
        command = command.replace("{username}", username)

    try:
        # Split command into parts
        cmd_parts = command.split()
        if not cmd_parts:
            return results

        result = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=timeout,
        )
        stdout, stderr = await result.communicate()

        if result.returncode != 0:
            logger.debug(f"Command failed: {command} (exit code {result.returncode})")
            return results

        output = stdout.decode().strip()

        if parser == "json":
            data = _parse_json_robustly(output)
            if data is not None:
                if extract_path:
                    results = _extract_json_path(data, extract_path)
                else:
                    results = [data] if data else []
        elif parser == "json_lines":
            for line in output.split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        pass
        elif parser == "lines":
            results = [line.strip() for line in output.split("\n") if line.strip()]
        elif parser == "text":
            if output:
                results = [output]
        else:
            logger.warning(f"Unknown parser: {parser}")

    except TimeoutError:
        logger.warning(f"Command timed out: {command}")
    except Exception as e:
        logger.debug(f"Error executing command: {command}: {e}")

    return results


def _extract_json_path(data: Any, path: str) -> list[Any]:
    """Extract values from JSON using a simple path syntax."""
    results = []

    # Simple path extraction
    # Supports: "key", "key.subkey", "[].key", "dependencies.keys()"
    try:
        if path.endswith(".keys()"):
            # Extract keys from a dict
            key_path = path[:-7]
            obj = _get_json_value(data, key_path)
            if isinstance(obj, dict):
                results = list(obj.keys())
        elif path.startswith("[].") or path.startswith("[]."):
            # Array extraction
            key = path[3:]
            if isinstance(data, list):
                for item in data:
                    value = _get_json_value(item, key)
                    if value is not None:
                        results.append(value)
        else:
            value = _get_json_value(data, path)
            if value is not None:
                results = [value] if not isinstance(value, list) else value
    except Exception as e:
        logger.debug(f"Error extracting JSON path {path}: {e}")

    return results


def _get_json_value(data: Any, path: str) -> Any:
    """Get a value from nested JSON using dot notation."""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
        if current is None:
            return None
    return current


async def scan_files(
    base_path: Path,
    pattern: str,
    extractor: str,
    extract_path: str | None,
    timeout: int,
) -> list[Any]:
    """Scan files matching a pattern and extract data."""
    results = []
    start_time = asyncio.get_event_loop().time()

    try:
        # Expand ~ in pattern
        if pattern.startswith("~/"):
            pattern = str(Path.home() / pattern[2:])
        elif not pattern.startswith("/"):
            # Relative to base_path
            search_path = base_path / pattern
        else:
            search_path = Path(pattern)

        # Handle glob patterns
        if "**" in pattern or "*" in pattern:
            for file_path in base_path.rglob(
                pattern.replace("**/", "").replace("~", str(Path.home()))
            ):
                if (asyncio.get_event_loop().time() - start_time) > timeout:
                    break
                try:
                    extracted = _extract_from_file(file_path, extractor, extract_path)
                    if extracted:
                        results.extend(extracted if isinstance(extracted, list) else [extracted])
                except Exception as e:
                    logger.debug(f"Error processing {file_path}: {e}")
        else:
            # Single file
            if search_path.exists():
                extracted = _extract_from_file(search_path, extractor, extract_path)
                if extracted:
                    results.extend(extracted if isinstance(extracted, list) else [extracted])
    except Exception as e:
        logger.warning(f"Error scanning files: {e}")

    return results


def _extract_from_file(file_path: Path, extractor: str, extract_path: str | None) -> Any:
    """Extract data from a file based on extractor type."""
    try:
        content = file_path.read_text()

        if extractor == "json_path":
            data = json.loads(content)
            if extract_path:
                return _extract_json_path(data, extract_path)
            return data
        elif extractor == "yaml_path":
            import yaml

            data = yaml.safe_load(content)
            if extract_path:
                return _extract_json_path(data, extract_path)  # Same logic works for YAML
            return data
        elif extractor == "regex":
            if extract_path:
                matches = re.findall(extract_path, content)
                return list(set(matches))  # Remove duplicates
            return []
        elif extractor == "raw":
            return content.strip()
        else:
            logger.warning(f"Unknown extractor: {extractor}")
            return None
    except Exception as e:
        logger.debug(f"Error extracting from {file_path}: {e}")
        return None


async def discover_from_rule(
    rule: DiscoveryRule, base_path: Path | None = None, username: str | None = None
) -> list[Any]:
    """Discover resources using a single rule."""
    if not rule.enabled:
        return []

    if base_path is None:
        base_path = Path.home() / "Documents" / "dev"

    if rule.method == "cli":
        if not rule.command:
            logger.warning(f"Rule {rule.name} has method=cli but no command")
            return []
        return await execute_cli_command(
            rule.command, rule.command_parser or "text", rule.extract_path, rule.timeout, username
        )
    elif rule.method == "file_scan":
        if not rule.file_pattern:
            logger.warning(f"Rule {rule.name} has method=file_scan but no file_pattern")
            return []
        return await scan_files(
            base_path,
            rule.file_pattern,
            rule.file_extractor or "raw",
            rule.extract_path,
            rule.timeout,
        )
    elif rule.method == "api":
        # API-based discovery would go here
        logger.warning(f"API method not yet implemented for rule {rule.name}")
        return []
    elif rule.method == "custom":
        # Custom discovery would go here
        logger.warning(f"Custom method not yet implemented for rule {rule.name}")
        return []
    else:
        logger.warning(f"Unknown method: {rule.method} for rule {rule.name}")
        return []


async def discover_all(
    spec: MonitorSpec, base_path: Path | None = None, username: str | None = None
) -> DiscoveryResult:
    """Run all discovery rules from a spec."""
    result = DiscoveryResult()

    # Get username if needed
    if not username:
        # Try to get from a username discovery rule
        username_rules = [r for r in spec.discovery_rules if r.type == "username"]
        if username_rules:
            try:
                username_results = await discover_from_rule(username_rules[0], base_path)
                if username_results:
                    username = username_results[0]

            except Exception:
                pass

    # Run all discovery rules
    tasks = []
    for rule in spec.discovery_rules:
        if rule.type != "username":  # Already handled
            tasks.append(discover_from_rule(rule, base_path, username))

    try:
        rule_results = await asyncio.gather(*tasks, return_exceptions=True)

        for rule, rule_result in zip(spec.discovery_rules, rule_results):
            if isinstance(rule_result, Exception):
                result.errors.append(f"{rule.name}: {str(rule_result)}")
            elif isinstance(rule_result, list):
                for value in rule_result:
                    result.add_resource(rule.type, value)
    except Exception as e:
        result.errors.append(f"Discovery error: {str(e)}")

    # Add manual resources
    for resource_type, resources in spec.manual_resources.items():
        for resource in resources:
            result.add_resource(resource_type, resource)

    return result
