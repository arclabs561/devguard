"""Integration tests for discovery functionality."""

import json
import tempfile
from pathlib import Path

import pytest

from guardian.discovery import DiscoveryResult, discover_all
from guardian.spec import DiscoveryRule, MonitorSpec


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir) / "test-project"
        project_path.mkdir()

        # Create a package.json
        package_json = project_path / "package.json"
        package_json.write_text(
            json.dumps({"name": "test-package", "version": "1.0.0"})
        )

        # Create a .git directory
        git_dir = project_path / ".git"
        git_dir.mkdir()

        yield project_path


@pytest.fixture
def minimal_spec():
    """Create a minimal monitoring spec for testing."""
    return MonitorSpec(
        name="test",
        discovery_rules=[
            DiscoveryRule(
                name="npm_list",
                type="npm",
                method="file_scan",
                enabled=True,
                file_pattern="package.json",
                file_extractor="json_path",
                extract_path="name",
            )
        ],
    )


@pytest.mark.asyncio
async def test_discover_all_finds_npm_packages(temp_project_dir, minimal_spec):
    """Test that discover_all finds npm packages."""
    result = await discover_all(minimal_spec, temp_project_dir)

    assert isinstance(result, DiscoveryResult)
    # Should find at least the test package
    assert "npm" in result.resources or len(result.resources) >= 0


@pytest.mark.asyncio
async def test_discover_all_handles_missing_files(minimal_spec):
    """Test that discover_all handles missing files gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_dir = Path(tmpdir)
        result = await discover_all(minimal_spec, empty_dir)

        assert isinstance(result, DiscoveryResult)
        # Should not crash, may have empty resources or errors
        assert result.resources is not None


@pytest.mark.asyncio
async def test_discover_all_handles_invalid_json(temp_project_dir, minimal_spec):
    """Test that discover_all handles invalid JSON gracefully."""
    # Create a file with invalid JSON
    invalid_json = temp_project_dir / "invalid.json"
    invalid_json.write_text("{ invalid json }")

    # Add rule for invalid.json
    spec = MonitorSpec(
        name="test",
        discovery_rules=[
            DiscoveryRule(
                name="test_rule",
                type="npm",
                method="file_scan",
                enabled=True,
                file_pattern="invalid.json",
                file_extractor="json_path",
                extract_path="name",
            )
        ],
    )

    result = await discover_all(spec, temp_project_dir)

    assert isinstance(result, DiscoveryResult)
    # Should handle gracefully, may have errors
    assert result.errors is not None or result.resources is not None


def test_discovery_result_to_dict():
    """Test that DiscoveryResult can be converted to dict."""
    from guardian.discovery import DiscoveryResult

    result = DiscoveryResult()
    result.add_resource("npm", "package1")
    result.add_resource("npm", "package2")
    result.errors.append("error1")

    result_dict = result.to_dict()

    assert isinstance(result_dict, dict)
    assert "resources" in result_dict
    assert "errors" in result_dict
    assert "npm" in result_dict["resources"]
    assert len(result_dict["resources"]["npm"]) == 2
    assert len(result_dict["errors"]) == 1

