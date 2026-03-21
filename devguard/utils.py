"""Utility functions for devguard.

This module provides utilities for accessing external modules (like ops/agent)
without fragile path manipulation.
"""

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from devguard.config import Settings

logger = logging.getLogger(__name__)

# Cache for resolved paths
_resolved_paths: dict[str, Path | None] = {}


def get_ops_agent_path() -> Path | None:
    """Get the path to ops/agent directory.

    Returns None if not found. Uses cached result after first resolution.
    """
    cache_key = "ops_agent"
    if cache_key in _resolved_paths:
        return _resolved_paths[cache_key]

    # Try to find ops/agent relative to devguard
    devguard_path = Path(__file__).parent.parent.parent
    ops_agent_path = devguard_path.parent / "ops" / "agent"

    if ops_agent_path.exists() and ops_agent_path.is_dir():
        _resolved_paths[cache_key] = ops_agent_path
        return ops_agent_path

    _resolved_paths[cache_key] = None
    return None


def get_ops_config_path() -> Path | None:
    """Get the path to ops/config directory.

    Returns None if not found. Uses cached result after first resolution.
    """
    cache_key = "ops_config"
    if cache_key in _resolved_paths:
        return _resolved_paths[cache_key]

    devguard_path = Path(__file__).parent.parent.parent
    ops_config_path = devguard_path.parent / "ops" / "config"

    if ops_config_path.exists() and ops_config_path.is_dir():
        _resolved_paths[cache_key] = ops_config_path
        return ops_config_path

    _resolved_paths[cache_key] = None
    return None


def import_smart_email() -> Any:
    """Import smart_email module from ops/agent.

    Returns the module if found, None otherwise.
    Handles path manipulation internally.
    """
    ops_agent_path = get_ops_agent_path()
    if not ops_agent_path:
        return None

    try:
        # Add to path if not already there
        ops_agent_str = str(ops_agent_path)
        if ops_agent_str not in sys.path:
            sys.path.insert(0, ops_agent_str)

        import smart_email

        return smart_email
    except ImportError as e:
        logger.debug(f"Could not import smart_email: {e}")
        return None


def import_llm_service() -> Any:
    """Import LLMService from ops/agent.

    Returns the class if found, None otherwise.
    """
    ops_agent_path = get_ops_agent_path()
    if not ops_agent_path:
        return None

    try:
        ops_agent_str = str(ops_agent_path)
        if ops_agent_str not in sys.path:
            sys.path.insert(0, ops_agent_str)

        from llm_service import LLMService

        return LLMService
    except ImportError as e:
        logger.debug(f"Could not import LLMService: {e}")
        return None


def get_smart_email_db_path(settings: "Settings") -> Path:
    """Get the smart_email database path from settings or environment.

    Args:
        settings: Settings object with smart_email_db_path attribute

    Returns:
        Path to database file
    """
    db_path_str = getattr(settings, "smart_email_db_path", None)
    if db_path_str:
        return Path(db_path_str)

    import os

    db_path_str = os.getenv("SMART_EMAIL_DB", "/data/smart_email.db")
    return Path(db_path_str)


def get_budget_config_path() -> Path | None:
    """Get the path to ops/config/budget.yaml.

    Returns None if not found.
    """
    ops_config_path = get_ops_config_path()
    if not ops_config_path:
        return None

    budget_path = ops_config_path / "budget.yaml"
    if budget_path.exists():
        return budget_path

    return None


def load_budget_config() -> dict[str, Any]:
    """Load budget configuration from ops/config/budget.yaml.

    Returns empty dict if file not found or error loading.
    """
    budget_path = get_budget_config_path()
    if not budget_path:
        return {}

    try:
        import yaml

        with open(budget_path) as f:
            config = yaml.safe_load(f)
            return config.get("aws", {})
    except Exception as e:
        logger.debug(f"Failed to load budget config from {budget_path}: {e}")
        return {}


def get_iam_posture_path() -> Path | None:
    """Get the path to ops/security/iam-posture.yaml.

    Returns None if not found.
    """
    devguard_path = Path(__file__).parent.parent.parent
    iam_path = devguard_path.parent / "ops" / "security" / "iam-posture.yaml"

    if iam_path.exists():
        return iam_path

    return None
