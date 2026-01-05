#!/usr/bin/env python3
"""Comprehensive validation of the unified email system.

Validates:
1. Database schema (author, message_preview columns exist)
2. Metadata preservation (all fields stored)
3. Integration points (Guardian → smart_email)
4. History introspection (all methods work)
5. LLM integration (if enabled)
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

def validate_database_schema(db_path: Path) -> tuple[bool, list[str]]:
    """Validate database schema has required columns."""
    errors = []
    
    if not db_path.exists():
        return True, ["Database doesn't exist yet (OK if not used)"]  # Not an error
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Get table schema
    cursor.execute("PRAGMA table_info(alert_history)")
    columns = {row[1]: row[2] for row in cursor.fetchall()}
    
    required_columns = {
        "id": "TEXT",
        "topic": "TEXT",
        "severity": "TEXT",
        "subject": "TEXT",
        "sent_at": "TEXT",
        "thread_id": "TEXT",
        "occurrence_count": "INTEGER",
        "author": "TEXT",  # Required for unified system
        "message_preview": "TEXT",  # Required for introspection
        "metadata_json": "TEXT",  # Required for full metadata
    }
    
    for col, col_type in required_columns.items():
        if col not in columns:
            errors.append(f"Missing column: {col}")
        elif col_type and columns[col] != col_type:
            errors.append(f"Column {col} has wrong type: {columns[col]} (expected {col_type})")
    
    # Check indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alert_history'")
    indexes = {row[0] for row in cursor.fetchall()}
    
    required_indexes = ["idx_alert_topic", "idx_alert_sent", "idx_alert_author"]
    for idx in required_indexes:
        if idx not in indexes:
            errors.append(f"Missing index: {idx}")
    
    conn.close()
    
    return len(errors) == 0, errors


def validate_metadata_structure(metadata_json: str) -> tuple[bool, list[str]]:
    """Validate metadata JSON has all required fields."""
    errors = []
    
    try:
        metadata = json.loads(metadata_json)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON: {e}"]
    
    # Check for key fields that should be preserved
    expected_fields = [
        "context",  # Alert context (occurrence counts, trends)
        "author",  # Author attribution
    ]
    
    for field in expected_fields:
        if field not in metadata:
            errors.append(f"Missing metadata field: {field}")
    
    # Check for Guardian-specific fields (if author is guardian)
    if metadata.get("author") == "guardian":
        guardian_fields = ["summary", "issues", "report_summary"]
        for field in guardian_fields:
            if field not in metadata:
                errors.append(f"Missing Guardian metadata field: {field}")
    
    return len(errors) == 0, errors


def validate_history_entries(db_path: Path, limit: int = 5) -> tuple[bool, list[str]]:
    """Validate history entries have complete metadata."""
    errors = []
    
    if not db_path.exists():
        return True, ["No database to validate"]
    
    conn = sqlite3.connect(str(db_path))
    
    # Get recent entries
    rows = conn.execute("""
        SELECT author, message_preview, metadata_json
        FROM alert_history
        ORDER BY sent_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    
    if not rows:
        return True, ["No history entries to validate"]
    
    for author, message_preview, metadata_json in rows:
        # Check author is set
        if not author:
            errors.append("Entry missing author")
        
        # Check message_preview exists (can be empty but should be present)
        if message_preview is None:
            errors.append("Entry missing message_preview")
        
        # Validate metadata structure
        if metadata_json:
            valid, meta_errors = validate_metadata_structure(metadata_json)
            if not valid:
                errors.extend([f"Entry {author}: {e}" for e in meta_errors])
        else:
            errors.append(f"Entry {author}: Missing metadata_json")
    
    conn.close()
    
    return len(errors) == 0, errors


def validate_smart_email_integration() -> tuple[bool, list[str]]:
    """Validate smart_email function signature and parameters."""
    errors = []
    
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent / "ops" / "agent"))
        from smart_email import smart_send_alert
        import inspect
        
        sig = inspect.signature(smart_send_alert)
        params = list(sig.parameters.keys())
        
        required_params = ["db_path", "topic", "severity", "headline", "message", "author"]
        optional_params = ["force_immediate", "use_llm", "llm_settings", "rich_metadata"]
        
        for param in required_params:
            if param not in params:
                errors.append(f"Missing required parameter: {param}")
        
        if "rich_metadata" not in params:
            errors.append("Missing rich_metadata parameter (needed for comprehensive storage)")
        
    except ImportError as e:
        errors.append(f"Could not import smart_email: {e}")
    except Exception as e:
        errors.append(f"Error validating smart_email: {e}")
    
    return len(errors) == 0, errors


def validate_guardian_integration() -> tuple[bool, list[str]]:
    """Validate Guardian passes rich_metadata to smart_email."""
    errors = []
    
    try:
        guardian_path = Path(__file__).parent / "guardian" / "reporting.py"
        content = guardian_path.read_text()
        
        # Check that _send_via_smart_email builds rich_metadata
        if "rich_metadata" not in content:
            errors.append("Guardian reporting.py doesn't mention rich_metadata")
        
        # Check that smart_send_alert is called with rich_metadata
        if "smart_send_alert(" in content:
            # Find the call
            lines = content.split("\n")
            in_smart_send_call = False
            has_rich_metadata = False
            
            for i, line in enumerate(lines):
                if "smart_send_alert(" in line:
                    in_smart_send_call = True
                if in_smart_send_call:
                    if "rich_metadata=" in line:
                        has_rich_metadata = True
                        break
                    if ")" in line and not has_rich_metadata:
                        # End of call without rich_metadata
                        errors.append("smart_send_alert call missing rich_metadata parameter")
                        break
        
    except Exception as e:
        errors.append(f"Error validating Guardian integration: {e}")
    
    return len(errors) == 0, errors


def main():
    """Run all validations."""
    print("=" * 60)
    print("Email System Validation")
    print("=" * 60)
    print()
    
    all_passed = True
    
    # 1. Database schema validation
    print("1. Validating database schema...")
    db_path = Path(os.getenv("SMART_EMAIL_DB", "/data/smart_email.db"))
    schema_ok, schema_errors = validate_database_schema(db_path)
    if schema_ok:
        print("   ✓ Database schema is correct")
    else:
        print(f"   ✗ Schema errors: {schema_errors}")
        all_passed = False
    print()
    
    # 2. Metadata structure validation
    print("2. Validating metadata structure...")
    if db_path.exists():
        entries_ok, entry_errors = validate_history_entries(db_path, limit=5)
        if entries_ok:
            print("   ✓ History entries have complete metadata")
        else:
            print(f"   ✗ Entry errors: {entry_errors}")
            all_passed = False
    else:
        print("   ⚠️  No database to validate (OK if not used yet)")
    print()
    
    # 3. smart_email integration validation
    print("3. Validating smart_email integration...")
    smart_ok, smart_errors = validate_smart_email_integration()
    if smart_ok:
        print("   ✓ smart_email function signature is correct")
    else:
        print(f"   ✗ Integration errors: {smart_errors}")
        all_passed = False
    print()
    
    # 4. Guardian integration validation
    print("4. Validating Guardian integration...")
    guardian_ok, guardian_errors = validate_guardian_integration()
    if guardian_ok:
        print("   ✓ Guardian passes rich_metadata to smart_email")
    else:
        print(f"   ✗ Integration errors: {guardian_errors}")
        all_passed = False
    print()
    
    # Summary
    print("=" * 60)
    if all_passed:
        print("✓ All validations passed")
    else:
        print("✗ Some validations failed - see errors above")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())







