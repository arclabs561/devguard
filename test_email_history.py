#!/usr/bin/env python3
"""Test script to verify email history persistence and introspection.

This script:
1. Creates a test Guardian report
2. Sends it via smart_email (if enabled) or SMTP
3. Verifies history is stored with all reasoning/metadata
4. Tests introspection via MCP tools
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add guardian to path
sys.path.insert(0, str(Path(__file__).parent))

from guardian.config import Settings
from guardian.core import Guardian
from guardian.reporting import Reporter


async def test_email_history():
    """Test email history persistence and introspection."""
    print("=" * 60)
    print("Testing Email History Persistence & Introspection")
    print("=" * 60)
    print()
    
    # Create test settings
    settings = Settings()
    
    # Check if smart_email is enabled
    use_smart_email = getattr(settings, "use_smart_email", False) or os.getenv("USE_SMART_EMAIL", "").lower() == "true"
    
    print(f"Configuration:")
    print(f"  USE_SMART_EMAIL: {use_smart_email}")
    print(f"  EMAIL_LLM_ENABLED: {getattr(settings, 'email_llm_enabled', False)}")
    print(f"  ALERT_EMAIL: {settings.alert_email}")
    print()
    
    if not settings.alert_email:
        print("⚠️  ALERT_EMAIL not set - skipping actual email send")
        print("   Set ALERT_EMAIL to test full flow")
        print()
    
    # Create Guardian and run checks
    print("1. Running Guardian checks...")
    guardian = Guardian(settings)
    report = await guardian.run_checks()
    
    print(f"   ✓ Generated report with {len(report.checks)} checks")
    print(f"   ✓ Total vulnerabilities: {report.summary.get('total_vulnerabilities', 0)}")
    print()
    
    # Create reporter
    reporter = Reporter(settings)
    
    # Test history introspection BEFORE sending
    print("2. Testing history introspection (before send)...")
    history_before = reporter.get_email_history(limit=5)
    print(f"   ✓ Retrieved {len(history_before)} previous emails")
    if history_before:
        print(f"   ✓ Latest email: {history_before[-1].get('subject', 'N/A')[:50]}")
        print(f"   ✓ Has metadata: {'summary' in history_before[-1]}")
        print(f"   ✓ Has LLM decision: {'llm_decision' in history_before[-1]}")
    print()
    
    # Send email (if configured)
    if settings.alert_email:
        print("3. Sending email...")
        try:
            await reporter.report(report)
            print("   ✓ Email sent successfully")
        except Exception as e:
            print(f"   ✗ Email send failed: {e}")
        print()
    else:
        print("3. Skipping email send (ALERT_EMAIL not set)")
        print()
    
    # Test history introspection AFTER sending
    print("4. Testing history introspection (after send)...")
    history_after = reporter.get_email_history(limit=5)
    print(f"   ✓ Retrieved {len(history_after)} emails")
    
    if history_after and len(history_after) > len(history_before):
        latest = history_after[-1]
        print(f"   ✓ Latest email subject: {latest.get('subject', 'N/A')[:60]}")
        print(f"   ✓ Timestamp: {latest.get('timestamp', 'N/A')}")
        print(f"   ✓ Author: {latest.get('author', 'N/A')}")
        print(f"   ✓ Severity: {latest.get('severity', 'N/A')}")
        print()
        
        # Verify metadata preservation
        print("5. Verifying metadata preservation...")
        checks = {
            "summary": "summary" in latest,
            "issues": "issues" in latest,
            "llm_decision": "llm_decision" in latest or "llm_reasoning" in latest,
            "message_preview": "message_preview" in latest,
            "full_metadata": "full_metadata" in latest,
        }
        
        for key, present in checks.items():
            status = "✓" if present else "✗"
            print(f"   {status} {key}: {present}")
        
        # Show sample metadata
        if latest.get("summary"):
            summary = latest["summary"]
            print()
            print("   Sample summary metadata:")
            print(f"     - Critical vulnerabilities: {summary.get('critical_vulnerabilities', 0)}")
            print(f"     - High findings: {summary.get('high_findings', 0)}")
            print(f"     - Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        
        if latest.get("llm_decision"):
            llm = latest["llm_decision"]
            print()
            print("   LLM decision metadata:")
            print(f"     - Should send: {llm.get('should_send', 'N/A')}")
            print(f"     - Priority: {llm.get('priority', 'N/A')}")
            print(f"     - Reasoning: {llm.get('reasoning', 'N/A')[:80]}")
        
        if latest.get("full_metadata"):
            print()
            print("   ✓ Full metadata preserved for deep analysis")
    else:
        print("   ⚠️  No new email in history (may not have been sent)")
    print()
    
    # Test unified history if smart_email enabled
    if use_smart_email:
        print("6. Testing unified history (smart_email SQLite)...")
        try:
            import sys
            from pathlib import Path
            
            ops_agent_path = Path(__file__).parent.parent.parent / "ops" / "agent"
            if str(ops_agent_path) not in sys.path:
                sys.path.insert(0, str(ops_agent_path))
            
            from smart_email import init_db
            from pathlib import Path as PathLib
            import sqlite3
            
            db_path_str = getattr(settings, "smart_email_db_path", None)
            if db_path_str:
                db_path = PathLib(db_path_str)
            else:
                db_path_str = os.getenv("SMART_EMAIL_DB", "/data/smart_email.db")
                db_path = PathLib(db_path_str)
            
            if db_path.exists():
                init_db(db_path)
                conn = sqlite3.connect(str(db_path))
                
                # Count alerts
                count = conn.execute("SELECT COUNT(*) FROM alert_history").fetchone()[0]
                guardian_count = conn.execute(
                    "SELECT COUNT(*) FROM alert_history WHERE author = 'guardian'"
                ).fetchone()[0]
                
                print(f"   ✓ Total alerts in DB: {count}")
                print(f"   ✓ Guardian alerts: {guardian_count}")
                
                # Get latest Guardian alert
                latest_row = conn.execute("""
                    SELECT topic, severity, subject, sent_at, author, message_preview, metadata_json
                    FROM alert_history
                    WHERE author = 'guardian'
                    ORDER BY sent_at DESC
                    LIMIT 1
                """).fetchone()
                
                if latest_row:
                    topic, severity, subject, sent_at, author, message_preview, metadata_json = latest_row
                    metadata = json.loads(metadata_json) if metadata_json else {}
                    print(f"   ✓ Latest Guardian alert:")
                    print(f"     - Topic: {topic}")
                    print(f"     - Subject: {subject[:60]}")
                    print(f"     - Has LLM decision: {'llm_decision' in metadata or 'llm_reasoning' in metadata}")
                    print(f"     - Has report summary: {'report_summary' in metadata}")
                    print(f"     - Has full context: {'context' in metadata}")
                
                conn.close()
            else:
                print(f"   ⚠️  Database not found at {db_path}")
                print(f"      (This is OK if smart_email hasn't been used yet)")
        except Exception as e:
            print(f"   ✗ Error accessing unified history: {e}")
        print()
    
    print("=" * 60)
    print("Test Complete")
    print("=" * 60)
    print()
    print("To verify introspection via MCP:")
    print("  from guardian.mcp_server import get_email_history, get_unified_alert_history")
    print("  history = await get_email_history(limit=10)")
    print("  unified = await get_unified_alert_history(limit=20)")


if __name__ == "__main__":
    asyncio.run(test_email_history())







