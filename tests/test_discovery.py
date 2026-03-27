"""Tests for discovery module."""

from devguard.discovery import _parse_json_robustly


class TestParseJsonRobustly:
    """Tests for the robust JSON parser that handles CLI output noise."""

    def test_clean_json_object(self):
        """Test parsing clean JSON object."""
        result = _parse_json_robustly('{"name": "test", "value": 42}')
        assert result == {"name": "test", "value": 42}

    def test_clean_json_array(self):
        """Test parsing clean JSON array."""
        result = _parse_json_robustly("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_empty_string(self):
        """Test parsing empty string returns None."""
        result = _parse_json_robustly("")
        assert result is None

    def test_whitespace_only(self):
        """Test parsing whitespace-only string returns None."""
        result = _parse_json_robustly("   \n\t  ")
        assert result is None

    def test_banner_before_json(self):
        """Test parsing JSON with npm-style update banner before it."""
        output = """npm WARN update available: 10.2.0 → 10.5.0
npm WARN Run npm -g install npm@10.5.0 to update
{"packages": ["lodash", "express"]}"""
        result = _parse_json_robustly(output)
        assert result == {"packages": ["lodash", "express"]}

    def test_text_after_json(self):
        """Test parsing JSON with text after it."""
        output = '{"status": "ok"}\nDone in 1.2s'
        result = _parse_json_robustly(output)
        assert result == {"status": "ok"}

    def test_banner_before_and_after(self):
        """Test parsing JSON with noise both before and after."""
        output = """Update available!
[{"id": 1}, {"id": 2}]
Operation completed successfully."""
        result = _parse_json_robustly(output)
        assert result == [{"id": 1}, {"id": 2}]

    def test_nested_braces(self):
        """Test parsing JSON with nested objects."""
        output = 'Some header\n{"outer": {"inner": {"deep": 42}}}'
        result = _parse_json_robustly(output)
        assert result == {"outer": {"inner": {"deep": 42}}}

    def test_array_of_objects(self):
        """Test parsing array of objects with surrounding noise."""
        output = """gh version 2.40.0
[
  {"name": "repo1", "private": false},
  {"name": "repo2", "private": true}
]
"""
        result = _parse_json_robustly(output)
        assert result == [
            {"name": "repo1", "private": False},
            {"name": "repo2", "private": True},
        ]

    def test_no_json(self):
        """Test parsing output with no JSON returns None."""
        result = _parse_json_robustly("This is just plain text with no JSON")
        assert result is None

    def test_unmatched_braces(self):
        """Test parsing output with unmatched braces returns None."""
        result = _parse_json_robustly("Some text { but no closing brace")
        assert result is None

    def test_invalid_json_content(self):
        """Test parsing output with invalid JSON structure returns None."""
        result = _parse_json_robustly("{not: valid json}")
        assert result is None

    def test_fly_cli_output(self):
        """Test parsing Fly.io CLI style output."""
        output = """? Select organization: Personal
{"apps": [{"name": "my-app", "status": "deployed"}]}"""
        result = _parse_json_robustly(output)
        assert result == {"apps": [{"name": "my-app", "status": "deployed"}]}

    def test_vercel_cli_output(self):
        """Test parsing Vercel CLI style output with ANSI codes stripped."""
        # Simulating stripped ANSI output
        output = """Vercel CLI 33.0.0
[{"name": "my-project", "alias": ["my-project.vercel.app"]}]
"""
        result = _parse_json_robustly(output)
        assert result == [{"name": "my-project", "alias": ["my-project.vercel.app"]}]

    def test_gh_cli_rate_limit_warning(self):
        """Test parsing GitHub CLI output with rate limit warning."""
        output = """gh: warning: You have been rate limited by GitHub.
{"viewer": {"login": "testuser"}}"""
        result = _parse_json_robustly(output)
        assert result == {"viewer": {"login": "testuser"}}

    def test_json_with_special_chars(self):
        """Test parsing JSON containing special characters."""
        output = '{"message": "Hello, \\"world\\"!", "emoji": "\\u2764"}'
        result = _parse_json_robustly(output)
        assert result == {"message": 'Hello, "world"!', "emoji": "\u2764"}
