"""Tests for CLI interface."""

import argparse
import json
import sys
from unittest.mock import patch

import pytest

from suricata_rule_parser.cli import (
    info_command,
    main,
    parse_command,
    validate_command,
)


class TestParseCommand:
    """Test the parse command."""

    def test_parse_compact_format(self, tmp_path, capsys):
        """Test parse command with compact format."""
        # Create test file
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, format="compact", verbose=False)
        result = parse_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "[1] alert tcp: Test" in captured.out

    def test_parse_json_format(self, tmp_path, capsys):
        """Test parse command with JSON format."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, format="json", verbose=False)
        result = parse_command(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["options"]["sid"] == 1
        assert data[0]["options"]["msg"] == "Test"

    def test_parse_text_format(self, tmp_path, capsys):
        """Test parse command with text format."""
        test_file = tmp_path / "test.rules"
        test_file.write_text(
            "alert tcp any any -> any any "
            '(msg:"Test"; classtype:trojan-activity; sid:1; rev:1;)\n'
        )

        args = argparse.Namespace(file=test_file, format="text", verbose=False)
        result = parse_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "SID 1: Test" in captured.out
        assert "Action: alert" in captured.out
        assert "Protocol: tcp" in captured.out
        assert "Classtype: trojan-activity" in captured.out

    def test_parse_with_verbose(self, tmp_path, capsys):
        """Test parse command with verbose flag."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, format="compact", verbose=True)
        result = parse_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules parsed: 1" in captured.err

    def test_parse_file_not_found(self, tmp_path, capsys):
        """Test parse command with non-existent file."""
        test_file = tmp_path / "nonexistent.rules"

        args = argparse.Namespace(file=test_file, format="compact", verbose=False)
        result = parse_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_parse_invalid_rule(self, tmp_path, capsys):
        """Test parse command with invalid rule."""
        test_file = tmp_path / "test.rules"
        test_file.write_text("invalid rule format\n")

        args = argparse.Namespace(file=test_file, format="compact", verbose=False)
        result = parse_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Parse error:" in captured.err

    def test_parse_unexpected_error_verbose(self, tmp_path, capsys):
        """Test parse command with unexpected error in verbose mode."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, format="compact", verbose=True)

        # Mock to raise unexpected exception
        with patch(
            "suricata_rule_parser.cli.SuricataParser.parse_file",
            side_effect=RuntimeError("Unexpected"),
        ):
            result = parse_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unexpected error:" in captured.err
        assert "RuntimeError" in captured.err


class TestValidateCommand:
    """Test the validate command."""

    def test_validate_valid_rules(self, tmp_path, capsys):
        """Test validate command with valid rules."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, strict=False, verbose=False)
        result = validate_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules: 1" in captured.out
        assert "Valid rules: 1" in captured.out
        assert "Invalid rules: 0" in captured.out

    def test_validate_invalid_rules(self, tmp_path, capsys):
        """Test validate command with invalid rules."""
        test_file = tmp_path / "test.rules"
        # Missing required 'msg' option
        test_file.write_text("alert tcp any any -> any any (sid:1; rev:1;)\n")

        args = argparse.Namespace(file=test_file, strict=False, verbose=False)
        result = validate_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Total rules: 1" in captured.out
        assert "Valid rules: 0" in captured.out
        assert "Invalid rules: 1" in captured.out
        assert "✗ SID 1:" in captured.out

    def test_validate_with_verbose(self, tmp_path, capsys):
        """Test validate command with verbose flag."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, strict=False, verbose=True)
        result = validate_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "✓ SID 1: Test" in captured.out

    def test_validate_strict_mode(self, tmp_path, capsys):
        """Test validate command with strict mode."""
        test_file = tmp_path / "test.rules"
        # Priority 4 is invalid in strict mode
        test_file.write_text(
            "alert tcp any any -> any any " '(msg:"Test"; priority:4; sid:1; rev:1;)\n'
        )

        args = argparse.Namespace(file=test_file, strict=True, verbose=False)
        result = validate_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid rules: 1" in captured.out

    def test_validate_file_not_found(self, tmp_path, capsys):
        """Test validate command with non-existent file."""
        test_file = tmp_path / "nonexistent.rules"

        args = argparse.Namespace(file=test_file, strict=False, verbose=False)
        result = validate_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_validate_parse_error(self, tmp_path, capsys):
        """Test validate command with parse error."""
        test_file = tmp_path / "test.rules"
        test_file.write_text("invalid rule\n")

        args = argparse.Namespace(file=test_file, strict=False, verbose=False)
        result = validate_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Parse error:" in captured.err

    def test_validate_unexpected_error_verbose(self, tmp_path, capsys):
        """Test validate command with unexpected error in verbose mode."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, strict=False, verbose=True)

        with patch(
            "suricata_rule_parser.cli.SuricataParser.parse_file",
            side_effect=RuntimeError("Unexpected"),
        ):
            result = validate_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unexpected error:" in captured.err
        assert "RuntimeError" in captured.err


class TestInfoCommand:
    """Test the info command."""

    def test_info_basic(self, tmp_path, capsys):
        """Test info command with basic statistics."""
        test_file = tmp_path / "test.rules"
        test_file.write_text(
            'alert tcp any any -> any any (msg:"Test1"; sid:1; rev:1;)\n'
            'drop udp any any -> any any (msg:"Test2"; sid:2; rev:1;)\n'
        )

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules: 2" in captured.out
        assert "Enabled: 2" in captured.out
        assert "Disabled: 0" in captured.out
        assert "alert: 1" in captured.out
        assert "drop: 1" in captured.out
        assert "tcp: 1" in captured.out
        assert "udp: 1" in captured.out

    def test_info_with_disabled_rules(self, tmp_path, capsys):
        """Test info command with disabled rules."""
        test_file = tmp_path / "test.rules"
        test_file.write_text(
            'alert tcp any any -> any any (msg:"Test1"; sid:1; rev:1;)\n'
            '# drop udp any any -> any any (msg:"Test2"; sid:2; rev:1;)\n'
        )

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules: 2" in captured.out
        assert "Enabled: 1" in captured.out
        assert "Disabled: 1" in captured.out

    def test_info_with_classtypes(self, tmp_path, capsys):
        """Test info command with classtypes."""
        test_file = tmp_path / "test.rules"
        test_file.write_text(
            "alert tcp any any -> any any "
            '(msg:"Test1"; classtype:trojan-activity; sid:1; rev:1;)\n'
            "alert tcp any any -> any any "
            '(msg:"Test2"; classtype:trojan-activity; sid:2; rev:1;)\n'
            "alert tcp any any -> any any "
            '(msg:"Test3"; classtype:malware-cnc; sid:3; rev:1;)\n'
        )

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Top Classtypes:" in captured.out
        assert "trojan-activity: 2" in captured.out
        assert "malware-cnc: 1" in captured.out

    def test_info_many_protocols(self, tmp_path, capsys):
        """Test info command with multiple protocols."""
        test_file = tmp_path / "test.rules"
        # Create rules with various protocols
        rules = [
            'alert tcp any any -> any any (msg:"Test1"; sid:1; rev:1;)\n',
            'alert udp any any -> any any (msg:"Test2"; sid:2; rev:1;)\n',
            'alert http any any -> any any (msg:"Test3"; sid:3; rev:1;)\n',
            'alert dns any any -> any any (msg:"Test4"; sid:4; rev:1;)\n',
            'alert tls any any -> any any (msg:"Test5"; sid:5; rev:1;)\n',
        ]
        test_file.write_text("".join(rules))

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 0
        captured = capsys.readouterr()
        # Verify protocol counts are shown
        assert "tcp: 1" in captured.out
        assert "udp: 1" in captured.out
        assert "http: 1" in captured.out
        assert "dns: 1" in captured.out
        assert "tls: 1" in captured.out

    def test_info_file_not_found(self, tmp_path, capsys):
        """Test info command with non-existent file."""
        test_file = tmp_path / "nonexistent.rules"

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_info_parse_error(self, tmp_path, capsys):
        """Test info command with parse error."""
        test_file = tmp_path / "test.rules"
        test_file.write_text("invalid rule\n")

        args = argparse.Namespace(file=test_file, verbose=False)
        result = info_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Parse error:" in captured.err

    def test_info_unexpected_error_verbose(self, tmp_path, capsys):
        """Test info command with unexpected error in verbose mode."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        args = argparse.Namespace(file=test_file, verbose=True)

        with patch(
            "suricata_rule_parser.cli.SuricataParser.parse_file",
            side_effect=RuntimeError("Unexpected"),
        ):
            result = info_command(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unexpected error:" in captured.err
        assert "RuntimeError" in captured.err


class TestMainFunction:
    """Test the main function and CLI dispatching."""

    def test_main_no_command(self, capsys):
        """Test main function with no command."""
        with patch.object(sys, "argv", ["suricata-parse"]):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "usage:" in captured.out

    def test_main_parse_command(self, tmp_path, capsys):
        """Test main function dispatches to parse command."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        with patch.object(sys, "argv", ["suricata-parse", "parse", str(test_file)]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "[1] alert tcp: Test" in captured.out

    def test_main_validate_command(self, tmp_path, capsys):
        """Test main function dispatches to validate command."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        with patch.object(sys, "argv", ["suricata-parse", "validate", str(test_file)]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules: 1" in captured.out

    def test_main_info_command(self, tmp_path, capsys):
        """Test main function dispatches to info command."""
        test_file = tmp_path / "test.rules"
        test_file.write_text('alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n')

        with patch.object(sys, "argv", ["suricata-parse", "info", str(test_file)]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "Total rules: 1" in captured.out

    def test_main_version(self, capsys):
        """Test main function with --version flag."""
        with patch.object(sys, "argv", ["suricata-parse", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "suricata-rule-parser" in captured.out

    def test_main_invalid_command(self, capsys):
        """Test main function with invalid command."""
        with patch.object(sys, "argv", ["suricata-parse", "invalid"]):
            # argparse will exit with error
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code != 0
