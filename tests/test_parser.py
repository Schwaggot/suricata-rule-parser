"""Tests for the Suricata rule parser."""

import pytest

from suricata_rule_parser import parse_rule, parse_file
from suricata_rule_parser.exceptions import ParseError, InvalidRuleFormatError
from suricata_rule_parser.parser import SuricataParser


class TestSuricataParser:
    """Tests for SuricataParser class."""

    def test_parse_simple_rule(self, sample_alert_rule):
        """Test parsing a simple alert rule."""
        rule = parse_rule(sample_alert_rule)

        assert rule.header.action == "alert"
        assert rule.header.protocol == "tcp"
        assert rule.header.source_ip == "any"
        assert rule.header.source_port == "any"
        assert rule.header.direction == "->"
        assert rule.header.dest_ip == "any"
        assert rule.header.dest_port == "80"
        assert rule.options.msg == "Test rule"
        assert rule.options.sid == 1000001
        assert rule.options.rev == 1
        assert rule.enabled is True

    def test_parse_http_rule(self, sample_http_rule):
        """Test parsing an HTTP rule with content."""
        rule = parse_rule(sample_http_rule)

        assert rule.header.protocol == "http"
        assert rule.options.msg == "ET WEB_SERVER Suspicious User-Agent sqlmap"
        assert rule.options.sid == 2000008
        assert rule.options.rev == 2
        assert "to_server" in rule.options.flow
        assert "established" in rule.options.flow
        assert rule.options.classtype == "web-application-attack"
        assert rule.options.priority == 1

    def test_parse_dns_rule(self, sample_dns_rule):
        """Test parsing a DNS rule with metadata."""
        rule = parse_rule(sample_dns_rule)

        assert rule.header.protocol == "dns"
        assert rule.header.source_ip == "$HOME_NET"
        assert rule.options.sid == 2014169
        assert ".su" in rule.options.content
        assert "nocase" in rule.options.other_options
        assert "endswith" in rule.options.other_options
        assert len(rule.options.reference) > 0
        assert len(rule.options.metadata) > 0

    def test_parse_disabled_rule(self, sample_disabled_rule):
        """Test parsing a commented out rule."""
        rule = parse_rule(sample_disabled_rule)

        assert rule.enabled is False
        assert rule.header.action == "alert"
        assert rule.options.sid == 1000002

    def test_parse_complex_rule(self, sample_complex_rule):
        """Test parsing a complex rule with hex content."""
        rule = parse_rule(sample_complex_rule)

        assert rule.header.protocol == "tcp"
        assert rule.header.source_ip == "$HOME_NET"
        assert rule.header.dest_ip == "$EXTERNAL_NET"
        assert rule.header.dest_port == "1024:"
        assert rule.options.sid == 2007922
        assert len(rule.options.content) > 0
        assert "depth" in rule.options.other_options
        assert "offset" in rule.options.other_options

    def test_parse_file(self, rules_file_path):
        """Test parsing a rules file."""
        rules = parse_file(rules_file_path)

        assert len(rules) >= 3
        assert all(rule.options.sid > 0 for rule in rules)

    def test_parse_empty_string(self):
        """Test parsing an empty string raises error."""
        with pytest.raises(ParseError):
            parse_rule("")

    def test_parse_invalid_format(self):
        """Test parsing invalid rule format raises error."""
        with pytest.raises(InvalidRuleFormatError):
            parse_rule("this is not a valid rule")

    def test_parse_invalid_action(self, invalid_rule_bad_action):
        """Test parsing rule with invalid action."""
        with pytest.raises(ParseError):
            parse_rule(invalid_rule_bad_action)

    def test_parse_file_not_found(self):
        """Test parsing non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            parse_file("/nonexistent/path/to/rules.rules")

    def test_to_dict(self, sample_alert_rule):
        """Test converting rule to dictionary."""
        rule = parse_rule(sample_alert_rule)
        rule_dict = rule.to_dict()

        assert "header" in rule_dict
        assert "options" in rule_dict
        assert rule_dict["header"]["action"] == "alert"
        assert rule_dict["options"]["sid"] == 1000001

    def test_from_dict(self, sample_alert_rule):
        """Test creating rule from dictionary."""
        from suricata_rule_parser import SuricataRule

        rule = parse_rule(sample_alert_rule)
        rule_dict = rule.to_dict()
        new_rule = SuricataRule.from_dict(rule_dict)

        assert new_rule.header.action == rule.header.action
        assert new_rule.options.sid == rule.options.sid
        assert new_rule.options.msg == rule.options.msg

    def test_parse_pcre_with_quotes(self, sample_pcre_rule_with_quotes):
        """Test parsing PCRE pattern with quotes in character class."""
        rule = parse_rule(sample_pcre_rule_with_quotes)

        assert rule.header.action == "alert"
        assert rule.options.sid == 1000010
        assert rule.options.msg == "PCRE with quotes in character class"
        assert "pcre" in rule.options.other_options
        # The PCRE pattern should be preserved
        pcre_value = rule.options.other_options["pcre"]
        assert "/" in pcre_value
        assert "Ri" in pcre_value or pcre_value.endswith("i")

    def test_parse_pcre_complex(self, sample_pcre_rule_complex):
        """Test parsing complex rule with PCRE and other options."""
        rule = parse_rule(sample_pcre_rule_complex)

        assert rule.header.protocol == "http"
        assert rule.options.sid == 1000011
        assert "test" in rule.options.content
        assert "pcre" in rule.options.other_options

    def test_parse_unknown_protocol(self):
        """Test parsing rule with unknown protocol."""
        rule_string = 'alert custom_proto any any -> any any (msg:"Test"; sid:1; rev:1;)'
        rule = parse_rule(rule_string)

        assert rule.header.protocol == "custom_proto"
        assert rule.sid == 1

    def test_parse_comment_not_rule(self, tmp_path):
        """Test parsing file with comments that aren't rules."""
        parser = SuricataParser()
        test_file = tmp_path / "test.rules"
        content = """# This is just a comment, not a rule
# Another regular comment
alert tcp any any -> any any (msg:"Real rule"; sid:1; rev:1;)
"""
        test_file.write_text(content)
        rules = parser.parse_file(test_file)
        assert len(rules) == 1
        assert rules[0].sid == 1

    def test_parse_rules_with_invalid(self):
        """Test parse_rules method with some invalid rules."""
        from suricata_rule_parser import parse_rules

        rule_strings = [
            'alert tcp any any -> any any (msg:"Valid1"; sid:1; rev:1;)',
            "invalid rule format",
            'alert tcp any any -> any any (msg:"Valid2"; sid:2; rev:1;)',
        ]
        rules = parse_rules(rule_strings)

        # Should skip the invalid rule
        assert len(rules) == 2
        assert rules[0].sid == 1
        assert rules[1].sid == 2

    def test_parse_options_not_starting_with_paren(self):
        """Test error when options don't start with parenthesis."""
        parser = SuricataParser()

        with pytest.raises(ParseError) as exc_info:
            parser._extract_options_section("invalid options")

        assert "must start with (" in str(exc_info.value)

    def test_parse_unclosed_parentheses(self):
        """Test error for unclosed parentheses in options."""
        parser = SuricataParser()

        with pytest.raises(ParseError) as exc_info:
            parser._extract_options_section('(msg:"Test"; sid:1')

        assert "Unclosed parentheses" in str(exc_info.value)

    def test_parse_unclosed_pcre_pattern(self):
        """Test error for unclosed PCRE pattern."""
        parser = SuricataParser()

        with pytest.raises(ParseError) as exc_info:
            parser._extract_pcre_value('"/unclosed/pattern', 0)

        assert "Unclosed PCRE pattern" in str(exc_info.value)

    def test_parse_pcre_without_pattern(self):
        """Test PCRE value extraction without pattern delimiter."""
        parser = SuricataParser()

        # PCRE value that closes before any pattern starts
        value, end_pos = parser._extract_pcre_value('"value"', 0)
        assert value == "value"

    def test_parse_invalid_sid_value(self):
        """Test parsing rule with invalid (non-numeric) SID."""
        rule_string = 'alert tcp any any -> any any (msg:"Test"; sid:invalid; rev:1;)'

        with pytest.raises(ParseError) as exc_info:
            parse_rule(rule_string)

        assert "Invalid SID value" in str(exc_info.value)

    def test_parse_invalid_rev_value(self):
        """Test parsing rule with invalid (non-numeric) rev."""
        rule_string = 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:invalid;)'

        with pytest.raises(ParseError) as exc_info:
            parse_rule(rule_string)

        assert "Invalid rev value" in str(exc_info.value)

    def test_parse_invalid_priority_value(self):
        """Test parsing rule with invalid (non-numeric) priority."""
        rule_string = 'alert tcp any any -> any any (msg:"Test"; priority:high; sid:1; rev:1;)'

        with pytest.raises(ParseError) as exc_info:
            parse_rule(rule_string)

        assert "Invalid priority value" in str(exc_info.value)

    def test_parse_flag_option(self):
        """Test parsing rule with flag options (no value)."""
        rule_string = 'alert tcp any any -> any any (msg:"Test"; nocase; sid:1; rev:1;)'
        rule = parse_rule(rule_string)

        # Flag options are stored with empty string value
        assert "nocase" in rule.options.other_options
        assert rule.options.other_options.get("nocase") == ""

    def test_parse_metadata_with_integer(self):
        """Test parsing metadata with integer value."""
        rule_string = (
            'alert tcp any any -> any any (msg:"Test"; metadata:attack_target 123; sid:1; rev:1;)'
        )
        rule = parse_rule(rule_string)

        assert rule.options.metadata.get("attack_target") == 123

    def test_parse_metadata_with_boolean(self):
        """Test parsing metadata with boolean values."""
        rule_string = (
            "alert tcp any any -> any any "
            '(msg:"Test"; metadata:enabled true, disabled false; sid:1; rev:1;)'
        )
        rule = parse_rule(rule_string)

        assert rule.options.metadata.get("enabled") is True
        assert rule.options.metadata.get("disabled") is False

    def test_parse_metadata_flag_only(self):
        """Test parsing metadata with flag (no value)."""
        rule_string = 'alert tcp any any -> any any (msg:"Test"; metadata:flagvalue; sid:1; rev:1;)'
        rule = parse_rule(rule_string)

        assert rule.options.metadata.get("flagvalue") is True

    def test_parse_backslash_escape_sequence(self):
        """Test parsing content with backslash escape sequences."""
        # Two backslashes followed by a quote - quote is NOT escaped
        rule_string = r'alert tcp any any -> any any (msg:"Test"; content:"text\\"; sid:1; rev:1;)'
        rule = parse_rule(rule_string)

        assert "text\\\\" in rule.options.content[0]
