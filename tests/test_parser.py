"""Tests for the Suricata rule parser."""

import pytest

from suricata_rule_parser import parse_rule, parse_file
from suricata_rule_parser.exceptions import ParseError, InvalidRuleFormatError


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
        assert "established" in rule.options.flow
        assert "to_server" in rule.options.flow

    def test_parse_pcre_simple(self, sample_pcre_rule_simple):
        """Test parsing simple PCRE pattern without quotes."""
        rule = parse_rule(sample_pcre_rule_simple)

        assert rule.header.action == "alert"
        assert rule.options.sid == 1000012
        assert "pcre" in rule.options.other_options
        pcre_value = rule.options.other_options["pcre"]
        assert "GET" in pcre_value
