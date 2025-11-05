"""Tests for the Suricata rule serializer."""

import pytest

from suricata_rule_parser import parse_rule, serialize_rule
from suricata_rule_parser.exceptions import SerializationError
from suricata_rule_parser.models import RuleHeader, RuleOptions, SuricataRule
from suricata_rule_parser.serializer import SuricataSerializer


class TestSuricataSerializer:
    """Tests for SuricataSerializer class."""

    def test_serialize_simple_rule(self, sample_alert_rule):
        """Test serializing a simple rule."""
        rule = parse_rule(sample_alert_rule)
        serialized = serialize_rule(rule)

        assert "alert" in serialized
        assert "tcp" in serialized
        assert "sid:1000001" in serialized
        assert "msg:" in serialized

    def test_serialize_and_parse_roundtrip(self, sample_alert_rule):
        """Test that parse -> serialize -> parse produces same rule."""
        original_rule = parse_rule(sample_alert_rule)
        serialized = serialize_rule(original_rule)

        # Clear raw to force serialization
        original_rule.raw = ""
        serialized = serialize_rule(original_rule)

        reparsed_rule = parse_rule(serialized)

        assert reparsed_rule.action == original_rule.action
        assert reparsed_rule.protocol == original_rule.protocol
        assert reparsed_rule.sid == original_rule.sid
        assert reparsed_rule.msg == original_rule.msg

    def test_serialize_with_raw(self, sample_http_rule):
        """Test that serializer uses raw string when available."""
        rule = parse_rule(sample_http_rule)
        serialized = serialize_rule(rule)

        # Should preserve the original raw string
        assert serialized == rule.raw

    def test_serialize_disabled_rule(self):
        """Test serializing a disabled rule."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options, enabled=False)

        serialized = serialize_rule(rule)
        assert serialized.startswith("#")

    def test_serialize_from_dict(self, sample_alert_rule):
        """Test serializing a rule created from dict."""
        rule = parse_rule(sample_alert_rule)
        rule_dict = rule.to_dict()
        new_rule = SuricataRule.from_dict(rule_dict)

        # Clear raw to force serialization
        new_rule.raw = ""
        serialized = serialize_rule(new_rule)

        assert "alert" in serialized
        assert "tcp" in serialized
        assert f"sid:{new_rule.sid}" in serialized

    def test_serialize_disabled_rule_with_raw(self, sample_alert_rule):
        """Test serializing a rule with raw that should be disabled."""
        rule = parse_rule(sample_alert_rule)
        rule.enabled = False  # Disable the rule

        serialized = serialize_rule(rule)
        assert serialized.startswith("#")

    def test_serialize_enabled_rule_with_commented_raw(self):
        """Test serializing an enabled rule that has commented raw."""
        commented_rule = '# alert tcp any any -> any any (msg:"Test"; sid:1000; rev:1;)'
        rule = parse_rule(commented_rule)
        rule.enabled = True  # Enable the rule

        serialized = serialize_rule(rule)
        assert not serialized.startswith("#")
        assert "alert tcp" in serialized

    def test_serialize_with_flag_option(self):
        """Test serializing a rule with flag options (True value)."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(
            msg="Test",
            sid=1000,
            rev=1,
            other_options={"nocase": True, "noalert": True},  # Flag options
        )
        rule = SuricataRule(header=header, options=options)

        serialized = serialize_rule(rule)
        assert "nocase;" in serialized
        assert "noalert;" in serialized

    def test_serialize_with_metadata_flag(self):
        """Test serializing a rule with metadata that has True value."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(
            msg="Test", sid=1000, rev=1, metadata={"former_category": "MALWARE", "flag_value": True}
        )
        rule = SuricataRule(header=header, options=options)

        serialized = serialize_rule(rule)
        assert "metadata:" in serialized
        assert "former_category MALWARE" in serialized
        assert "flag_value" in serialized

    def test_serialize_error_handling(self):
        """Test serialization error handling."""
        from unittest.mock import patch

        serializer = SuricataSerializer()
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        # Mock _serialize_header to raise an exception
        with patch.object(serializer, "_serialize_header", side_effect=Exception("Mock error")):
            with pytest.raises(SerializationError) as exc_info:
                serializer.serialize_rule(rule)

        assert "Failed to serialize rule" in str(exc_info.value)
        assert exc_info.value.rule_sid == 1000
