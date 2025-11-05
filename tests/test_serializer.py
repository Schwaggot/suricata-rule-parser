"""Tests for the Suricata rule serializer."""

from suricata_rule_parser import parse_rule, serialize_rule
from suricata_rule_parser.models import RuleHeader, RuleOptions, SuricataRule


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
