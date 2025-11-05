"""Tests for the Suricata rule validator."""

import pytest

from suricata_rule_parser import parse_rule, validate_rule
from suricata_rule_parser.exceptions import ValidationError
from suricata_rule_parser.models import RuleHeader, RuleOptions, SuricataRule
from suricata_rule_parser.validator import SuricataValidator


class TestSuricataValidator:
    """Tests for SuricataValidator class."""

    def test_validate_valid_rule(self, sample_alert_rule):
        """Test validating a valid rule."""
        rule = parse_rule(sample_alert_rule)
        is_valid, errors = validate_rule(rule)

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_http_rule(self, sample_http_rule):
        """Test validating an HTTP rule."""
        rule = parse_rule(sample_http_rule)
        is_valid, errors = validate_rule(rule)

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_dns_rule(self, sample_dns_rule):
        """Test validating a DNS rule."""
        rule = parse_rule(sample_dns_rule)
        is_valid, errors = validate_rule(rule)

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_missing_msg(self):
        """Test validation fails when msg is missing."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("msg" in error.lower() for error in errors)

    def test_validate_missing_sid(self):
        """Test validation fails when SID is missing."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=0, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("sid" in error.lower() for error in errors)

    def test_validate_invalid_action(self):
        """Test validation fails with invalid action."""
        header = RuleHeader(
            action="invalid_action",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("action" in error.lower() for error in errors)

    def test_validate_invalid_direction(self):
        """Test validation fails with invalid direction."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="<-",  # Invalid direction
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("direction" in error.lower() for error in errors)

    def test_validate_invalid_priority(self):
        """Test validation with invalid priority (strict mode)."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1, priority=5)
        rule = SuricataRule(header=header, options=options)

        # Non-strict mode should pass
        is_valid, errors = validate_rule(rule, strict=False)
        assert is_valid is True

        # Strict mode should fail
        is_valid, errors = validate_rule(rule, strict=True)
        assert is_valid is False

    def test_validate_conflicting_flow_directions(self):
        """Test validation fails with conflicting flow directions."""
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
            msg="Test", sid=1000, rev=1, flow=["to_server", "to_client"]  # Conflicting
        )
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("conflict" in error.lower() for error in errors)

    def test_validate_ip_addresses(self):
        """Test validation of IP addresses."""
        # Valid IPs
        valid_ips = ["192.168.1.1", "$HOME_NET", "any", "10.0.0.0/8"]
        for ip in valid_ips:
            header = RuleHeader(
                action="alert",
                protocol="tcp",
                source_ip=ip,
                source_port="any",
                direction="->",
                dest_ip="any",
                dest_port="80",
            )
            options = RuleOptions(msg="Test", sid=1000, rev=1)
            rule = SuricataRule(header=header, options=options)
            is_valid, errors = validate_rule(rule)
            assert is_valid is True, f"IP {ip} should be valid"

    def test_validate_ports(self):
        """Test validation of ports."""
        # Valid ports
        valid_ports = ["80", "1024:", ":1024", "any", "$HTTP_PORTS"]
        for port in valid_ports:
            header = RuleHeader(
                action="alert",
                protocol="tcp",
                source_ip="any",
                source_port="any",
                direction="->",
                dest_ip="any",
                dest_port=port,
            )
            options = RuleOptions(msg="Test", sid=1000, rev=1)
            rule = SuricataRule(header=header, options=options)
            is_valid, errors = validate_rule(rule)
            assert is_valid is True, f"Port {port} should be valid"

    def test_validate_rule_strict_raises_exception(self):
        """Test validate_rule_strict raises exception on invalid rule."""
        validator = SuricataValidator(strict=True)
        header = RuleHeader(
            action="invalid_action",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        with pytest.raises(ValidationError) as exc_info:
            validator.validate_rule_strict(rule)

        assert "validation failed" in str(exc_info.value).lower()
        assert exc_info.value.rule_sid == 1000

    def test_validate_unknown_protocol_strict(self):
        """Test validation with unknown protocol in strict mode."""
        header = RuleHeader(
            action="alert",
            protocol="custom_proto",  # Unknown protocol
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        # Non-strict mode should pass
        is_valid, errors = validate_rule(rule, strict=False)
        assert is_valid is True

        # Strict mode should fail
        is_valid, errors = validate_rule(rule, strict=True)
        assert is_valid is False
        assert any("unknown protocol" in error.lower() for error in errors)

    def test_validate_invalid_ip_address(self):
        """Test validation with invalid IP address."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="999.999.999.999",  # Invalid IP
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("invalid source ip" in error.lower() for error in errors)

    def test_validate_invalid_port(self):
        """Test validation with invalid port."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="invalid_port",  # Invalid port
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("invalid source port" in error.lower() for error in errors)

    def test_validate_invalid_rev(self):
        """Test validation with invalid rev value."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=0)  # Invalid rev
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("rev" in error.lower() for error in errors)

    def test_validate_negative_sid(self):
        """Test validation with negative SID."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=-1, rev=1)  # Negative SID
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("sid" in error.lower() and "positive" in error.lower() for error in errors)

    def test_validate_unknown_flow_state_strict(self):
        """Test validation with unknown flow state in strict mode."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1, flow=["unknown_flow_state"])
        rule = SuricataRule(header=header, options=options)

        # Non-strict mode should pass
        is_valid, errors = validate_rule(rule, strict=False)
        assert is_valid is True

        # Strict mode should fail
        is_valid, errors = validate_rule(rule, strict=True)
        assert is_valid is False
        assert any("unknown flow state" in error.lower() for error in errors)

    def test_validate_http_rule_strict(self):
        """Test validation of HTTP rule without HTTP keywords in strict mode."""
        header = RuleHeader(
            action="alert",
            protocol="http",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)  # No HTTP keywords
        rule = SuricataRule(header=header, options=options)

        # Non-strict mode should pass
        is_valid, errors = validate_rule(rule, strict=False)
        assert is_valid is True

        # Strict mode should warn
        is_valid, errors = validate_rule(rule, strict=True)
        assert is_valid is False
        assert any("http" in error.lower() for error in errors)

    def test_validate_dns_rule_strict(self):
        """Test validation of DNS rule without DNS keywords in strict mode."""
        header = RuleHeader(
            action="alert",
            protocol="dns",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="53",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)  # No DNS keywords
        rule = SuricataRule(header=header, options=options)

        # Non-strict mode should pass
        is_valid, errors = validate_rule(rule, strict=False)
        assert is_valid is True

        # Strict mode should warn
        is_valid, errors = validate_rule(rule, strict=True)
        assert is_valid is False
        assert any("dns" in error.lower() for error in errors)

    def test_validate_conflicting_from_flow(self):
        """Test validation with conflicting from_server and from_client."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1, flow=["from_server", "from_client"])
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("conflict" in error.lower() for error in errors)

    def test_validate_empty_ip(self):
        """Test validation with empty IP address."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="",  # Empty IP
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False

    def test_validate_empty_port(self):
        """Test validation with empty port."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="",  # Empty port
            direction="->",
            dest_ip="any",
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False

    def test_validate_invalid_dest_ip(self):
        """Test validation with invalid destination IP."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="invalid_ip",  # Invalid destination IP
            dest_port="80",
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("invalid destination ip" in error.lower() for error in errors)

    def test_validate_invalid_dest_port(self):
        """Test validation with invalid destination port."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="invalid_port",  # Invalid destination port
        )
        options = RuleOptions(msg="Test", sid=1000, rev=1)
        rule = SuricataRule(header=header, options=options)

        is_valid, errors = validate_rule(rule)
        assert is_valid is False
        assert any("invalid destination port" in error.lower() for error in errors)
