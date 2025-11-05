"""Tests for the Suricata rule validator."""

from suricata_rule_parser import parse_rule, validate_rule
from suricata_rule_parser.models import RuleHeader, RuleOptions, SuricataRule


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
