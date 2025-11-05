"""Tests for Suricata rule models."""

from suricata_rule_parser.models import RuleHeader, RuleOptions, SuricataRule


class TestRuleHeader:
    """Tests for RuleHeader class."""

    def test_create_header(self):
        """Test creating a rule header."""
        header = RuleHeader(
            action="alert",
            protocol="tcp",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="192.168.1.1",
            dest_port="80",
        )

        assert header.action == "alert"
        assert header.protocol == "tcp"
        assert header.dest_ip == "192.168.1.1"

    def test_header_to_dict(self):
        """Test converting header to dictionary."""
        header = RuleHeader(
            action="drop",
            protocol="udp",
            source_ip="10.0.0.1",
            source_port="53",
            direction="<>",
            dest_ip="any",
            dest_port="any",
        )

        header_dict = header.to_dict()
        assert header_dict["action"] == "drop"
        assert header_dict["protocol"] == "udp"
        assert header_dict["direction"] == "<>"

    def test_header_from_dict(self):
        """Test creating header from dictionary."""
        data = {
            "action": "alert",
            "protocol": "http",
            "source_ip": "any",
            "source_port": "any",
            "direction": "->",
            "dest_ip": "any",
            "dest_port": "80",
        }

        header = RuleHeader.from_dict(data)
        assert header.action == "alert"
        assert header.protocol == "http"


class TestRuleOptions:
    """Tests for RuleOptions class."""

    def test_create_options(self):
        """Test creating rule options."""
        options = RuleOptions(
            msg="Test message",
            sid=1000001,
            rev=2,
            classtype="misc-activity",
            priority=2,
        )

        assert options.msg == "Test message"
        assert options.sid == 1000001
        assert options.rev == 2
        assert options.classtype == "misc-activity"
        assert options.priority == 2

    def test_options_defaults(self):
        """Test options default values."""
        options = RuleOptions()

        assert options.msg == ""
        assert options.sid == 0
        assert options.rev == 1
        assert options.priority == 3
        assert options.content == []
        assert options.reference == []
        assert options.metadata == {}

    def test_options_to_dict(self):
        """Test converting options to dictionary."""
        options = RuleOptions(
            msg="Test",
            sid=1000,
            rev=1,
            classtype="test-type",
            content=["test content"],
        )

        options_dict = options.to_dict()
        assert options_dict["msg"] == "Test"
        assert options_dict["sid"] == 1000
        assert options_dict["classtype"] == "test-type"
        assert "test content" in options_dict["content"]


class TestSuricataRule:
    """Tests for SuricataRule class."""

    def test_create_rule(self):
        """Test creating a complete rule."""
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
            msg="Test rule",
            sid=1000001,
            rev=1,
        )

        rule = SuricataRule(header=header, options=options)

        assert rule.action == "alert"
        assert rule.protocol == "tcp"
        assert rule.sid == 1000001
        assert rule.msg == "Test rule"
        assert rule.enabled is True

    def test_rule_properties(self):
        """Test rule convenience properties."""
        header = RuleHeader(
            action="drop",
            protocol="http",
            source_ip="any",
            source_port="any",
            direction="->",
            dest_ip="any",
            dest_port="any",
        )
        options = RuleOptions(
            msg="Block request",
            sid=2000,
            rev=3,
            classtype="web-application-attack",
        )

        rule = SuricataRule(header=header, options=options)

        assert rule.action == "drop"
        assert rule.protocol == "http"
        assert rule.sid == 2000
        assert rule.msg == "Block request"
        assert rule.classtype == "web-application-attack"

    def test_rule_str_representation(self):
        """Test string representation of rule."""
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
            msg="Test rule",
            sid=1000001,
            rev=1,
        )

        rule = SuricataRule(header=header, options=options)
        rule_str = str(rule)

        assert "alert" in rule_str
        assert "1000001" in rule_str

    def test_rule_repr(self):
        """Test repr of rule."""
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
            msg="Test rule",
            sid=1000001,
            rev=1,
        )

        rule = SuricataRule(header=header, options=options)
        rule_repr = repr(rule)

        assert "SuricataRule" in rule_repr
        assert "alert" in rule_repr
        assert "tcp" in rule_repr
