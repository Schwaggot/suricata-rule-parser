"""Tests for custom exceptions."""

import pytest

from suricata_rule_parser.exceptions import (
    InvalidOptionError,
    InvalidRuleFormatError,
    MissingRequiredOptionError,
    ParseError,
    SerializationError,
    SuricataRuleParserError,
    ValidationError,
)


class TestSuricataRuleParserError:
    """Test base exception."""

    def test_base_exception(self):
        """Test base exception can be raised."""
        with pytest.raises(SuricataRuleParserError):
            raise SuricataRuleParserError("Base error")


class TestParseError:
    """Test ParseError exception."""

    def test_parse_error_message_only(self):
        """Test ParseError with just a message."""
        error = ParseError("Something went wrong")
        assert error.message == "Something went wrong"
        assert error.rule == ""
        assert error.position == -1
        assert str(error) == "Something went wrong"

    def test_parse_error_with_rule(self):
        """Test ParseError with rule but no position."""
        rule = 'alert tcp any any -> any any (msg:"Test"; sid:1;)'
        error = ParseError("Invalid syntax", rule=rule)
        assert error.message == "Invalid syntax"
        assert error.rule == rule
        assert error.position == -1
        assert "Invalid syntax in rule:" in str(error)
        assert rule[:50] in str(error)

    def test_parse_error_with_rule_and_position(self):
        """Test ParseError with rule and position."""
        rule = 'alert tcp any any -> any any (msg:"Test"; sid:1;)'
        error = ParseError("Missing semicolon", rule=rule, position=25)
        assert error.message == "Missing semicolon"
        assert error.rule == rule
        assert error.position == 25
        assert "Missing semicolon at position 25 in rule:" in str(error)

    def test_parse_error_with_long_rule(self):
        """Test ParseError with long rule (truncation)."""
        long_rule = "a" * 100
        error = ParseError("Error", rule=long_rule)
        error_str = str(error)
        # Should be truncated to 50 chars plus ellipsis
        assert "..." in error_str
        assert len(long_rule[:50]) == 50


class TestValidationError:
    """Test ValidationError exception."""

    def test_validation_error_message_only(self):
        """Test ValidationError with just a message."""
        error = ValidationError("Validation failed")
        assert error.message == "Validation failed"
        assert error.rule_sid == -1
        assert error.errors == []
        assert str(error) == "Validation failed"

    def test_validation_error_with_sid(self):
        """Test ValidationError with SID."""
        error = ValidationError("Missing required field", rule_sid=1234)
        assert error.message == "Missing required field"
        assert error.rule_sid == 1234
        assert error.errors == []
        assert "Missing required field (SID: 1234)" in str(error)

    def test_validation_error_with_errors_list(self):
        """Test ValidationError with errors list."""
        errors = ["Missing msg", "Invalid sid"]
        error = ValidationError("Multiple errors", rule_sid=100, errors=errors)
        assert error.message == "Multiple errors"
        assert error.rule_sid == 100
        assert error.errors == errors
        assert len(error.errors) == 2

    def test_validation_error_with_none_errors(self):
        """Test ValidationError with None errors (default to empty list)."""
        error = ValidationError("Error", errors=None)
        assert error.errors == []


class TestSerializationError:
    """Test SerializationError exception."""

    def test_serialization_error_message_only(self):
        """Test SerializationError with just a message."""
        error = SerializationError("Serialization failed")
        assert error.message == "Serialization failed"
        assert error.rule_sid == -1
        assert str(error) == "Serialization failed"

    def test_serialization_error_with_sid(self):
        """Test SerializationError with SID."""
        error = SerializationError("Cannot serialize", rule_sid=5678)
        assert error.message == "Cannot serialize"
        assert error.rule_sid == 5678
        assert "Cannot serialize (SID: 5678)" in str(error)


class TestInvalidRuleFormatError:
    """Test InvalidRuleFormatError exception."""

    def test_invalid_rule_format_error(self):
        """Test InvalidRuleFormatError inherits from ParseError."""
        error = InvalidRuleFormatError("Bad format")
        assert isinstance(error, ParseError)
        assert isinstance(error, SuricataRuleParserError)
        assert error.message == "Bad format"


class TestInvalidOptionError:
    """Test InvalidOptionError exception."""

    def test_invalid_option_error(self):
        """Test InvalidOptionError inherits from ParseError."""
        rule = "alert tcp any any -> any any (invalid:option;)"
        error = InvalidOptionError("Unknown option", rule=rule, position=30)
        assert isinstance(error, ParseError)
        assert isinstance(error, SuricataRuleParserError)
        assert error.message == "Unknown option"
        assert error.position == 30


class TestMissingRequiredOptionError:
    """Test MissingRequiredOptionError exception."""

    def test_missing_required_option_error(self):
        """Test MissingRequiredOptionError inherits from ValidationError."""
        error = MissingRequiredOptionError("Missing msg", rule_sid=999)
        assert isinstance(error, ValidationError)
        assert isinstance(error, SuricataRuleParserError)
        assert error.message == "Missing msg"
        assert error.rule_sid == 999
