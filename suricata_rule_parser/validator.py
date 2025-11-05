"""Validator for Suricata rules."""

import re
from typing import List, Tuple

from .constants import ACTIONS, DIRECTIONS, FLOW_STATES, PROTOCOLS
from .exceptions import ValidationError
from .models import SuricataRule


class SuricataValidator:
    """Validator for Suricata rules."""

    # Regex for IP addresses and networks
    IP_PATTERN = re.compile(
        r"^(?:"
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"  # IPv4
        r"\$\w+|"  # Variable like $HOME_NET
        r"any|"  # Any
        r"!\$\w+|"  # Negated variable
        r"!\d+\.\d+\.\d+\.\d+|"  # Negated IP
        r"\[.*?\]"  # IP list
        r")(?:/\d+)?$"  # Optional CIDR
    )

    # Regex for ports
    PORT_PATTERN = re.compile(
        r"^(?:"
        r"\d+|"  # Single port
        r"\d+:\d*|"  # Port range
        r":\d+|"  # Port range from 0
        r"\$\w+|"  # Variable
        r"any|"  # Any
        r"!\$\w+|"  # Negated variable
        r"!\d+|"  # Negated port
        r"\[.*?\]"  # Port list
        r")$"
    )

    def __init__(self, strict: bool = False) -> None:
        """
        Initialize the validator.

        Args:
            strict: If True, apply strict validation rules
        """
        self.strict = strict

    def validate_rule(self, rule: SuricataRule) -> Tuple[bool, List[str]]:
        """
        Validate a Suricata rule.

        Args:
            rule: SuricataRule object to validate

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors: List[str] = []

        # Validate header
        header_errors = self._validate_header(rule)
        errors.extend(header_errors)

        # Validate options
        options_errors = self._validate_options(rule)
        errors.extend(options_errors)

        # Validate logical consistency
        consistency_errors = self._validate_consistency(rule)
        errors.extend(consistency_errors)

        is_valid = len(errors) == 0
        return is_valid, errors

    def validate_rule_strict(self, rule: SuricataRule) -> None:
        """
        Validate a rule and raise exception if invalid.

        Args:
            rule: SuricataRule object to validate

        Raises:
            ValidationError: If validation fails
        """
        is_valid, errors = self.validate_rule(rule)
        if not is_valid:
            raise ValidationError(
                f"Rule validation failed with {len(errors)} error(s)",
                rule_sid=rule.sid,
                errors=errors,
            )

    def _validate_header(self, rule: SuricataRule) -> List[str]:
        """Validate rule header."""
        errors: List[str] = []

        # Validate action
        if rule.header.action not in ACTIONS:
            errors.append(f"Invalid action: {rule.header.action}")

        # Validate protocol
        if rule.header.protocol not in PROTOCOLS and rule.header.protocol != "ip":
            if self.strict:
                errors.append(f"Unknown protocol: {rule.header.protocol}")
            # In non-strict mode, allow unknown protocols (could be custom)

        # Validate direction
        if rule.header.direction not in DIRECTIONS:
            errors.append(f"Invalid direction: {rule.header.direction}")

        # Validate IPs
        if not self._is_valid_ip(rule.header.source_ip):
            errors.append(f"Invalid source IP: {rule.header.source_ip}")
        if not self._is_valid_ip(rule.header.dest_ip):
            errors.append(f"Invalid destination IP: {rule.header.dest_ip}")

        # Validate ports
        if not self._is_valid_port(rule.header.source_port):
            errors.append(f"Invalid source port: {rule.header.source_port}")
        if not self._is_valid_port(rule.header.dest_port):
            errors.append(f"Invalid destination port: {rule.header.dest_port}")

        return errors

    def _validate_options(self, rule: SuricataRule) -> List[str]:
        """Validate rule options."""
        errors: List[str] = []

        # Check required options
        if not rule.options.msg:
            errors.append("Missing required option: msg")
        if rule.options.sid == 0:
            errors.append("Missing required option: sid")
        if rule.options.rev == 0:
            errors.append("Invalid rev value: must be >= 1")

        # Validate SID range
        if rule.options.sid < 0:
            errors.append(f"Invalid SID: {rule.options.sid} (must be positive)")

        # Validate priority
        if rule.options.priority not in (1, 2, 3):
            if self.strict:
                errors.append(f"Invalid priority: {rule.options.priority} (should be 1-3)")

        # Validate flow options
        for flow_state in rule.options.flow:
            if flow_state not in FLOW_STATES:
                if self.strict:
                    errors.append(f"Unknown flow state: {flow_state}")

        return errors

    def _validate_consistency(self, rule: SuricataRule) -> List[str]:
        """Validate logical consistency of the rule."""
        errors: List[str] = []

        # Check protocol-specific options
        protocol = rule.header.protocol

        # HTTP-specific checks
        if protocol == "http":
            http_keywords = [k for k in rule.options.other_options.keys() if k.startswith("http")]
            if not http_keywords and not rule.options.content:
                if self.strict:
                    errors.append("HTTP rule should have HTTP-specific keywords or content")

        # DNS-specific checks
        elif protocol == "dns":
            dns_keywords = [k for k in rule.options.other_options.keys() if k.startswith("dns")]
            if not dns_keywords:
                if self.strict:
                    errors.append("DNS rule should have DNS-specific keywords")

        # Check flow direction consistency
        if "to_server" in rule.options.flow and "to_client" in rule.options.flow:
            errors.append("Conflicting flow directions: to_server and to_client")

        if "from_server" in rule.options.flow and "from_client" in rule.options.flow:
            errors.append("Conflicting flow directions: from_server and from_client")

        return errors

    def _is_valid_ip(self, ip_string: str) -> bool:
        """Check if IP address or variable is valid."""
        if not ip_string:
            return False
        return bool(self.IP_PATTERN.match(ip_string))

    def _is_valid_port(self, port_string: str) -> bool:
        """Check if port or variable is valid."""
        if not port_string:
            return False
        return bool(self.PORT_PATTERN.match(port_string))


# Convenience function
def validate_rule(rule: SuricataRule, strict: bool = False) -> Tuple[bool, List[str]]:
    """
    Validate a Suricata rule.

    Args:
        rule: SuricataRule object to validate
        strict: If True, apply strict validation rules

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    validator = SuricataValidator(strict=strict)
    return validator.validate_rule(rule)
