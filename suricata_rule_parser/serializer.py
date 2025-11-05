"""Serializer for converting Suricata rule objects back to rule strings."""

from typing import Any, Dict, List

from .exceptions import SerializationError
from .models import RuleOptions, SuricataRule


class SuricataSerializer:
    """Serializer for Suricata rules."""

    def __init__(self) -> None:
        """Initialize the serializer."""
        pass

    def serialize_rule(self, rule: SuricataRule) -> str:
        """
        Convert a SuricataRule object to a valid rule string.

        Args:
            rule: SuricataRule object to serialize

        Returns:
            Valid Suricata rule string

        Raises:
            SerializationError: If serialization fails
        """
        try:
            # If we have the raw rule and it hasn't been modified, use it
            if rule.raw:
                # Check if rule should be disabled
                if not rule.enabled and not rule.raw.strip().startswith("#"):
                    return f"# {rule.raw}"
                elif rule.enabled and rule.raw.strip().startswith("#"):
                    return rule.raw.lstrip("#").lstrip()
                return rule.raw

            # Build the rule from components
            header = self._serialize_header(rule)
            options = self._serialize_options(rule.options)

            rule_string = f"{header} ({options})"

            # Add comment marker if disabled
            if not rule.enabled:
                rule_string = f"# {rule_string}"

            return rule_string

        except Exception as e:
            raise SerializationError(
                f"Failed to serialize rule: {str(e)}",
                rule_sid=rule.sid,
            ) from e

    def _serialize_header(self, rule: SuricataRule) -> str:
        """
        Serialize the rule header.

        Args:
            rule: SuricataRule object

        Returns:
            Header string
        """
        h = rule.header
        return (
            f"{h.action} {h.protocol} "
            f"{h.source_ip} {h.source_port} "
            f"{h.direction} "
            f"{h.dest_ip} {h.dest_port}"
        )

    def _serialize_options(self, options: RuleOptions) -> str:
        """
        Serialize rule options.

        Args:
            options: RuleOptions object

        Returns:
            Options string (without outer parentheses)
        """
        parts: List[str] = []

        # Required options first
        if options.msg:
            parts.append(f'msg:"{options.msg}"')

        # Flow (if present, usually goes early)
        if options.flow:
            flow_value = ",".join(options.flow)
            parts.append(f"flow:{flow_value}")

        # Content matches
        for content in options.content:
            parts.append(f'content:"{content}"')

        # Content modifiers (if tracked separately)
        # Note: In the current model, modifiers are in other_options

        # Other options
        for key, value in options.other_options.items():
            if value is True:
                # Flag option
                parts.append(f"{key}")
            else:
                # Value option
                # Quote string values, don't quote numbers
                if isinstance(value, str) and not value.isdigit():
                    parts.append(f'{key}:"{value}"')
                else:
                    parts.append(f"{key}:{value}")

        # Classtype
        if options.classtype:
            parts.append(f"classtype:{options.classtype}")

        # Priority
        if options.priority != 3:  # Only include if not default
            parts.append(f"priority:{options.priority}")

        # References
        for ref in options.reference:
            parts.append(f"reference:{ref}")

        # Metadata
        if options.metadata:
            metadata_str = self._serialize_metadata(options.metadata)
            parts.append(f"metadata:{metadata_str}")

        # Required options last (SID and rev)
        parts.append(f"sid:{options.sid}")
        parts.append(f"rev:{options.rev}")

        return "; ".join(parts) + ";"

    def _serialize_metadata(self, metadata: Dict[str, Any]) -> str:
        """
        Serialize metadata dictionary.

        Args:
            metadata: Metadata dictionary

        Returns:
            Metadata string
        """
        parts = []
        for key, value in metadata.items():
            if value is True:
                parts.append(key)
            else:
                parts.append(f"{key} {value}")

        return ", ".join(parts)


# Convenience function
def serialize_rule(rule: SuricataRule) -> str:
    """
    Convert a SuricataRule object to a valid rule string.

    Args:
        rule: SuricataRule object to serialize

    Returns:
        Valid Suricata rule string
    """
    serializer = SuricataSerializer()
    return serializer.serialize_rule(rule)
