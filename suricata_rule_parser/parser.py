"""Parser for Suricata IDS/IPS rules."""

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from .constants import ACTIONS, PROTOCOLS
from .exceptions import InvalidRuleFormatError, ParseError
from .models import RuleHeader, RuleOptions, SuricataRule


class SuricataParser:
    """Parser for Suricata rules using regex-based approach."""

    # Regex pattern for rule header
    HEADER_PATTERN = re.compile(
        r"^\s*"  # Optional leading whitespace
        r"(#\s*)?"  # Optional comment marker
        r"(\w+)"  # Action (alert, drop, etc.)
        r"\s+"
        r"([\w-]+)"  # Protocol (supports hyphens like tcp-pkt, ftp-data)
        r"\s+"
        r"(\S+)"  # Source IP (supports !, $VAR, [list], CIDR, etc.)
        r"\s+"
        r"(\S+)"  # Source port (supports !, $VAR, [list], ranges, etc.)
        r"\s+"
        r"(->|<>)"  # Direction
        r"\s+"
        r"(\S+)"  # Dest IP (supports !, $VAR, [list], CIDR, etc.)
        r"\s+"
        r"(\S+)"  # Dest port (supports !, $VAR, [list], ranges, etc.)
        r"\s+"
        r"\("  # Opening parenthesis for options
    )

    # Regex for matching individual options
    OPTION_PATTERN = re.compile(
        r"(\w+(?:\.\w+)?)"  # Option key (supports dot notation like dns.query)
        r"(?:\s*:\s*"  # Optional colon and value
        r"(?:"
        r'"([^"]*(?:\\.[^"]*)*)"|'  # Quoted string with escaped quotes
        r"'([^']*(?:\\.[^']*)*)\'|"  # Single-quoted string
        r"([^;]+?)"  # Unquoted value
        r"))?"
        r"\s*;"  # Semicolon
    )

    def __init__(self) -> None:
        """Initialize the parser."""
        pass

    def parse_rule(self, rule_string: str) -> SuricataRule:
        """
        Parse a single Suricata rule string.

        Args:
            rule_string: The rule string to parse

        Returns:
            SuricataRule object

        Raises:
            ParseError: If the rule cannot be parsed
        """
        if not rule_string or not rule_string.strip():
            raise ParseError("Empty rule string")

        original_rule = rule_string
        rule_string = rule_string.strip()

        # Check if rule is commented out
        enabled = not rule_string.startswith("#")

        # Parse header
        header_match = self.HEADER_PATTERN.match(rule_string)
        if not header_match:
            raise InvalidRuleFormatError(
                "Invalid rule format: unable to parse header",
                rule=rule_string,
            )

        comment_marker, action, protocol, src_ip, src_port, direction, dst_ip, dst_port = (
            header_match.groups()
        )

        # Validate action and protocol
        if action not in ACTIONS:
            raise ParseError(f"Invalid action: {action}", rule=rule_string)

        if protocol not in PROTOCOLS and protocol != "ip":
            # Allow unknown protocols but might want to warn
            pass

        # Create header
        header = RuleHeader(
            action=action,
            protocol=protocol,
            source_ip=src_ip,
            source_port=src_port,
            direction=direction,
            dest_ip=dst_ip,
            dest_port=dst_port,
        )

        # Extract options section (everything inside parentheses)
        options_start = header_match.end() - 1  # Position of opening parenthesis
        options_section = self._extract_options_section(rule_string[options_start:])

        # Parse options
        options = self._parse_options(options_section)

        # Create and return rule
        return SuricataRule(
            header=header,
            options=options,
            raw=original_rule,
            enabled=enabled,
        )

    def parse_file(self, filepath: Union[str, Path]) -> List[SuricataRule]:
        """
        Parse a Suricata rules file.

        Args:
            filepath: Path to the rules file

        Returns:
            List of parsed SuricataRule objects

        Raises:
            FileNotFoundError: If file doesn't exist
            ParseError: If parsing fails
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Rules file not found: {filepath}")

        rules = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comment-only lines (that don't contain rule keywords)
                if not line:
                    continue

                # Skip pure comment lines
                if line.startswith("#"):
                    # Check if this looks like an actual commented-out rule
                    # A commented rule should have the pattern: # action protocol ...
                    # Remove leading # and whitespace to check
                    uncommented = line.lstrip("#").strip()
                    if not uncommented:
                        # Empty comment line
                        continue

                    # Check if it starts with an action keyword followed by a protocol
                    parts = uncommented.split()
                    if len(parts) < 8:  # Minimum rule has 8 parts before options
                        # Too short to be a valid rule
                        continue

                    # Check if first word is a valid action
                    if parts[0] not in ACTIONS:
                        continue

                    # Check if second word is a protocol
                    if parts[1] not in PROTOCOLS and parts[1] != "ip":
                        # Not a valid protocol, likely just a comment
                        continue

                    # Looks like a commented-out rule, try to parse it

                try:
                    rule = self.parse_rule(line)
                    rules.append(rule)
                except ParseError as e:
                    # Add line number context to error
                    raise ParseError(
                        f"Line {line_num}: {e.message}",
                        rule=line,
                    ) from e

        return rules

    def parse_rules(self, rule_strings: List[str]) -> List[SuricataRule]:
        """
        Parse multiple rule strings.

        Args:
            rule_strings: List of rule strings

        Returns:
            List of parsed SuricataRule objects
        """
        rules = []
        for rule_string in rule_strings:
            if rule_string.strip():
                try:
                    rules.append(self.parse_rule(rule_string))
                except ParseError:
                    # Skip invalid rules in batch parsing
                    continue
        return rules

    def _count_preceding_backslashes(self, text: str, pos: int) -> int:
        """
        Count consecutive backslashes before a position.

        Args:
            text: The text to search
            pos: The position to look before

        Returns:
            Number of consecutive backslashes before pos
        """
        count = 0
        i = pos - 1
        while i >= 0 and text[i] == "\\":
            count += 1
            i -= 1
        return count

    def _extract_options_section(self, text: str) -> str:
        """
        Extract the options section from within parentheses.

        Handles nested parentheses in option values and PCRE patterns with quotes.

        Args:
            text: Text starting with opening parenthesis

        Returns:
            Options string without outer parentheses
        """
        if not text.startswith("("):
            raise ParseError("Options section must start with (")

        depth = 0
        in_quotes = False
        quote_char = None
        in_option_value = False  # Track if we're in an unquoted option value
        last_semicolon = 0  # Position of last semicolon
        i = 0

        while i < len(text):
            char = text[i]

            # Handle quotes - check if quote is escaped by counting preceding backslashes
            # A quote is escaped if there's an odd number of backslashes before it
            if char in ('"', "'"):
                num_backslashes = self._count_preceding_backslashes(text, i)
                is_escaped = (num_backslashes % 2) == 1

                if not is_escaped and not in_quotes:
                    # Only treat as opening quote if immediately preceded by colon
                    # (with optional whitespace). This prevents apostrophes in URLs
                    # (like "fin8's") from being treated as quotes
                    segment_before = text[last_semicolon:i]
                    # Check if quote immediately follows colon: "key:" or "key: "
                    immediately_after_colon = re.search(r":\s*$", segment_before)

                    if immediately_after_colon:
                        # Check if this is a PCRE pattern by looking backwards
                        if re.search(r"pcre\s*:\s*$", segment_before):
                            # This is a PCRE pattern - use special extraction
                            try:
                                pcre_value, end_pos = self._extract_pcre_value(text, i)
                                # Jump to the position after the closing quote
                                i = end_pos + 1
                                continue
                            except ParseError:
                                # If PCRE extraction fails, fall back to normal quote handling
                                pass

                        # Normal quote handling - start quoted value
                        in_quotes = True
                        quote_char = char
                elif not is_escaped and char == quote_char:
                    in_quotes = False
                    quote_char = None

            # Track option value state (only when not in quotes)
            if not in_quotes:
                if char == ":":
                    # Check if this colon is the first one after the last semicolon
                    segment = text[last_semicolon:i]
                    if ":" not in segment and depth > 0:
                        # This is the first colon after a semicolon/start - entering an option value
                        in_option_value = True
                elif char == ";":
                    # Exiting an option value
                    in_option_value = False
                    last_semicolon = i

            # Handle parentheses (only when not in quotes and not in option values)
            if not in_quotes and not in_option_value:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        # Found the closing parenthesis
                        return text[1:i]

            i += 1

        raise ParseError("Unclosed parentheses in options section")

    def _extract_pcre_value(self, text: str, start_pos: int) -> Tuple[str, int]:
        """
        Extract a PCRE pattern value handling quotes inside character classes.

        PCRE patterns in Suricata are formatted as: pcre:"/pattern/flags"
        The pattern can contain character classes like ["'] which include quotes.

        Args:
            text: The text containing the PCRE value
            start_pos: Position of the opening quote after 'pcre:'

        Returns:
            Tuple of (extracted_value, end_quote_position)
        """
        i = start_pos + 1  # Start after opening quote
        in_pattern = False
        escaped = False

        while i < len(text):
            char = text[i]

            if escaped:
                # Skip escaped characters
                escaped = False
                i += 1
                continue

            if char == "\\":
                # Mark next character as escaped
                escaped = True
                i += 1
                continue

            # Look for the opening / of the PCRE pattern
            if not in_pattern and char == "/":
                in_pattern = True
                i += 1
                continue

            # Look for the closing / of the PCRE pattern
            if in_pattern and char == "/":
                # Skip past any flags (i, s, m, R, U, x, A, D, P, S, X, J, etc.)
                i += 1
                while i < len(text) and text[i] in "ismRUxADPSXJbuLpyPQYlwZQOIB":
                    i += 1

                # Next character should be the closing quote
                if i < len(text) and text[i] == '"':
                    return text[start_pos + 1 : i], i

                # If not a quote, this wasn't the end of the pattern
                # Continue looking (edge case: / inside pattern)
                in_pattern = True
                continue

            # If we find a closing quote before any pattern, return it
            if not in_pattern and char == '"':
                return text[start_pos + 1 : i], i

            i += 1

        raise ParseError("Unclosed PCRE pattern")

    def _parse_options(self, options_string: str) -> RuleOptions:
        """
        Parse the options section of a rule.

        Args:
            options_string: The options string (without outer parentheses)

        Returns:
            RuleOptions object
        """
        options = RuleOptions()

        # Find all option matches
        matches = self.OPTION_PATTERN.findall(options_string)

        content_list = []
        reference_list = []
        flow_list = []
        other_options: Dict[str, Any] = {}

        for match in matches:
            key = match[0]
            # Value is in one of the three captured groups (quoted, single-quoted, or unquoted)
            value = match[1] or match[2] or match[3] if len(match) > 1 else None

            # Strip whitespace from value if present
            if value:
                value = value.strip()

            # Handle specific options
            if key == "msg":
                options.msg = value or ""
            elif key == "sid":
                try:
                    options.sid = int(value) if value else 0
                except ValueError:
                    raise ParseError(f"Invalid SID value: {value}")
            elif key == "rev":
                try:
                    options.rev = int(value) if value else 1
                except ValueError:
                    raise ParseError(f"Invalid rev value: {value}")
            elif key == "classtype":
                options.classtype = value or ""
            elif key == "priority":
                try:
                    options.priority = int(value) if value else 3
                except ValueError:
                    raise ParseError(f"Invalid priority value: {value}")
            elif key == "reference":
                if value:
                    reference_list.append(value)
            elif key == "metadata":
                if value:
                    options.metadata = self._parse_metadata(value)
            elif key == "content":
                if value:
                    content_list.append(value)
            elif key == "flow":
                if value:
                    # Flow can be comma-separated values
                    flow_list.extend([f.strip() for f in value.split(",")])
            else:
                # Store other options
                if value is not None:
                    other_options[key] = value
                else:
                    # Flag option (no value)
                    other_options[key] = True

        # Set list-based options
        options.content = content_list
        options.reference = reference_list
        options.flow = flow_list
        options.other_options = other_options

        return options

    def _parse_metadata(self, metadata_string: str) -> Dict[str, Any]:
        """
        Parse metadata option value.

        Metadata format: key value, key value, ...

        Args:
            metadata_string: The metadata string

        Returns:
            Dictionary of metadata key-value pairs
        """
        metadata: Dict[str, Any] = {}

        # Split by comma, but be careful about spaces
        parts = [p.strip() for p in metadata_string.split(",")]

        for part in parts:
            # Each part should be "key value" or just "key"
            tokens = part.split(None, 1)
            if len(tokens) == 2:
                key, value = tokens
                # Try to convert to appropriate type
                if value.isdigit():
                    metadata[key] = int(value)
                elif value.lower() in ("true", "false"):
                    metadata[key] = value.lower() == "true"
                else:
                    metadata[key] = value
            elif len(tokens) == 1:
                # Just a key, no value
                metadata[tokens[0]] = True

        return metadata


# Convenience functions for direct use
def parse_rule(rule_string: str) -> SuricataRule:
    """
    Parse a single Suricata rule string.

    Args:
        rule_string: The rule string to parse

    Returns:
        SuricataRule object
    """
    parser = SuricataParser()
    return parser.parse_rule(rule_string)


def parse_file(filepath: Union[str, Path]) -> List[SuricataRule]:
    """
    Parse a Suricata rules file.

    Args:
        filepath: Path to the rules file

    Returns:
        List of parsed SuricataRule objects
    """
    parser = SuricataParser()
    return parser.parse_file(filepath)


def parse_rules(rule_strings: List[str]) -> List[SuricataRule]:
    """
    Parse multiple rule strings.

    Args:
        rule_strings: List of rule strings

    Returns:
        List of parsed SuricataRule objects
    """
    parser = SuricataParser()
    return parser.parse_rules(rule_strings)
