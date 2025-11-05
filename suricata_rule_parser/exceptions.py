"""Custom exceptions for Suricata rule parser."""


class SuricataRuleParserError(Exception):
    """Base exception for all parser errors."""

    pass


class ParseError(SuricataRuleParserError):
    """Exception raised when parsing fails."""

    def __init__(self, message: str, rule: str = "", position: int = -1) -> None:
        """
        Initialize ParseError.

        Args:
            message: Error message describing what went wrong
            rule: The rule string that failed to parse
            position: Position in the rule where the error occurred
        """
        self.message = message
        self.rule = rule
        self.position = position

        if rule and position >= 0:
            super().__init__(f"{message} at position {position} in rule: {rule[:50]}...")
        elif rule:
            super().__init__(f"{message} in rule: {rule[:50]}...")
        else:
            super().__init__(message)


class ValidationError(SuricataRuleParserError):
    """Exception raised when rule validation fails."""

    def __init__(self, message: str, rule_sid: int = -1, errors: list = None) -> None:
        """
        Initialize ValidationError.

        Args:
            message: Error message describing validation failure
            rule_sid: SID of the rule that failed validation
            errors: List of specific validation errors
        """
        self.message = message
        self.rule_sid = rule_sid
        self.errors = errors or []

        if rule_sid >= 0:
            super().__init__(f"{message} (SID: {rule_sid})")
        else:
            super().__init__(message)


class SerializationError(SuricataRuleParserError):
    """Exception raised when rule serialization fails."""

    def __init__(self, message: str, rule_sid: int = -1) -> None:
        """
        Initialize SerializationError.

        Args:
            message: Error message describing serialization failure
            rule_sid: SID of the rule that failed serialization
        """
        self.message = message
        self.rule_sid = rule_sid

        if rule_sid >= 0:
            super().__init__(f"{message} (SID: {rule_sid})")
        else:
            super().__init__(message)


class InvalidRuleFormatError(ParseError):
    """Exception raised when rule format is invalid."""

    pass


class InvalidOptionError(ParseError):
    """Exception raised when a rule option is invalid."""

    pass


class MissingRequiredOptionError(ValidationError):
    """Exception raised when a required option is missing."""

    pass
