"""
Suricata Rule Parser - A high-performance Python library for parsing Suricata IDS/IPS rules.

This library provides functionality to:
- Parse Suricata .rules files into Python objects
- Convert rules to dictionaries
- Serialize rules back to valid Suricata format
- Validate rules against syntax requirements
"""

from .__version__ import __version__, __author__, __license__
from .constants import ACTIONS, PROTOCOLS, DIRECTIONS
from .exceptions import (
    SuricataRuleParserError,
    ParseError,
    ValidationError,
    SerializationError,
    InvalidRuleFormatError,
    InvalidOptionError,
    MissingRequiredOptionError,
)
from .models import RuleHeader, RuleOptions, SuricataRule
from .parser import SuricataParser, parse_rule, parse_file, parse_rules
from .serializer import SuricataSerializer, serialize_rule
from .validator import SuricataValidator, validate_rule

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Constants
    "ACTIONS",
    "PROTOCOLS",
    "DIRECTIONS",
    # Exceptions
    "SuricataRuleParserError",
    "ParseError",
    "ValidationError",
    "SerializationError",
    "InvalidRuleFormatError",
    "InvalidOptionError",
    "MissingRequiredOptionError",
    # Models
    "RuleHeader",
    "RuleOptions",
    "SuricataRule",
    # Parser
    "SuricataParser",
    "parse_rule",
    "parse_file",
    "parse_rules",
    # Serializer
    "SuricataSerializer",
    "serialize_rule",
    # Validator
    "SuricataValidator",
    "validate_rule",
]
