"""Command-line interface for Suricata rule parser."""

import argparse
import json
import sys
from pathlib import Path
from typing import List

from .__version__ import __version__
from .exceptions import ParseError, ValidationError
from .parser import SuricataParser
from .serializer import SuricataSerializer
from .validator import SuricataValidator


def parse_command(args: argparse.Namespace) -> int:
    """
    Parse command: Parse rules and display as JSON.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    parser = SuricataParser()

    try:
        rules = parser.parse_file(args.file)

        if args.format == "json":
            output = [rule.to_dict() for rule in rules]
            print(json.dumps(output, indent=2))
        elif args.format == "text":
            for rule in rules:
                print(f"SID {rule.sid}: {rule.msg}")
                print(f"  Action: {rule.action}")
                print(f"  Protocol: {rule.protocol}")
                print(f"  {rule.header.source_ip}:{rule.header.source_port} "
                      f"{rule.header.direction} "
                      f"{rule.header.dest_ip}:{rule.header.dest_port}")
                if rule.classtype:
                    print(f"  Classtype: {rule.classtype}")
                print()
        else:  # compact
            for rule in rules:
                print(f"[{rule.sid}] {rule.action} {rule.protocol}: {rule.msg}")

        if args.verbose:
            print(f"\nTotal rules parsed: {len(rules)}", file=sys.stderr)

        return 0

    except ParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def validate_command(args: argparse.Namespace) -> int:
    """
    Validate command: Validate rules and report errors.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    parser = SuricataParser()
    validator = SuricataValidator(strict=args.strict)

    try:
        rules = parser.parse_file(args.file)

        total_rules = len(rules)
        valid_rules = 0
        invalid_rules = 0
        all_errors: List[str] = []

        for rule in rules:
            is_valid, errors = validator.validate_rule(rule)
            if is_valid:
                valid_rules += 1
                if args.verbose:
                    print(f"✓ SID {rule.sid}: {rule.msg}")
            else:
                invalid_rules += 1
                print(f"✗ SID {rule.sid}: {rule.msg}")
                for error in errors:
                    print(f"  - {error}")
                    all_errors.append(f"SID {rule.sid}: {error}")

        print(f"\n{'=' * 60}")
        print(f"Total rules: {total_rules}")
        print(f"Valid rules: {valid_rules}")
        print(f"Invalid rules: {invalid_rules}")
        print(f"{'=' * 60}")

        return 0 if invalid_rules == 0 else 1

    except ParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def info_command(args: argparse.Namespace) -> int:
    """
    Info command: Show statistics about rules.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    parser = SuricataParser()

    try:
        rules = parser.parse_file(args.file)

        # Collect statistics
        total_rules = len(rules)
        enabled_rules = sum(1 for r in rules if r.enabled)
        disabled_rules = total_rules - enabled_rules

        # Count by action
        actions = {}
        for rule in rules:
            actions[rule.action] = actions.get(rule.action, 0) + 1

        # Count by protocol
        protocols = {}
        for rule in rules:
            protocols[rule.protocol] = protocols.get(rule.protocol, 0) + 1

        # Count by classtype
        classtypes = {}
        for rule in rules:
            if rule.classtype:
                classtypes[rule.classtype] = classtypes.get(rule.classtype, 0) + 1

        # Print statistics
        print(f"{'=' * 60}")
        print(f"Suricata Rules Statistics: {args.file}")
        print(f"{'=' * 60}")
        print(f"\nTotal rules: {total_rules}")
        print(f"  Enabled: {enabled_rules}")
        print(f"  Disabled: {disabled_rules}")

        print(f"\nActions:")
        for action, count in sorted(actions.items(), key=lambda x: x[1], reverse=True):
            print(f"  {action}: {count}")

        print(f"\nProtocols:")
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {protocol}: {count}")
        if len(protocols) > 10:
            print(f"  ... and {len(protocols) - 10} more")

        if classtypes:
            print(f"\nTop Classtypes:")
            for classtype, count in sorted(classtypes.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {classtype}: {count}")

        print(f"\n{'=' * 60}")

        return 0

    except ParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main() -> int:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Suricata IDS/IPS rule parser and analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"suricata-rule-parser {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Parse command
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse rules and display as JSON or text",
    )
    parse_parser.add_argument("file", type=Path, help="Path to rules file")
    parse_parser.add_argument(
        "--format",
        choices=["json", "text", "compact"],
        default="compact",
        help="Output format (default: compact)",
    )
    parse_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate rules and report errors",
    )
    validate_parser.add_argument("file", type=Path, help="Path to rules file")
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply strict validation rules",
    )
    validate_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    # Info command
    info_parser = subparsers.add_parser(
        "info",
        help="Show statistics about rules",
    )
    info_parser.add_argument("file", type=Path, help="Path to rules file")
    info_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Dispatch to command handler
    if args.command == "parse":
        return parse_command(args)
    elif args.command == "validate":
        return validate_command(args)
    elif args.command == "info":
        return info_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
