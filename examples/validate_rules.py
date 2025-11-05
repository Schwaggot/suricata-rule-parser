#!/usr/bin/env python3
"""Example script demonstrating how to validate Suricata rules."""

import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from suricata_rule_parser import parse_file, validate_rule


def main():
    """Validate rules from a file and report any issues."""
    if len(sys.argv) < 2:
        print("Usage: python validate_rules.py <rules_file> [--strict]")
        print("\nExample:")
        print("  python validate_rules.py ../rules/example.rules")
        print("  python validate_rules.py ../rules/example.rules --strict")
        sys.exit(1)

    rules_file = Path(sys.argv[1])
    strict_mode = "--strict" in sys.argv

    if not rules_file.exists():
        print(f"Error: File not found: {rules_file}")
        sys.exit(1)

    print(f"Validating rules from: {rules_file}")
    if strict_mode:
        print("Mode: STRICT")
    print("=" * 60)

    try:
        rules = parse_file(rules_file)
        print(f"\nParsed {len(rules)} rules successfully")
        print("\nValidating rules...")
        print("-" * 60)

        valid_count = 0
        invalid_count = 0
        all_errors = []

        for rule in rules:
            is_valid, errors = validate_rule(rule, strict=strict_mode)

            if is_valid:
                valid_count += 1
                print(f"✓ SID {rule.sid}: {rule.msg[:60]}")
            else:
                invalid_count += 1
                print(f"\n✗ SID {rule.sid}: {rule.msg[:60]}")
                for error in errors:
                    print(f"  - {error}")
                    all_errors.append((rule.sid, error))

        # Summary
        print("\n" + "=" * 60)
        print("Validation Summary:")
        print(f"  Total rules: {len(rules)}")
        print(f"  Valid: {valid_count}")
        print(f"  Invalid: {invalid_count}")

        if invalid_count > 0:
            print(f"\n  Total validation errors: {len(all_errors)}")
            sys.exit(1)
        else:
            print("\nAll rules are valid!")
            sys.exit(0)

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
