#!/usr/bin/env python3
"""Example script demonstrating how to parse a Suricata rules file."""

import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from suricata_rule_parser import parse_file


def main():
    """Parse a rules file and display information about the rules."""
    if len(sys.argv) < 2:
        print("Usage: python parse_file.py <rules_file>")
        print("\nExample:")
        print("  python parse_file.py ../rules/example.rules")
        sys.exit(1)

    rules_file = Path(sys.argv[1])

    if not rules_file.exists():
        print(f"Error: File not found: {rules_file}")
        sys.exit(1)

    print(f"Parsing rules from: {rules_file}")
    print("=" * 60)

    try:
        rules = parse_file(rules_file)

        print(f"\nTotal rules parsed: {len(rules)}")
        print("\nFirst 10 rules:")
        print("-" * 60)

        for i, rule in enumerate(rules[:10], 1):
            print(f"\n{i}. SID: {rule.sid}")
            print(f"   Message: {rule.msg}")
            print(f"   Action: {rule.action}")
            print(f"   Protocol: {rule.protocol}")
            print(f"   Direction: {rule.header.source_ip}:{rule.header.source_port} "
                  f"{rule.header.direction} "
                  f"{rule.header.dest_ip}:{rule.header.dest_port}")
            if rule.classtype:
                print(f"   Classtype: {rule.classtype}")
            if rule.options.content:
                print(f"   Content matches: {len(rule.options.content)}")
            print(f"   Enabled: {rule.enabled}")

        # Statistics
        print("\n" + "=" * 60)
        print("Statistics:")
        print(f"  Total rules: {len(rules)}")
        print(f"  Enabled: {sum(1 for r in rules if r.enabled)}")
        print(f"  Disabled: {sum(1 for r in rules if not r.enabled)}")

        actions = {}
        for rule in rules:
            actions[rule.action] = actions.get(rule.action, 0) + 1

        print("\n  Actions:")
        for action, count in sorted(actions.items()):
            print(f"    {action}: {count}")

    except Exception as e:
        print(f"Error parsing rules: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
