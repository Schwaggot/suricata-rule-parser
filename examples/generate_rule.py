#!/usr/bin/env python3
"""Example script demonstrating how to create and serialize Suricata rules."""

import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent))

from suricata_rule_parser import RuleHeader, RuleOptions, SuricataRule, serialize_rule


def create_http_rule():
    """Create a sample HTTP rule."""
    header = RuleHeader(
        action="alert",
        protocol="http",
        source_ip="$HOME_NET",
        source_port="any",
        direction="->",
        dest_ip="$EXTERNAL_NET",
        dest_port="any",
    )

    options = RuleOptions(
        msg="Suspicious User-Agent - Potential Scanner",
        sid=1000001,
        rev=1,
        classtype="web-application-attack",
        priority=1,
        content=["User-Agent"],
        flow=["to_server", "established"],
        reference=["url,example.com/security"],
        metadata={
            "created_at": "2025_01_01",
            "severity": "High",
            "confidence": "Medium",
        },
    )

    # Add HTTP-specific options to other_options
    options.other_options["http_header"] = True
    options.other_options["nocase"] = True

    return SuricataRule(header=header, options=options, enabled=True)


def create_dns_rule():
    """Create a sample DNS rule."""
    header = RuleHeader(
        action="alert",
        protocol="dns",
        source_ip="$HOME_NET",
        source_port="any",
        direction="->",
        dest_ip="any",
        dest_port="53",
    )

    options = RuleOptions(
        msg="DNS Query to Suspicious TLD",
        sid=1000002,
        rev=1,
        classtype="bad-unknown",
        priority=2,
        content=[".xyz"],
    )

    options.other_options["dns.query"] = True
    options.other_options["nocase"] = True
    options.other_options["endswith"] = True

    return SuricataRule(header=header, options=options, enabled=True)


def create_tcp_rule():
    """Create a sample TCP rule."""
    header = RuleHeader(
        action="drop",
        protocol="tcp",
        source_ip="$EXTERNAL_NET",
        source_port="any",
        direction="->",
        dest_ip="$HOME_NET",
        dest_port="22",
    )

    options = RuleOptions(
        msg="SSH Brute Force Attempt",
        sid=1000003,
        rev=1,
        classtype="attempted-admin",
        priority=1,
        flow=["to_server"],
    )

    options.other_options["threshold"] = "type threshold, track by_src, count 5, seconds 60"

    return SuricataRule(header=header, options=options, enabled=True)


def main():
    """Generate example rules and display them."""
    print("Generating Suricata Rules")
    print("=" * 60)

    # Create rules
    http_rule = create_http_rule()
    dns_rule = create_dns_rule()
    tcp_rule = create_tcp_rule()

    rules = [http_rule, dns_rule, tcp_rule]

    # Serialize and display
    for i, rule in enumerate(rules, 1):
        print(f"\nRule {i}:")
        print("-" * 60)
        print(f"Type: {rule.protocol.upper()}")
        print(f"SID: {rule.sid}")
        print(f"Message: {rule.msg}")
        print(f"\nSerialized rule:")
        serialized = serialize_rule(rule)
        print(serialized)

    # Save to file if requested
    if len(sys.argv) > 1:
        output_file = Path(sys.argv[1])
        print(f"\n{'=' * 60}")
        print(f"Saving rules to: {output_file}")

        with open(output_file, "w") as f:
            f.write("# Generated Suricata Rules\n")
            f.write("# Created with suricata-rule-parser\n\n")

            for rule in rules:
                serialized = serialize_rule(rule)
                f.write(f"{serialized}\n")

        print("Rules saved successfully!")


if __name__ == "__main__":
    main()
