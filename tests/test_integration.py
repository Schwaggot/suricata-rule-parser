"""Integration tests using real rule files."""

import pytest

from suricata_rule_parser import parse_file, validate_rule


class TestIntegration:
    """Integration tests with real Suricata rules."""

    def test_parse_example_rules(self, example_rules_dir):
        """Test parsing the example.rules file if it exists."""
        if example_rules_dir is None:
            pytest.skip("Example rules directory not found")

        example_file = example_rules_dir / "example.rules"
        if not example_file.exists():
            pytest.skip("example.rules file not found")

        rules = parse_file(example_file)
        assert len(rules) > 0
        assert all(rule.sid > 0 for rule in rules)
        assert all(rule.msg for rule in rules)

    def test_validate_example_rules(self, example_rules_dir):
        """Test validating example rules."""
        if example_rules_dir is None:
            pytest.skip("Example rules directory not found")

        example_file = example_rules_dir / "example.rules"
        if not example_file.exists():
            pytest.skip("example.rules file not found")

        rules = parse_file(example_file)
        for rule in rules:
            is_valid, errors = validate_rule(rule)
            # Most example rules should be valid
            if not is_valid:
                print(f"Rule SID {rule.sid} validation errors: {errors}")

    def test_parse_large_ruleset(self, example_rules_dir):
        """Test parsing a large ruleset (if available)."""
        if example_rules_dir is None:
            pytest.skip("Example rules directory not found")

        # Try to find a large ruleset
        et_files = (
            list((example_rules_dir / "et-open").glob("*.rules"))
            if (example_rules_dir / "et-open").exists()
            else []
        )

        if not et_files:
            pytest.skip("No large rulesets found")

        # Parse first available file
        test_file = et_files[0]
        rules = parse_file(test_file)

        # Basic checks
        assert len(rules) > 0
        assert all(isinstance(rule.sid, int) for rule in rules)
        assert all(rule.header.action in ["alert", "drop", "pass", "reject"] for rule in rules)

    def test_roundtrip_example_rules(self, example_rules_dir):
        """Test parse -> serialize -> parse roundtrip on example rules."""
        from suricata_rule_parser import serialize_rule

        if example_rules_dir is None:
            pytest.skip("Example rules directory not found")

        example_file = example_rules_dir / "example.rules"
        if not example_file.exists():
            pytest.skip("example.rules file not found")

        rules = parse_file(example_file)

        for rule in rules[:5]:  # Test first 5 rules
            # Clear raw to force serialization
            rule.raw = ""
            serialized = serialize_rule(rule)

            # Parse the serialized rule
            from suricata_rule_parser import parse_rule

            reparsed = parse_rule(serialized)

            # Compare key fields
            assert reparsed.action == rule.action
            assert reparsed.protocol == rule.protocol
            assert reparsed.sid == rule.sid
            assert reparsed.msg == rule.msg

    def test_batch_parsing_performance(self, example_rules_dir):
        """Test performance of batch parsing."""
        import time

        if example_rules_dir is None:
            pytest.skip("Example rules directory not found")

        example_file = example_rules_dir / "example.rules"
        if not example_file.exists():
            pytest.skip("example.rules file not found")

        # Time the parsing
        start_time = time.time()
        rules = parse_file(example_file)
        elapsed_time = time.time() - start_time

        # Should be able to parse rules reasonably fast
        # (This is a soft check, adjust as needed)
        assert elapsed_time < 10.0  # Should take less than 10 seconds
        print(f"\nParsed {len(rules)} rules in {elapsed_time:.3f} seconds")
        print(f"Average: {len(rules) / elapsed_time:.0f} rules/second")
