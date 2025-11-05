"""Pytest configuration and fixtures for suricata-rule-parser tests."""

import pytest
from pathlib import Path


@pytest.fixture
def sample_alert_rule():
    """Simple alert rule for testing."""
    return 'alert tcp any any -> any 80 (msg:"Test rule"; sid:1000001; rev:1;)'


@pytest.fixture
def sample_http_rule():
    """HTTP rule with content matching."""
    return (
        'alert http any any -> any any '
        '(msg:"ET WEB_SERVER Suspicious User-Agent sqlmap"; '
        'flow:to_server,established; '
        'content:"User-Agent|3a 20|sqlmap"; http_header; '
        'classtype:web-application-attack; '
        'priority:1; '
        'sid:2000008; '
        'rev:2;)'
    )


@pytest.fixture
def sample_dns_rule():
    """DNS rule with metadata."""
    return (
        'alert dns $HOME_NET any -> any any '
        '(msg:"ET DNS Query for .su TLD (Soviet Union) Often Malware Related"; '
        'dns.query; '
        'content:".su"; '
        'nocase; '
        'endswith; '
        'reference:url,www.abuse.ch/?p=3581; '
        'classtype:bad-unknown; '
        'sid:2014169; '
        'rev:4; '
        'metadata:created_at 2012_01_31, confidence Medium, '
        'signature_severity Major, updated_at 2020_09_14;)'
    )


@pytest.fixture
def sample_disabled_rule():
    """Commented out (disabled) rule."""
    return '# alert tcp any any -> any 22 (msg:"SSH traffic"; sid:1000002; rev:1;)'


@pytest.fixture
def sample_complex_rule():
    """Complex rule with multiple content matches."""
    return (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 1024: '
        '(msg:"ET MALWARE Backdoor.Win32.VB.brg C&C Checkin"; '
        'flow:established,to_server; '
        'content:"Status|2a 28|Idle|2e 2e 2e 29 2a|"; '
        'depth:17; '
        'offset:0; '
        'classtype:command-and-control; '
        'sid:2007922; '
        'rev:5; '
        'metadata:created_at 2010_07_30, signature_severity Major, updated_at 2019_07_26;)'
    )


@pytest.fixture
def invalid_rule_no_sid():
    """Invalid rule missing SID."""
    return 'alert tcp any any -> any 80 (msg:"Test rule"; rev:1;)'


@pytest.fixture
def invalid_rule_bad_action():
    """Invalid rule with bad action."""
    return 'badaction tcp any any -> any 80 (msg:"Test rule"; sid:1000001; rev:1;)'


@pytest.fixture
def rules_file_path(tmp_path):
    """Create a temporary rules file for testing."""
    rules_content = """
# Test rules file
alert tcp any any -> any 80 (msg:"HTTP traffic"; sid:1000001; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS traffic"; sid:1000002; rev:1;)
# Commented rule
# alert tcp any any -> any 22 (msg:"SSH traffic"; sid:1000003; rev:1;)
alert dns any any -> any 53 (msg:"DNS traffic"; sid:1000004; rev:1;)
"""
    file_path = tmp_path / "test_rules.rules"
    file_path.write_text(rules_content.strip())
    return file_path


@pytest.fixture
def example_rules_dir():
    """Path to the example rules directory if it exists."""
    project_root = Path(__file__).parent.parent
    rules_dir = project_root / "rules"
    return rules_dir if rules_dir.exists() else None


@pytest.fixture
def sample_pcre_rule_with_quotes():
    """Rule with PCRE pattern containing quotes in character class."""
    return (
        r'alert tcp any any -> any any '
        r'(msg:"PCRE with quotes in character class"; '
        r'pcre:"/^[\"\']\s*:\s*[\"\']\s*/Ri"; '
        r'sid:1000010; '
        r'rev:1;)'
    )


@pytest.fixture
def sample_pcre_rule_complex():
    """Complex PCRE rule with multiple patterns."""
    return (
        r'alert http any any -> any any '
        r'(msg:"Complex PCRE pattern"; '
        r'content:"test"; '
        r'pcre:"/[a-z0-9][\"\']/i"; '
        r'flow:established,to_server; '
        r'sid:1000011; '
        r'rev:1;)'
    )


@pytest.fixture
def sample_pcre_rule_simple():
    """Simple PCRE rule without quotes in pattern."""
    return (
        r'alert tcp any any -> any 80 '
        r'(msg:"Simple PCRE pattern"; '
        r'pcre:"/GET\s+\\/[a-z]+/i"; '
        r'sid:1000012; '
        r'rev:1;)'
    )
