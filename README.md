# Suricata Rule Parser

A high-performance Python library for parsing Suricata IDS/IPS rules. This library provides a robust, regex-based parser
that converts Suricata `.rules` files into Python objects, supports rule validation, and can serialize rules back to
valid Suricata format.

## Features

- **Parse Suricata Rules**: Convert `.rules` files into Python objects
- **Rule Validation**: Validate rules against Suricata syntax requirements
- **Serialization**: Convert Python objects back to valid Suricata rule strings
- **Dictionary Conversion**: Export rules as dictionaries for easy integration
- **CLI Tool**: Command-line interface for parsing, validating, and analyzing rules
- **High Performance**: Optimized regex-based parser for both single-rule and batch parsing
- **Type Hints**: Full type annotations for better IDE support
- **Comprehensive Testing**: Extensive test suite with pytest

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/suricata-rule-parser.git
cd suricata-rule-parser

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

### From Wheel

```bash
# Build the wheel
pip install build
python -m build

# Install the wheel
pip install dist/suricata_rule_parser-0.1.0-py3-none-any.whl
```

## Quick Start

### Parse a Single Rule

```python
from suricata_rule_parser import parse_rule

rule_string = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'
rule = parse_rule(rule_string)

print(f"Action: {rule.action}")
print(f"Protocol: {rule.protocol}")
print(f"SID: {rule.sid}")
print(f"Message: {rule.msg}")
```

### Parse a Rules File

```python
from suricata_rule_parser import parse_file

rules = parse_file("path/to/rules.rules")

for rule in rules:
    print(f"[{rule.sid}] {rule.msg}")
```

### Convert to Dictionary

```python
from suricata_rule_parser import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)')
rule_dict = rule.to_dict()

print(rule_dict)
# Output:
# {
#   'header': {
#     'action': 'alert',
#     'protocol': 'tcp',
#     'source_ip': 'any',
#     ...
#   },
#   'options': {
#     'msg': 'Test',
#     'sid': 1,
#     'rev': 1,
#     ...
#   }
# }
```

### Validate Rules

```python
from suricata_rule_parser import parse_rule, validate_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)')
is_valid, errors = validate_rule(rule)

if is_valid:
    print("Rule is valid!")
else:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error}")
```

### Serialize Rules

```python
from suricata_rule_parser import RuleHeader, RuleOptions, SuricataRule, serialize_rule

# Create a rule programmatically
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
    msg="Suspicious HTTP Request",
    sid=1000001,
    rev=1,
    classtype="web-application-attack",
    priority=1,
)

rule = SuricataRule(header=header, options=options)

# Serialize to rule string
rule_string = serialize_rule(rule)
print(rule_string)
```

## CLI Usage

The library includes a command-line tool for working with rules:

### Parse Rules

```bash
# Parse and display rules in compact format
suricata-parse parse rules/example.rules

# Parse and display as JSON
suricata-parse parse rules/example.rules --format json

# Parse and display in text format
suricata-parse parse rules/example.rules --format text
```

### Validate Rules

```bash
# Validate rules
suricata-parse validate rules/example.rules

# Validate with strict mode
suricata-parse validate rules/example.rules --strict
```

### Show Statistics

```bash
# Display rule statistics
suricata-parse info rules/example.rules
```

## Examples

See the `examples/` directory for complete example scripts:

- `parse_file.py`: Parse and display rules from a file
- `validate_rules.py`: Validate rules and report errors
- `generate_rule.py`: Create and serialize rules programmatically

Run examples:

```bash
# Parse example rules
python examples/parse_file.py rules/example.rules

# Validate rules
python examples/validate_rules.py rules/example.rules

# Generate rules
python examples/generate_rule.py output.rules
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=suricata_rule_parser --cov-report=html

# Run specific test file
pytest tests/test_parser.py

# Run with verbose output
pytest -v
```

### Code Quality

```bash
# Format code with black
black suricata_rule_parser/ tests/

# Lint with flake8
flake8 suricata_rule_parser/ tests/

# Type check with mypy
mypy suricata_rule_parser/
```

## Performance

The parser is optimized for both single-rule and batch parsing:

- **Single rule**: Low latency parsing for real-time analysis
- **Batch parsing**: Efficient processing of large rulesets (tested with 45K+ rules)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
