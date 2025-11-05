"""Constants for Suricata rule parsing."""

from typing import Set, FrozenSet

# Rule actions
ACTIONS: FrozenSet[str] = frozenset([
    "alert",
    "pass",
    "drop",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
])

# Protocols
PROTOCOLS: FrozenSet[str] = frozenset([
    # Network layer
    "ip",
    "icmp",
    "tcp",
    "udp",
    # Packet-level protocols
    "tcp-pkt",
    "udp-pkt",
    "icmp-pkt",
    # Application layer
    "http",
    "ftp",
    "ftp-data",
    "tls",
    "smb",
    "dns",
    "dcerpc",
    "ssh",
    "smtp",
    "imap",
    "http2",
    "modbus",
    "dnp3",
    "enip",
    "nfs",
    "ikev2",
    "krb5",
    "ntp",
    "dhcp",
    "rfb",
    "rdp",
    "snmp",
    "tftp",
    "sip",
    "http3",
])

# Direction operators
DIRECTIONS: FrozenSet[str] = frozenset([
    "->",  # Unidirectional (source to destination)
    "<>",  # Bidirectional
])

# Option keywords that take string values
STRING_OPTIONS: FrozenSet[str] = frozenset([
    "msg",
    "content",
    "uricontent",
    "pcre",
    "isdataat",
    "classtype",
    "reference",
    "priority",
    "sid",
    "rev",
    "gid",
    "metadata",
    "target",
    "flowbits",
    "xbits",
    "noalert",
    "tag",
    "detection_filter",
    "threshold",
    "http_method",
    "http_uri",
    "http_header",
    "http_cookie",
    "http_user_agent",
    "http_stat_code",
    "http_stat_msg",
    "http_client_body",
    "http_server_body",
    "dns_query",
    "dns.query",
    "tls_cert_subject",
    "tls_cert_issuer",
    "tls_sni",
    "ssh.proto",
    "ssl_version",
    "ssl_state",
])

# Option keywords that are flags (no value)
FLAG_OPTIONS: FrozenSet[str] = frozenset([
    "nocase",
    "rawbytes",
    "fast_pattern",
    "endswith",
    "startswith",
    "http_encode",
    "http_header_names",
    "http_request_line",
    "http_response_line",
    "file_data",
    "pkt_data",
    "base64_decode",
    "base64_data",
])

# Option keywords that take numeric values
NUMERIC_OPTIONS: FrozenSet[str] = frozenset([
    "depth",
    "offset",
    "distance",
    "within",
    "dsize",
    "ttl",
    "itype",
    "icode",
    "id",
    "ack",
    "seq",
    "window",
    "ipopts",
    "fragbits",
    "fragoffset",
    "tos",
    "ip_proto",
    "sameip",
])

# Flow-related options
FLOW_OPTIONS: FrozenSet[str] = frozenset([
    "flow",
    "flowint",
    "stream_size",
])

# Byte test/jump/extract options
BYTE_OPTIONS: FrozenSet[str] = frozenset([
    "byte_test",
    "byte_jump",
    "byte_extract",
    "byte_math",
])

# All recognized option keywords
ALL_OPTIONS: Set[str] = set(
    STRING_OPTIONS
    | FLAG_OPTIONS
    | NUMERIC_OPTIONS
    | FLOW_OPTIONS
    | BYTE_OPTIONS
)

# Required options in every rule
REQUIRED_OPTIONS: FrozenSet[str] = frozenset([
    "msg",
    "sid",
    "rev",
])

# Metadata option keys (commonly used)
COMMON_METADATA_KEYS: FrozenSet[str] = frozenset([
    "created_at",
    "updated_at",
    "signature_severity",
    "attack_target",
    "deployment",
    "former_category",
    "confidence",
    "affected_product",
    "performance_impact",
    "tag",
])

# Flow states
FLOW_STATES: FrozenSet[str] = frozenset([
    "established",
    "not_established",
    "stateless",
    "to_server",
    "to_client",
    "from_server",
    "from_client",
    "only_stream",
    "no_stream",
    "only_frag",
    "no_frag",
])

# Classtype definitions (commonly used)
COMMON_CLASSTYPES: FrozenSet[str] = frozenset([
    "not-suspicious",
    "unknown",
    "bad-unknown",
    "attempted-recon",
    "successful-recon-limited",
    "successful-recon-largescale",
    "attempted-dos",
    "successful-dos",
    "attempted-user",
    "unsuccessful-user",
    "successful-user",
    "attempted-admin",
    "successful-admin",
    "rpc-portmap-decode",
    "shellcode-detect",
    "string-detect",
    "suspicious-filename-detect",
    "suspicious-login",
    "system-call-detect",
    "tcp-connection",
    "trojan-activity",
    "unusual-client-port-connection",
    "network-scan",
    "denial-of-service",
    "non-standard-protocol",
    "protocol-command-decode",
    "web-application-activity",
    "web-application-attack",
    "misc-activity",
    "misc-attack",
    "icmp-event",
    "inappropriate-content",
    "policy-violation",
    "default-login-attempt",
    "targeted-activity",
    "exploit-kit",
    "external-ip-check",
    "domain-c2",
    "pup-activity",
    "credential-theft",
    "social-engineering",
    "coin-mining",
    "command-and-control",
])
