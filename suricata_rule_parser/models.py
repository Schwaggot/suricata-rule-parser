"""Data models for Suricata rules."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RuleHeader:
    """Represents the header portion of a Suricata rule."""

    action: str
    protocol: str
    source_ip: str
    source_port: str
    direction: str
    dest_ip: str
    dest_port: str

    def to_dict(self) -> Dict[str, str]:
        """Convert header to dictionary."""
        return {
            "action": self.action,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "direction": self.direction,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "RuleHeader":
        """Create header from dictionary."""
        return cls(
            action=data["action"],
            protocol=data["protocol"],
            source_ip=data["source_ip"],
            source_port=data["source_port"],
            direction=data["direction"],
            dest_ip=data["dest_ip"],
            dest_port=data["dest_port"],
        )


@dataclass
class RuleOptions:
    """Represents the options portion of a Suricata rule."""

    # Required options
    msg: str = ""
    sid: int = 0
    rev: int = 1

    # Common metadata options
    classtype: str = ""
    priority: int = 3
    reference: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Content matching options
    content: List[str] = field(default_factory=list)
    content_modifiers: List[Dict[str, Any]] = field(default_factory=list)

    # Flow options
    flow: List[str] = field(default_factory=list)

    # All other options (catch-all for any option we don't explicitly model)
    other_options: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert options to dictionary."""
        result: Dict[str, Any] = {
            "msg": self.msg,
            "sid": self.sid,
            "rev": self.rev,
        }

        if self.classtype:
            result["classtype"] = self.classtype
        if self.priority != 3:
            result["priority"] = self.priority
        if self.reference:
            result["reference"] = self.reference
        if self.metadata:
            result["metadata"] = self.metadata
        if self.content:
            result["content"] = self.content
        if self.content_modifiers:
            result["content_modifiers"] = self.content_modifiers
        if self.flow:
            result["flow"] = self.flow
        if self.other_options:
            result["other_options"] = self.other_options

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleOptions":
        """Create options from dictionary."""
        return cls(
            msg=data.get("msg", ""),
            sid=data.get("sid", 0),
            rev=data.get("rev", 1),
            classtype=data.get("classtype", ""),
            priority=data.get("priority", 3),
            reference=data.get("reference", []),
            metadata=data.get("metadata", {}),
            content=data.get("content", []),
            content_modifiers=data.get("content_modifiers", []),
            flow=data.get("flow", []),
            other_options=data.get("other_options", {}),
        )


@dataclass
class SuricataRule:
    """Represents a complete Suricata IDS/IPS rule."""

    header: RuleHeader
    options: RuleOptions
    raw: str = ""  # Original raw rule string
    enabled: bool = True  # Whether the rule is enabled (not commented out)

    def __post_init__(self) -> None:
        """Validate rule after initialization."""
        if not self.header:
            raise ValueError("Rule must have a header")
        if not self.options:
            raise ValueError("Rule must have options")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule to dictionary representation.

        Returns:
            Dictionary containing all rule data
        """
        return {
            "header": self.header.to_dict(),
            "options": self.options.to_dict(),
            "raw": self.raw,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SuricataRule":
        """
        Create rule from dictionary representation.

        Args:
            data: Dictionary containing rule data

        Returns:
            SuricataRule instance
        """
        return cls(
            header=RuleHeader.from_dict(data["header"]),
            options=RuleOptions.from_dict(data["options"]),
            raw=data.get("raw", ""),
            enabled=data.get("enabled", True),
        )

    @property
    def action(self) -> str:
        """Get rule action."""
        return self.header.action

    @property
    def protocol(self) -> str:
        """Get rule protocol."""
        return self.header.protocol

    @property
    def sid(self) -> int:
        """Get rule SID (Signature ID)."""
        return self.options.sid

    @property
    def msg(self) -> str:
        """Get rule message."""
        return self.options.msg

    @property
    def classtype(self) -> str:
        """Get rule classtype."""
        return self.options.classtype

    def __str__(self) -> str:
        """String representation of the rule."""
        if self.raw:
            return self.raw
        return f"{self.header.action} {self.header.protocol} (sid:{self.sid}; msg:{self.msg})"

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"SuricataRule(action={self.header.action}, "
            f"protocol={self.header.protocol}, "
            f"sid={self.sid}, "
            f"msg={self.msg[:30]}...)"
        )
