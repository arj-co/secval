"""
SPAG Node Definitions (State-Provenance Authorization Graph).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SPAGNodeType(str, Enum):
    DOCUMENT = "DOCUMENT"
    VALUE = "VALUE"
    AUTHORITATIVE = "AUTHORITATIVE"
    APPROVAL = "APPROVAL"
    POLICY = "POLICY"
    ACTION = "ACTION"


class SPAGEdgeType(str, Enum):
    EXTRACTED_FROM = "EXTRACTED_FROM"
    MATCHES_RECORD = "MATCHES_RECORD"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    AUTHORIZES = "AUTHORIZES"
    GOVERNS = "GOVERNS"
    SUPPLIES_ARGUMENT = "SUPPLIES_ARGUMENT"


@dataclass
class SPAGNode:
    node_id: str
    node_type: SPAGNodeType
    label: str
    trust_level: str  # "trusted" | "user_authorized" | "untrusted" | "derived_untrusted"
    attributes: Dict[str, Any] = field(default_factory=dict)
    is_conflict: bool = False
    conflict_reason: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        return data

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "trust_level": self.trust_level,
            "attributes": self.attributes,
            "is_conflict": self.is_conflict,
            "conflict_reason": self.conflict_reason,
        }


@dataclass
class SPAGEdge:
    source_id: str
    target_id: str
    edge_type: SPAGEdgeType
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "label": self.label,
        }
