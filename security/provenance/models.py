"""
Instruction & Argument Provenance Data Model.

Implements ADR-004 and Section 3:
- Opaque, immutable runtime-assigned source handles.
- Trust classifications assigned strictly by SecVal (never by the agent).
- Session binding and tamper-evident content hashing.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SourceType(str, Enum):
    USER_TASK = "user_task"
    EMAIL = "email"
    INVOICE = "invoice"
    DOCUMENT = "document"
    PURCHASE_ORDER = "purchase_order"
    VENDOR_REGISTRY = "vendor_registry"
    HUMAN_APPROVAL = "human_approval"
    SYSTEM = "system"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    USER_AUTHORIZED = "user_authorized"
    UNTRUSTED = "untrusted"
    DERIVED_UNTRUSTED = "derived_untrusted"


@dataclass
class SourceRecord:
    source_handle: str
    source_type: SourceType
    trust_level: TrustLevel
    session_id: str
    content_hash: str
    creator: str
    timestamp: float = field(default_factory=time.time)
    parent_handles: List[str] = field(default_factory=list)
    description: str = ""
    raw_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["source_type"] = self.source_type.value
        data["trust_level"] = self.trust_level.value
        # Exclude massive raw content from light serialization if needed
        return data


@dataclass
class ArgumentProvenance:
    argument_name: str
    value: Any
    trust_level: TrustLevel
    contributing_handles: List[str] = field(default_factory=list)
    is_tainted: bool = False
    taint_reason: Optional[str] = None
    trusted_registry_value: Optional[Any] = None

    @property
    def inferred_trust_level(self) -> TrustLevel:
        return self.trust_level

    @property
    def tainted(self) -> bool:
        return self.is_tainted

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["trust_level"] = self.trust_level.value
        return data


def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
