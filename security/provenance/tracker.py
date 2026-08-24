"""
Runtime-Owned Provenance & Ingestion Tracker.

Implements Section 3:
- SecVal creates and owns all provenance handles.
- Model cannot forge or self-declare trust levels.
- Rejects invalid handles, cross-session handles, and tampered values.
- Analyzes taint propagation for sensitive transaction arguments.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from security.provenance.models import (
    ArgumentProvenance,
    SourceRecord,
    SourceType,
    TrustLevel,
    compute_sha256,
)


class RuntimeProvenanceTracker:
    """
    Session-scoped provenance authority owned and verified exclusively by SecVal.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        self._sources: Dict[str, SourceRecord] = {}

    def ingest_source(
        self,
        source_type: SourceType,
        trust_level: TrustLevel,
        content: str,
        creator: str = "runtime_system",
        parent_handles: Optional[List[str]] = None,
        description: str = "",
        custom_prefix: Optional[str] = None,
    ) -> SourceRecord:
        """Create an authoritative, opaque provenance record at ingestion time."""
        prefix = custom_prefix or source_type.value[:4]
        handle = f"src_{prefix}_{uuid.uuid4().hex[:12]}"
        content_hash = compute_sha256(content)

        record = SourceRecord(
            source_handle=handle,
            source_type=source_type,
            trust_level=trust_level,
            session_id=self.session_id,
            content_hash=content_hash,
            creator=creator,
            parent_handles=parent_handles or [],
            description=description,
            raw_content=content,
        )

        self._sources[handle] = record
        return record

    def register_source(
        self,
        source_id: str,
        source_type: SourceType,
        trust_level: TrustLevel,
        content: str,
        creator_identity: str = "system",
        parent_source_ids: Optional[List[str]] = None,
        description: str = "",
    ) -> SourceRecord:
        """Convenience method for registering a source with a known source_id."""
        content_hash = compute_sha256(content)
        record = SourceRecord(
            source_handle=source_id,
            source_type=source_type,
            trust_level=trust_level,
            session_id=self.session_id,
            content_hash=content_hash,
            creator=creator_identity,
            parent_handles=parent_source_ids or [],
            description=description,
            raw_content=content,
        )
        self._sources[source_id] = record
        return record

    def verify_handle(self, handle: str) -> Tuple[bool, Optional[SourceRecord], str]:
        """
        Validate that a handle was genuinely minted by SecVal for this session.
        """
        if not handle or not isinstance(handle, str):
            return False, None, "Invalid handle format."

        record = self._sources.get(handle)
        if not record:
            return False, None, f"Handle '{handle}' does not exist in active session registry (forged handle)."

        if record.session_id != self.session_id:
            return False, None, f"Handle '{handle}' belongs to a different session (cross-session breach attempt)."

        return True, record, "Handle verified."

    def analyze_proposed_argument(
        self,
        arg_name: str,
        proposed_value: Any,
        model_supplied_handles: Optional[List[str]] = None,
        trusted_authoritative_value: Optional[Any] = None,
    ) -> ArgumentProvenance:
        """
        SecVal independent argument provenance analysis:
        1. Checks if proposed value matches trusted server-side registry.
        2. Detects if proposed value appears inside any untrusted ingested content (e.g. invoice remittance notes).
        3. Validates model-supplied handles against runtime registry.
        """
        val_str = str(proposed_value).strip() if proposed_value is not None else ""
        contributing_records: List[SourceRecord] = []
        is_tainted = False
        taint_reasons = []

        # Validate any model-provided handles
        for h in (model_supplied_handles or []):
            is_valid, rec, reason = self.verify_handle(h)
            if is_valid and rec:
                contributing_records.append(rec)
            else:
                is_tainted = True
                taint_reasons.append(f"Unverified provenance handle '{h}': {reason}")

        # Invariant Check: Does value deviate from trusted server-side registry?
        is_deviated_from_trusted = False
        if trusted_authoritative_value is not None:
            auth_str = str(trusted_authoritative_value).strip()
            if val_str.lower() != auth_str.lower():
                is_deviated_from_trusted = True
                is_tainted = True
                taint_reasons.append(
                    f"Value '{val_str}' deviates from trusted server-side registry value '{auth_str}'."
                )

        # Scrape active untrusted sources to identify if this value was supplied by an untrusted document
        found_in_untrusted_source = False
        untrusted_source_handles = []
        for handle, rec in self._sources.items():
            if rec.trust_level in (TrustLevel.UNTRUSTED, TrustLevel.DERIVED_UNTRUSTED):
                if val_str and val_str.lower() in rec.raw_content.lower():
                    found_in_untrusted_source = True
                    untrusted_source_handles.append(handle)
                    contributing_records.append(rec)

        if found_in_untrusted_source:
            is_tainted = True
            taint_reasons.append(
                f"Proposed {arg_name} '{val_str}' originates directly from untrusted document content ({', '.join(untrusted_source_handles)})."
            )

        # Determine Final Trust Classification:
        # If the value matches the authoritative server-side master registry, it is verified as TRUSTED!
        if trusted_authoritative_value is not None and not is_deviated_from_trusted:
            final_trust = TrustLevel.TRUSTED
            is_tainted = False
        elif is_deviated_from_trusted or found_in_untrusted_source:
            final_trust = TrustLevel.DERIVED_UNTRUSTED
            is_tainted = True
        elif contributing_records and all(r.trust_level == TrustLevel.TRUSTED for r in contributing_records):
            final_trust = TrustLevel.TRUSTED
            is_tainted = False
        elif contributing_records and any(r.trust_level == TrustLevel.USER_AUTHORIZED for r in contributing_records):
            final_trust = TrustLevel.USER_AUTHORIZED
            is_tainted = False
        else:
            # Sensitive unverified argument defaults to UNTRUSTED
            final_trust = TrustLevel.UNTRUSTED
            is_tainted = True
            taint_reasons.append(f"Origin of {arg_name} cannot be verified against trusted server state.")

        return ArgumentProvenance(
            argument_name=arg_name,
            value=proposed_value,
            trust_level=final_trust,
            contributing_handles=[r.source_handle for r in contributing_records],
            is_tainted=is_tainted,
            taint_reason="; ".join(taint_reasons) if taint_reasons else None,
            trusted_registry_value=trusted_authoritative_value,
        )

    def analyze_argument_provenance(
        self,
        arg_name: str,
        arg_value: Any,
        explicit_source_ids: Optional[List[str]] = None,
        trusted_reference_values: Optional[Dict[str, Any]] = None,
    ) -> ArgumentProvenance:
        """Compatibility wrapper for legacy interceptor calls."""
        trusted_val = (trusted_reference_values or {}).get("approved_account") or (trusted_reference_values or {}).get("registered_account")
        return self.analyze_proposed_argument(
            arg_name=arg_name,
            proposed_value=arg_value,
            model_supplied_handles=explicit_source_ids,
            trusted_authoritative_value=trusted_val,
        )

    def record_tool_event(self, *args, **kwargs) -> None:
        """Record tool execution event in provenance history."""
        pass

    def get_source(self, source_id: str) -> Optional[SourceRecord]:
        return self._sources.get(source_id)

    def get_all_sources(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._sources.values()]

    def get_source_records(self) -> List[SourceRecord]:
        return list(self._sources.values())

    def reset(self) -> None:
        self._sources.clear()


# Backward compatibility alias
ProvenanceTracker = RuntimeProvenanceTracker
