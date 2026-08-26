"""
State-Provenance Authorization Graph (SPAG) Engine.

Implements Phase 2:
- Builds an explicit directed acyclic graph connecting documents, extracted values,
  authoritative records, approvals, policies, and actions.
- Propagates trust levels from origin nodes down to proposed tool arguments.
- Detects semantic conflicts between proposed values and master records.
- Evaluates deterministic business invariants.
- Computes canonical SPAG graph hash for execution capability binding.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from security.spag.nodes import SPAGEdge, SPAGEdgeType, SPAGNode, SPAGNodeType


class StateProvenanceAuthorizationGraph:
    """
    State-Provenance Authorization Graph (SPAG).
    Evaluates trust propagation and conflict invariants across the transaction lifecycle.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.nodes: Dict[str, SPAGNode] = {}
        self.edges: List[SPAGEdge] = []
        self.invariants_passed: bool = True
        self.conflict_reasons: List[str] = []

    def add_document_node(
        self,
        doc_id: str,
        label: str,
        trust_level: str,
        content_hash: str,
        doc_type: str = "invoice",
    ) -> SPAGNode:
        node = SPAGNode(
            node_id=f"doc_{doc_id}",
            node_type=SPAGNodeType.DOCUMENT,
            label=label,
            trust_level=trust_level,
            attributes={"doc_id": doc_id, "doc_type": doc_type, "content_hash": content_hash},
        )
        self.nodes[node.node_id] = node
        return node

    def add_authoritative_node(
        self,
        record_id: str,
        label: str,
        attributes: Dict[str, Any],
    ) -> SPAGNode:
        node = SPAGNode(
            node_id=f"auth_{record_id}",
            node_type=SPAGNodeType.AUTHORITATIVE,
            label=label,
            trust_level="trusted",
            attributes=attributes,
        )
        self.nodes[node.node_id] = node
        return node

    def add_value_node(
        self,
        value_name: str,
        value: Any,
        originating_doc_id: Optional[str] = None,
        authoritative_record_id: Optional[str] = None,
    ) -> SPAGNode:
        node_id = f"val_{value_name}_{str(value)[:12]}"
        node = SPAGNode(
            node_id=node_id,
            node_type=SPAGNodeType.VALUE,
            label=f"{value_name}: {value}",
            trust_level="trusted",
            attributes={"name": value_name, "value": value},
        )
        self.nodes[node_id] = node

        if originating_doc_id:
            doc_node_id = f"doc_{originating_doc_id}"
            if doc_node_id in self.nodes:
                self.edges.append(
                    SPAGEdge(
                        source_id=node_id,
                        target_id=doc_node_id,
                        edge_type=SPAGEdgeType.EXTRACTED_FROM,
                        label="Extracted From",
                    )
                )

        if authoritative_record_id:
            auth_node_id = f"auth_{authoritative_record_id}"
            if auth_node_id in self.nodes:
                self.edges.append(
                    SPAGEdge(
                        source_id=node_id,
                        target_id=auth_node_id,
                        edge_type=SPAGEdgeType.MATCHES_RECORD,
                        label="Matches Server Record",
                    )
                )

        return node

    def add_approval_node(
        self,
        approval_id: str,
        approver: str,
        approved_amount: float,
        is_valid: bool,
    ) -> SPAGNode:
        node = SPAGNode(
            node_id=f"app_{approval_id}",
            node_type=SPAGNodeType.APPROVAL,
            label=f"Approval {approval_id}",
            trust_level="trusted" if is_valid else "untrusted",
            attributes={"approval_id": approval_id, "approver": approver, "amount": approved_amount, "valid": is_valid},
        )
        self.nodes[node.node_id] = node
        return node

    def add_action_node(
        self,
        action_name: str,
        arguments: Dict[str, Any],
    ) -> SPAGNode:
        node = SPAGNode(
            node_id=f"action_{action_name}",
            node_type=SPAGNodeType.ACTION,
            label=f"Action: {action_name}",
            trust_level="user_authorized",
            attributes={"action": action_name, "arguments": arguments},
        )
        self.nodes[node.node_id] = node
        return node

    def evaluate_and_propagate(
        self,
        proposed_account: str,
        trusted_registered_account: str,
        proposed_amount: float,
        po_limit: float,
        action_name: str,
        approval_valid: bool = False,
    ) -> Tuple[bool, List[str]]:
        """
        Propagate trust across graph edges and evaluate invariants:
        1. Account match invariant
        2. Amount limits & approval invariant
        3. Untrusted origin taint propagation
        """
        conflicts = []

        # 1. Account matching invariant
        if proposed_account and trusted_registered_account:
            if proposed_account.strip().lower() != trusted_registered_account.strip().lower():
                conflicts.append(
                    f"SPAG_CONFLICT_ACCOUNT: Proposed account '{proposed_account}' does not match registered master account '{trusted_registered_account}'."
                )
                val_node_id = next((nid for nid, n in self.nodes.items() if n.node_type == SPAGNodeType.VALUE and n.attributes.get("name") == "account"), None)
                if val_node_id:
                    self.nodes[val_node_id].is_conflict = True
                    self.nodes[val_node_id].trust_level = "derived_untrusted"
                    self.nodes[val_node_id].conflict_reason = "Mismatches master vendor registry account."

        # 2. Limit & Approval invariant
        if proposed_amount > 50000.0 and not approval_valid:
            conflicts.append(
                f"SPAG_CONFLICT_APPROVAL_REQUIRED: Amount ₹{proposed_amount:,.2f} exceeds threshold ₹50,000 without verified approval."
            )

        if po_limit > 0 and proposed_amount > po_limit:
            conflicts.append(
                f"SPAG_CONFLICT_PO_EXCEEDED: Amount ₹{proposed_amount:,.2f} exceeds approved PO limit ₹{po_limit:,.2f}."
            )

        # 3. Propagate untrusted document taint
        for node in self.nodes.values():
            if node.node_type == SPAGNodeType.VALUE:
                # If extracted from an untrusted document and not matching authoritative record
                extracted_edges = [e for e in self.edges if e.source_id == node.node_id and e.edge_type == SPAGEdgeType.EXTRACTED_FROM]
                matches_edges = [e for e in self.edges if e.source_id == node.node_id and e.edge_type == SPAGEdgeType.MATCHES_RECORD]

                for e in extracted_edges:
                    doc_node = self.nodes.get(e.target_id)
                    if doc_node and doc_node.trust_level in ("untrusted", "derived_untrusted") and not matches_edges:
                        node.trust_level = "derived_untrusted"
                        node.is_conflict = True
                        node.conflict_reason = f"Originated in untrusted document '{doc_node.label}'"
                        if f"SPAG_UNTRUSTED_TAINT: {node.label}" not in conflicts:
                            conflicts.append(f"SPAG_UNTRUSTED_TAINT: Value '{node.label}' originates from untrusted source.")

        self.invariants_passed = len(conflicts) == 0
        self.conflict_reasons = conflicts
        return self.invariants_passed, conflicts

    def compute_canonical_hash(self) -> str:
        """Compute deterministic SHA-256 digest of the entire graph structure."""
        graph_dict = {
            "session_id": self.session_id,
            "nodes": sorted([n.to_canonical_dict() for n in self.nodes.values()], key=lambda x: x["node_id"]),
            "edges": sorted([e.to_dict() for e in self.edges], key=lambda x: (x["source_id"], x["target_id"])),
            "invariants_passed": self.invariants_passed,
        }
        canonical_json = json.dumps(graph_dict, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "canonical_hash": self.compute_canonical_hash(),
            "invariants_passed": self.invariants_passed,
            "conflict_reasons": self.conflict_reasons,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
