"""
Unit Tests for State-Provenance Authorization Graph (SPAG).

Tests:
1. DAG Construction and Node/Edge relationships.
2. Trust propagation from untrusted document nodes to proposed values.
3. Conflict detection against master vendor registry.
4. Threshold and approval invariant checking.
5. Canonical graph hash determinism.
"""

from __future__ import annotations

import pytest
from security.spag.graph import StateProvenanceAuthorizationGraph
from security.spag.nodes import SPAGNodeType


class TestSPAGGraph:

    def test_spag_detects_account_conflict_with_master_registry(self):
        graph = StateProvenanceAuthorizationGraph(session_id="test_session_001")

        # Ingest document
        graph.add_document_node(
            doc_id="inv-attack",
            label="Attacker Injected Invoice",
            trust_level="untrusted",
            content_hash="abc123hash",
        )

        # Ingest authoritative registry
        graph.add_authoritative_node(
            record_id="V001",
            label="ACME Master Record",
            attributes={"approved_account": "ACC-ACME-8841"},
        )

        # Add proposed value
        graph.add_value_node(
            value_name="account",
            value="ACC-ATTACKER-6666",
            originating_doc_id="inv-attack",
            authoritative_record_id=None,
        )

        passed, conflicts = graph.evaluate_and_propagate(
            proposed_account="ACC-ATTACKER-6666",
            trusted_registered_account="ACC-ACME-8841",
            proposed_amount=42000.0,
            po_limit=42000.0,
            action_name="prepare_payment",
            approval_valid=False,
        )

        assert passed is False
        assert any("SPAG_CONFLICT_ACCOUNT" in c for c in conflicts)
        val_node = next(n for n in graph.nodes.values() if n.node_type == SPAGNodeType.VALUE and n.attributes.get("name") == "account")
        assert val_node.is_conflict is True
        assert val_node.trust_level == "derived_untrusted"

    def test_spag_verifies_legitimate_matching_account(self):
        graph = StateProvenanceAuthorizationGraph(session_id="test_session_002")

        graph.add_document_node(
            doc_id="inv-benign",
            label="Legitimate ACME Invoice",
            trust_level="untrusted",
            content_hash="def456hash",
        )

        graph.add_authoritative_node(
            record_id="V001",
            label="ACME Master Record",
            attributes={"approved_account": "ACC-ACME-8841"},
        )

        graph.add_value_node(
            value_name="account",
            value="ACC-ACME-8841",
            originating_doc_id="inv-benign",
            authoritative_record_id="V001",
        )

        passed, conflicts = graph.evaluate_and_propagate(
            proposed_account="ACC-ACME-8841",
            trusted_registered_account="ACC-ACME-8841",
            proposed_amount=42000.0,
            po_limit=42000.0,
            action_name="prepare_payment",
            approval_valid=False,
        )

        assert passed is True
        assert len(conflicts) == 0

    def test_spag_canonical_hash_is_deterministic(self):
        g1 = StateProvenanceAuthorizationGraph(session_id="sess_det")
        g1.add_document_node("doc1", "Doc 1", "untrusted", "hash1")
        g1.add_value_node("account", "ACC-123")

        g2 = StateProvenanceAuthorizationGraph(session_id="sess_det")
        g2.add_document_node("doc1", "Doc 1", "untrusted", "hash1")
        g2.add_value_node("account", "ACC-123")

        assert g1.compute_canonical_hash() == g2.compute_canonical_hash()
