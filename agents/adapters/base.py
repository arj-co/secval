"""
Base Interface for Model-in-the-Loop Agent Adapters.

Defines typed interfaces for LLM providers (AWS Bedrock Converse, OpenAI, Deterministic Test Harness).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolCallRequest:
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentResponse:
    content: str
    tool_calls: List[ToolCallRequest] = field(default_factory=list)
    token_usage: Dict[str, int] = field(default_factory=dict)
    model_id: str = "unknown"
    provider: str = "unknown"
    execution_type: str = "deterministic_simulation"  # "live_model" | "deterministic_simulation"
    raw_response: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "token_usage": self.token_usage,
            "model_id": self.model_id,
            "provider": self.provider,
            "execution_type": self.execution_type,
        }


class BaseAgentAdapter(ABC):
    """Abstract agent adapter interface."""

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, Any]],
        tool_schemas: List[Dict[str, Any]],
        system_prompt: str,
        temperature: float = 0.0,
    ) -> AgentResponse:
        """Generate response and model-selected tool calls."""
        pass

    @abstractmethod
    def get_provider_info(self) -> Dict[str, str]:
        """Return provider and model metadata."""
        pass
