"""
AWS Bedrock Converse Tool-Use Agent Adapter.

Integrates with Amazon Bedrock Converse API for real LLM model execution.
Supports Anthropic Claude, Amazon Nova, and other Bedrock foundation models.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from agents.adapters.base import AgentResponse, BaseAgentAdapter, ToolCallRequest


class BedrockConverseAdapter(BaseAgentAdapter):
    """
    AWS Bedrock adapter using Converse API for live model tool calling.
    """

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ):
        self.model_id = (
            model_id
            or os.environ.get("BEDROCK_MODEL_ID")
            or "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        )
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self.profile = profile or os.environ.get("AWS_PROFILE")

        session = boto3.Session(profile_name=self.profile) if self.profile else boto3.Session()
        self.client = session.client("bedrock-runtime", region_name=self.region)

    def generate(
        self,
        messages: List[Dict[str, Any]],
        tool_schemas: List[Dict[str, Any]],
        system_prompt: str,
        temperature: float = 0.0,
    ) -> AgentResponse:
        # Convert tool schemas into Bedrock Converse toolSpec format
        bedrock_tools = []
        for schema in tool_schemas:
            bedrock_tools.append({
                "toolSpec": {
                    "name": schema.get("name"),
                    "description": schema.get("description", ""),
                    "inputSchema": {
                        "json": schema.get("parameters", {"type": "object", "properties": {}})
                    },
                }
            })

        # Format system prompt
        system_blocks = [{"text": system_prompt}] if system_prompt else []

        # Convert standard message format to Bedrock Converse format
        bedrock_messages = []
        for msg in messages:
            role = msg.get("role", "user")
            content_blocks = []
            raw_content = msg.get("content", "")
            if isinstance(raw_content, str) and raw_content:
                content_blocks.append({"text": raw_content})

            # Check for tool results
            if msg.get("tool_results"):
                for tr in msg["tool_results"]:
                    content_blocks.append({
                        "toolResult": {
                            "toolUseId": tr.get("call_id", ""),
                            "content": [{"json": tr.get("result", {})}],
                            "status": "error" if tr.get("is_error") else "success",
                        }
                    })

            # Check for assistant tool calls
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    content_blocks.append({
                        "toolUse": {
                            "toolUseId": tc.get("call_id", ""),
                            "name": tc.get("tool_name", ""),
                            "input": tc.get("arguments", {}),
                        }
                    })

            if content_blocks:
                bedrock_messages.append({"role": role, "content": content_blocks})

        try:
            converse_kwargs: Dict[str, Any] = {
                "modelId": self.model_id,
                "messages": bedrock_messages,
                "inferenceConfig": {"temperature": temperature, "maxTokens": 1024},
            }
            if system_blocks:
                converse_kwargs["system"] = system_blocks
            if bedrock_tools:
                converse_kwargs["toolConfig"] = {"tools": bedrock_tools}

            response = self.client.converse(**converse_kwargs)
            output = response.get("output", {}).get("message", {})
            usage = response.get("usage", {})

            # Parse content and tool use requests
            text_parts = []
            tool_call_requests = []

            for block in output.get("content", []):
                if "text" in block:
                    text_parts.append(block["text"])
                elif "toolUse" in block:
                    tu = block["toolUse"]
                    tool_call_requests.append(
                        ToolCallRequest(
                            call_id=tu.get("toolUseId", ""),
                            tool_name=tu.get("name", ""),
                            arguments=tu.get("input", {}),
                        )
                    )

            return AgentResponse(
                content="\n".join(text_parts),
                tool_calls=tool_call_requests,
                token_usage={
                    "input_tokens": usage.get("inputTokens", 0),
                    "output_tokens": usage.get("outputTokens", 0),
                    "total_tokens": usage.get("totalTokens", 0),
                },
                model_id=self.model_id,
                provider="aws_bedrock",
                execution_type="live_model",
                raw_response=response,
            )

        except ClientError as exc:
            raise RuntimeError(f"AWS Bedrock Converse API error: {exc}")

    def get_provider_info(self) -> Dict[str, str]:
        return {
            "provider": "AWS Bedrock Converse",
            "model_id": self.model_id,
            "region": self.region,
            "execution_type": "live_model",
        }
