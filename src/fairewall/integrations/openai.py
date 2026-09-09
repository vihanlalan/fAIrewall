"""fAIrewall integration for OpenAI Python SDK."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..firewall import Firewall
from ..types import Context, Decision, FirewallBlock, Principal


def guard_openai_tool_calls(
    tool_calls: List[Any],
    firewall: Firewall,
    ctx: Optional[Context] = None,
    session_id: Optional[str] = None,
    principal: Optional[Principal] = None,
    raise_on_block: bool = False,
) -> List[Tuple[Any, Decision]]:
    """Inspect a list of OpenAI tool_calls from a chat completion message.

    Returns a list of (tool_call, decision) tuples.
    If raise_on_block is True, raises FirewallBlock on the first blocked tool call.
    """
    ctx = ctx or firewall.session(session_id, principal)
    results: List[Tuple[Any, Decision]] = []

    for tc in tool_calls:
        # Compatible with both openai.types.chat.ChatCompletionMessageToolCall and plain dicts
        if hasattr(tc, "function"):
            tool_name = getattr(tc.function, "name", "")
            raw_args = getattr(tc.function, "arguments", "{}")
        elif isinstance(tc, dict):
            fn = tc.get("function", {})
            tool_name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
        else:
            tool_name = getattr(tc, "name", "")
            raw_args = getattr(tc, "arguments", "{}")

        try:
            arguments = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
        except Exception:
            arguments = {"raw": raw_args}

        decision = firewall.inspect(tool_name, arguments, ctx=ctx)
        if decision.blocked and raise_on_block:
            raise FirewallBlock(decision)

        results.append((tc, decision))

    return results


def execute_openai_tool_calls(
    tool_calls: List[Any],
    tool_map: Dict[str, Callable[..., Any]],
    firewall: Firewall,
    ctx: Optional[Context] = None,
    session_id: Optional[str] = None,
    principal: Optional[Principal] = None,
) -> List[Dict[str, Any]]:
    """Inspect and safely execute tool calls, returning tool role messages for the chat history.

    Blocked calls safely return a synthetic error message to the LLM so it can recover,
    without crashing the conversation.
    """
    ctx = ctx or firewall.session(session_id, principal)
    tool_messages: List[Dict[str, Any]] = []

    for tc in tool_calls:
        tc_id = getattr(tc, "id", None) or (tc.get("id") if isinstance(tc, dict) else "")
        if hasattr(tc, "function"):
            tool_name = getattr(tc.function, "name", "")
            raw_args = getattr(tc.function, "arguments", "{}")
        elif isinstance(tc, dict):
            fn = tc.get("function", {})
            tool_name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
        else:
            tool_name = getattr(tc, "name", "")
            raw_args = getattr(tc, "arguments", "{}")

        try:
            arguments = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
        except Exception:
            arguments = {"raw": raw_args}

        fn = tool_map.get(tool_name)
        if fn is None:
            tool_messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": f"Error: Tool '{tool_name}' not found in registry.",
            })
            continue

        result = firewall.execute(
            tool=tool_name,
            fn=fn,
            arguments=arguments,
            ctx=ctx,
            raise_on_block=False,
        )

        tool_messages.append({
            "role": "tool",
            "tool_call_id": tc_id,
            "content": str(result),
        })

    return tool_messages
