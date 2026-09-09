"""fAIrewall integration for LangChain."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ..firewall import Firewall
from ..types import Action, Context, FirewallBlock, Principal, Trust


class FairewallCallbackHandler:
    """LangChain callback handler that inspects inputs and tool calls."""

    def __init__(
        self,
        firewall: Firewall,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        raise_on_block: bool = True,
    ) -> None:
        self.firewall = firewall
        self.session_id = session_id or "langchain_session"
        self.principal = principal or Principal()
        self.raise_on_block = raise_on_block
        self._ctx = self.firewall.session(self.session_id, self.principal)

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        **kwargs: Any,
    ) -> None:
        """Inspect inbound prompt messages before they reach the model."""
        for message_list in messages:
            for msg in message_list:
                content = getattr(msg, "content", "")
                if isinstance(content, str) and content:
                    msg_type = getattr(msg, "type", "user")
                    trust = Trust.UNTRUSTED if msg_type in ("tool", "function") else Trust.USER
                    decision = self.firewall.inspect_input(
                        text=content,
                        trust=trust,
                        ctx=self._ctx,
                        source=f"langchain_{msg_type}",
                    )
                    if decision.blocked and self.raise_on_block:
                        raise FirewallBlock(decision)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Inspect tool invocation before it executes."""
        tool_name = serialized.get("name", kwargs.get("name", "unknown_tool"))
        # Parse inputs if passed as dict or string
        inputs: Dict[str, Any]
        if isinstance(input_str, dict):
            inputs = input_str
        elif isinstance(input_str, str):
            import json
            try:
                inputs = json.loads(input_str)
                if not isinstance(inputs, dict):
                    inputs = {"input": input_str}
            except Exception:
                inputs = {"input": input_str}
        else:
            inputs = {"input": input_str}

        decision = self.firewall.inspect(tool=tool_name, arguments=inputs, ctx=self._ctx)
        if decision.blocked:
            if self.raise_on_block:
                raise FirewallBlock(decision)
            raise ValueError(f"SECURITY BLOCK: {decision.reason}")

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Taint context with tool outputs if they contain raw data."""
        if isinstance(output, str):
            # Taint context with tool output
            self.firewall.inspect_input(
                text=output,
                trust=Trust.UNTRUSTED,
                ctx=self._ctx,
                source="langchain_tool_output",
            )
