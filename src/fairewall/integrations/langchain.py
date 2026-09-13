"""fAIrewall integration for LangChain."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ..firewall import Firewall
from ..types import Action, Context, FirewallBlock, Principal, Trust


class FairewallCallbackHandler:
    """LangChain callback handler that inspects inputs and tool calls.

    State commitment
    ----------------
    When ``commit=True`` (default), ``on_tool_start()`` calls ``firewall.commit()``
    for every allowed tool call so that ``max_spend_per_session`` and per-session
    rate limits accumulate correctly.  Pass ``commit=False`` for dry-run / shadow
    mode observation without mutating any state.

    Taint propagation
    -----------------
    ``on_tool_end()`` respects the ``produces_untrusted_output`` flag declared in
    the tool's ``ToolPolicy``.  Only outputs from tools that have
    ``produces_untrusted_output=True`` taint the session; all other outputs are
    still screened for injection signatures, but they do **not** unconditionally
    mark the session untrusted.  This matches the declarative opt-in model used
    throughout the library and prevents ``forbid_when_tainted`` tools from being
    silently blocked after the very first benign tool call.
    """

    def __init__(
        self,
        firewall: Firewall,
        session_id: Optional[str] = None,
        principal: Optional[Principal] = None,
        raise_on_block: bool = True,
        commit: bool = True,
    ) -> None:
        self.firewall = firewall
        self.session_id = session_id or "langchain_session"
        self.principal = principal or Principal()
        self.raise_on_block = raise_on_block
        self.commit = commit
        self._ctx = self.firewall.session(self.session_id, self.principal)
        # Tracks the tool name active during on_tool_start so on_tool_end
        # can look up the corresponding ToolPolicy.
        self._active_tool: Optional[str] = None

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
        self._active_tool = tool_name

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
            self._active_tool = None
            if self.raise_on_block:
                raise FirewallBlock(decision)
            raise ValueError(f"SECURITY BLOCK: {decision.reason}")

        if self.commit:
            self.firewall.commit(tool=tool_name, arguments=inputs, ctx=self._ctx)

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Conditionally taint context with tool outputs based on policy.

        Only taints the session if the tool's ``ToolPolicy`` has
        ``produces_untrusted_output=True``.  All outputs are still screened for
        prompt-injection signatures regardless of this flag.
        """
        tool_name = self._active_tool
        self._active_tool = None

        if not isinstance(output, str):
            return

        # Determine trust level from the policy for this tool.
        tool_policy = self.firewall.policy.tool(tool_name) if tool_name else None
        produces_untrusted = (
            tool_policy is not None
            and getattr(tool_policy, "produces_untrusted_output", False)
        )

        trust = Trust.UNTRUSTED if produces_untrusted else Trust.USER
        self.firewall.inspect_input(
            text=output,
            trust=trust,
            ctx=self._ctx,
            source="langchain_tool_output",
        )
