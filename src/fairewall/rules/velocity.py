"""Velocity guard: sliding-window rate limiting, per session and per tool.

Catches the failure mode unique to agents: a reasoning loop that retries a
"successful" action forever, or an attacker who has convinced the agent to
issue the same legitimate-looking call a thousand times.

State is only advanced in `commit`, so a call blocked by another rule does not
consume a slot. The naive version of this -- appending the timestamp during the
check -- lets a rejected call throttle the legitimate ones behind it, which is
a self-inflicted denial of service.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from ..policy import Policy, Rule
from ..types import Action, Context, Finding, Severity, ToolCall

WINDOW_SECONDS = 60.0


class VelocityRule(Rule):
    id = "velocity"

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        # (session_id, tool_or_None) -> timestamps within the current window
        self._windows: Dict[Tuple[str, Optional[str]], Deque[float]] = defaultdict(deque)

    def _window(self, key: Tuple[str, Optional[str]], now: float) -> Deque[float]:
        window = self._windows[key]
        cutoff = now - WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        return window

    def evaluate(self, call: ToolCall, ctx: Context, policy: Policy) -> List[Finding]:
        now = self._clock()
        findings: List[Finding] = []

        session_window = self._window((ctx.session_id, None), now)
        if len(session_window) >= policy.max_calls_per_minute:
            findings.append(
                Finding(
                    rule_id="velocity.session_rate",
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    message=(
                        "Session exceeded %d tool calls/minute; agent is exhibiting "
                        "anomalous repeating behavior." % policy.max_calls_per_minute
                    ),
                    evidence={
                        "observed": len(session_window),
                        "limit": policy.max_calls_per_minute,
                        "window_seconds": WINDOW_SECONDS,
                    },
                )
            )

        tool_policy = policy.tool(call.tool)
        if tool_policy and tool_policy.rate_limit_per_minute is not None:
            tool_window = self._window((ctx.session_id, call.tool), now)
            if len(tool_window) >= tool_policy.rate_limit_per_minute:
                findings.append(
                    Finding(
                        rule_id="velocity.tool_rate",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        message=(
                            "Tool %s exceeded %d calls/minute."
                            % (call.tool, tool_policy.rate_limit_per_minute)
                        ),
                        evidence={
                            "tool": call.tool,
                            "observed": len(tool_window),
                            "limit": tool_policy.rate_limit_per_minute,
                        },
                    )
                )
        return findings

    def commit(self, call: ToolCall, ctx: Context, policy: Policy) -> None:
        now = self._clock()
        self._window((ctx.session_id, None), now).append(now)
        self._window((ctx.session_id, call.tool), now).append(now)

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id is None:
            self._windows.clear()
            return
        for key in [k for k in self._windows if k[0] == session_id]:
            del self._windows[key]
