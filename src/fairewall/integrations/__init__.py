"""Agent framework and enterprise platform integrations for fAIrewall SDK.

Available integrations
----------------------
- **OpenAI** — ``guard_openai_tool_calls``, ``execute_openai_tool_calls``
- **LangChain** — ``FairewallCallbackHandler``
- **Zapier Agents** — ``ZapierWebhookAdapter``, ``guard_zapier_action``
- **Microsoft Copilot Studio** — ``CopilotAdapter``, ``guard_copilot_action``
- **Salesforce Agentforce** — ``AgentforceAdapter``, ``guard_agentforce_action``
- **Haptik / WhatsApp** — ``HaptikAdapter``, ``guard_whatsapp_message``,
  ``guard_haptik_message``
- **UiPath Platform** — ``UiPathAdapter``, ``guard_uipath_action``,
  ``screen_uipath_document``
"""

from __future__ import annotations

from .langchain import FairewallCallbackHandler
from .openai import execute_openai_tool_calls, guard_openai_tool_calls

# Platform integrations (imported lazily to avoid hard FastAPI dep at import time)

def _lazy(module: str, name: str):  # type: ignore[return]
    def _getter(*args, **kwargs):  # type: ignore[return]
        import importlib
        mod = importlib.import_module(module, package=__name__)
        return getattr(mod, name)
    _getter.__name__ = name
    return _getter


__all__ = [
    # Existing
    "FairewallCallbackHandler",
    "guard_openai_tool_calls",
    "execute_openai_tool_calls",
    # Zapier
    "ZapierWebhookAdapter",
    "guard_zapier_action",
    # Copilot
    "CopilotAdapter",
    "guard_copilot_action",
    # Salesforce
    "AgentforceAdapter",
    "guard_agentforce_action",
    # Haptik / WhatsApp
    "HaptikAdapter",
    "guard_whatsapp_message",
    "guard_haptik_message",
    # UiPath
    "UiPathAdapter",
    "guard_uipath_action",
    "screen_uipath_document",
]

# Deferred imports so that missing optional extras give a clear error at
# *use* time rather than at package import time.

def __getattr__(name: str):  # noqa: D401
    _map = {
        "ZapierWebhookAdapter": (".zapier", "ZapierWebhookAdapter"),
        "guard_zapier_action": (".zapier", "guard_zapier_action"),
        "CopilotAdapter": (".copilot", "CopilotAdapter"),
        "guard_copilot_action": (".copilot", "guard_copilot_action"),
        "AgentforceAdapter": (".salesforce", "AgentforceAdapter"),
        "guard_agentforce_action": (".salesforce", "guard_agentforce_action"),
        "HaptikAdapter": (".haptik", "HaptikAdapter"),
        "guard_whatsapp_message": (".haptik", "guard_whatsapp_message"),
        "guard_haptik_message": (".haptik", "guard_haptik_message"),
        "UiPathAdapter": (".uipath", "UiPathAdapter"),
        "guard_uipath_action": (".uipath", "guard_uipath_action"),
        "screen_uipath_document": (".uipath", "screen_uipath_document"),
    }
    if name in _map:
        import importlib
        module_path, attr = _map[name]
        mod = importlib.import_module(module_path, package=__package__)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
