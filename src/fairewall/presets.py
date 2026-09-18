"""Platform-specific policy presets for the fAIrewall SDK.

Each preset is a ready-to-use Policy tuned for a particular enterprise
automation platform's risk profile. Customers can use them as-is or as a
starting point for fine-grained customisation:

    from fairewall.presets import load_preset
    policy = load_preset("ZAPIER_SME")
    fw = Firewall(policy)

The presets are deliberately conservative: they fail safe.  Loosen the
limits only after you have observed your traffic in shadow mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from .policy import Policy, ToolPolicy

# ---------------------------------------------------------------------------
# Preset registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, "PolicyPreset"] = {}


@dataclass
class PolicyPreset:
    """A named, documented policy ready for a specific platform."""

    name: str
    description: str
    platform: str
    policy: Policy

    def __post_init__(self) -> None:
        _REGISTRY[self.name] = self


def load_preset(name: str) -> Policy:
    """Return the Policy for a named preset.

    Args:
        name: One of ``ZAPIER_SME``, ``COPILOT_ENTERPRISE``,
              ``SALESFORCE_CRM``, ``WHATSAPP_BOT``, ``UIPATH_RPA``.

    Raises:
        ValueError: If the name is not a known preset.
    """
    preset = _REGISTRY.get(name)
    if preset is None:
        available = sorted(_REGISTRY)
        raise ValueError(
            f"Unknown preset {name!r}. Available presets: {available}"
        )
    return preset.policy


def list_presets() -> Dict[str, str]:
    """Return a mapping of preset name → description."""
    return {name: p.description for name, p in sorted(_REGISTRY.items())}


# ---------------------------------------------------------------------------
# 1. Zapier SME  —  low-code, cross-platform SME automation
# ---------------------------------------------------------------------------

ZAPIER_SME = PolicyPreset(
    name="ZAPIER_SME",
    platform="Zapier Agents",
    description=(
        "Conservative policy for Zapier Agent workflows used by small and "
        "medium businesses. Limits financial transactions to $200 per call "
        "and $1,000 per session, caps velocity at 30 actions/minute, and "
        "restricts egress to *.zapier.com and *.zapierusercontent.com. "
        "All unknown tools are treated as high-risk."
    ),
    policy=Policy(
        version="zapier-sme-1",
        default_deny=False,
        max_spend_per_transaction=200.0,
        max_spend_per_session=1_000.0,
        max_calls_per_minute=30,
        allowed_egress_domains=["zapier.com", "zapierusercontent.com", "hooks.zapier.com"],
        unknown_tool_risk="high",
        detector_flag_threshold=0.45,
        detector_block_threshold=0.80,
        tools={
            # Zapier's built-in trigger/action primitives
            "zapier_trigger": ToolPolicy(
                name="zapier_trigger",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "zapier_action": ToolPolicy(
                name="zapier_action",
                risk_tier="high",
                forbid_when_tainted=True,
                max_values={"amount": 200.0, "value": 200.0},
            ),
            "send_email": ToolPolicy(
                name="send_email",
                risk_tier="high",
                forbid_when_tainted=True,
            ),
            "http_request": ToolPolicy(
                name="http_request",
                risk_tier="high",
                forbid_when_tainted=True,
                produces_untrusted_output=True,
            ),
            "create_record": ToolPolicy(
                name="create_record",
                risk_tier="high",
                forbid_when_tainted=True,
            ),
            "update_record": ToolPolicy(
                name="update_record",
                risk_tier="high",
                forbid_when_tainted=True,
                max_values={"amount": 200.0, "total": 200.0},
            ),
        },
    ),
)


# ---------------------------------------------------------------------------
# 2. Copilot Enterprise  —  Microsoft 365 ecosystem
# ---------------------------------------------------------------------------

COPILOT_ENTERPRISE = PolicyPreset(
    name="COPILOT_ENTERPRISE",
    platform="Microsoft Copilot Studio",
    description=(
        "Policy for Microsoft Copilot Studio bots embedded in Microsoft 365. "
        "Restricts egress to Microsoft and SharePoint domains, requires "
        "human approval for document-write and mail-send actions, enforces "
        "strict schema allowlists, and blocks all tools when session is "
        "tainted by external data fetches."
    ),
    policy=Policy(
        version="copilot-enterprise-1",
        default_deny=True,
        max_spend_per_transaction=500.0,
        max_spend_per_session=2_000.0,
        max_calls_per_minute=60,
        allowed_egress_domains=[
            "microsoft.com",
            "microsoftonline.com",
            "sharepoint.com",
            "graph.microsoft.com",
            "office.com",
            "teams.microsoft.com",
            "outlook.office365.com",
        ],
        unknown_tool_risk="high",
        detector_flag_threshold=0.4,
        detector_block_threshold=0.75,
        tools={
            # Read operations — lower risk
            "get_document": ToolPolicy(
                name="get_document",
                risk_tier="low",
                produces_untrusted_output=True,
                required_args=["document_id"],
            ),
            "search_sharepoint": ToolPolicy(
                name="search_sharepoint",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "get_email": ToolPolicy(
                name="get_email",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "get_calendar": ToolPolicy(
                name="get_calendar",
                risk_tier="low",
            ),
            # Write operations — require human approval and no-taint
            "create_document": ToolPolicy(
                name="create_document",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["title", "content"],
            ),
            "update_document": ToolPolicy(
                name="update_document",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["document_id"],
            ),
            "send_email": ToolPolicy(
                name="send_email",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["to", "subject", "body"],
                allowed_args=["to", "cc", "bcc", "subject", "body", "attachments"],
            ),
            "create_meeting": ToolPolicy(
                name="create_meeting",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
            ),
            "power_automate_flow": ToolPolicy(
                name="power_automate_flow",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
            ),
        },
    ),
)


# ---------------------------------------------------------------------------
# 3. Salesforce CRM  —  Sales and service CRM pipeline
# ---------------------------------------------------------------------------

SALESFORCE_CRM = PolicyPreset(
    name="SALESFORCE_CRM",
    platform="Salesforce Agentforce",
    description=(
        "Policy for Salesforce Agentforce deployed on sales/service teams. "
        "Guards financial CRM operations (Opportunity amounts, Quote totals) "
        "with per-transaction and session spend limits. Taints sessions that "
        "read external lead/contact data, and blocks all write tools while "
        "tainted. Restricts egress to Salesforce domains."
    ),
    policy=Policy(
        version="salesforce-crm-1",
        default_deny=False,
        max_spend_per_transaction=10_000.0,
        max_spend_per_session=50_000.0,
        max_calls_per_minute=60,
        spend_arg_names=["amount", "total", "value", "price", "discount", "refund"],
        allowed_egress_domains=[
            "salesforce.com",
            "force.com",
            "my.salesforce.com",
            "lightning.force.com",
        ],
        unknown_tool_risk="high",
        detector_flag_threshold=0.45,
        detector_block_threshold=0.80,
        tools={
            # Read operations
            "get_opportunity": ToolPolicy(
                name="get_opportunity",
                risk_tier="low",
                produces_untrusted_output=True,
                required_args=["opportunity_id"],
            ),
            "get_account": ToolPolicy(
                name="get_account",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "get_contact": ToolPolicy(
                name="get_contact",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "search_leads": ToolPolicy(
                name="search_leads",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "get_case": ToolPolicy(
                name="get_case",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            # Financial write operations — high risk, taint-blocked, human approval
            "update_opportunity_amount": ToolPolicy(
                name="update_opportunity_amount",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["opportunity_id", "amount"],
                max_values={"amount": 10_000.0},
            ),
            "create_quote": ToolPolicy(
                name="create_quote",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["opportunity_id", "total"],
                max_values={"total": 10_000.0},
            ),
            "process_refund": ToolPolicy(
                name="process_refund",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["case_id", "amount"],
                max_values={"amount": 500.0},
            ),
            "send_contract": ToolPolicy(
                name="send_contract",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["opportunity_id", "recipient_email"],
            ),
            "create_case": ToolPolicy(
                name="create_case",
                risk_tier="high",
                forbid_when_tainted=True,
            ),
            "external_service_callout": ToolPolicy(
                name="external_service_callout",
                risk_tier="high",
                forbid_when_tainted=True,
                produces_untrusted_output=True,
            ),
        },
    ),
)


# ---------------------------------------------------------------------------
# 4. WhatsApp Bot  —  Haptik / Meta WhatsApp Cloud API
# ---------------------------------------------------------------------------

WHATSAPP_BOT = PolicyPreset(
    name="WHATSAPP_BOT",
    platform="Haptik / WhatsApp",
    description=(
        "Policy for 24/7 WhatsApp bots (Haptik Smart Agent or Meta Cloud "
        "API). Conservative velocity limit (20 messages/minute per user) to "
        "prevent flooding. All financial actions require human approval. "
        "Egress restricted to WhatsApp/Meta and Haptik domains. Designed for "
        "regional markets where users may attempt social engineering."
    ),
    policy=Policy(
        version="whatsapp-bot-1",
        default_deny=False,
        max_spend_per_transaction=100.0,
        max_spend_per_session=300.0,
        max_calls_per_minute=20,
        allowed_egress_domains=[
            "graph.facebook.com",
            "whatsapp.com",
            "haptik.ai",
            "haptikapi.com",
        ],
        unknown_tool_risk="high",
        detector_flag_threshold=0.40,
        detector_block_threshold=0.75,
        tools={
            "send_message": ToolPolicy(
                name="send_message",
                risk_tier="low",
                required_args=["to", "body"],
                allowed_args=["to", "body", "template", "media_url"],
                rate_limit_per_minute=10,
            ),
            "send_template_message": ToolPolicy(
                name="send_template_message",
                risk_tier="low",
                required_args=["to", "template_name"],
                rate_limit_per_minute=10,
            ),
            "get_user_profile": ToolPolicy(
                name="get_user_profile",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "handle_payment": ToolPolicy(
                name="handle_payment",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["to", "amount", "currency"],
                max_values={"amount": 100.0},
            ),
            "escalate_to_agent": ToolPolicy(
                name="escalate_to_agent",
                risk_tier="low",
            ),
            "lookup_order": ToolPolicy(
                name="lookup_order",
                risk_tier="low",
                produces_untrusted_output=True,
                required_args=["order_id"],
            ),
            "update_subscription": ToolPolicy(
                name="update_subscription",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
            ),
        },
    ),
)


# ---------------------------------------------------------------------------
# 5. UiPath RPA  —  Invoice, HR, and clerical process automation
# ---------------------------------------------------------------------------

UIPATH_RPA = PolicyPreset(
    name="UIPATH_RPA",
    platform="UiPath Platform",
    description=(
        "Policy for UiPath RPA bots handling invoice processing, HR "
        "automation, and repetitive clerical tasks. Enforces financial "
        "ceilings on invoice amounts, blocks PII egress, taints the session "
        "when the bot reads external files or emails, and prevents financial "
        "actions while tainted. Designed for unattended automation with "
        "Action Center human-in-the-loop checkpoints."
    ),
    policy=Policy(
        version="uipath-rpa-1",
        default_deny=False,
        max_spend_per_transaction=5_000.0,
        max_spend_per_session=20_000.0,
        max_calls_per_minute=120,
        spend_arg_names=["amount", "total", "invoice_amount", "payment_amount", "value"],
        allowed_egress_domains=[
            "cloud.uipath.com",
            "uipath.com",
            "orchestrator.uipath.com",
        ],
        unknown_tool_risk="high",
        detector_flag_threshold=0.45,
        detector_block_threshold=0.80,
        tools={
            # File/document reading — mark as untrusted
            "read_file": ToolPolicy(
                name="read_file",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "read_email": ToolPolicy(
                name="read_email",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "read_invoice": ToolPolicy(
                name="read_invoice",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            "ocr_document": ToolPolicy(
                name="ocr_document",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
            # Financial actions — taint-blocked, human checkpoint
            "approve_invoice": ToolPolicy(
                name="approve_invoice",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["invoice_id", "amount"],
                max_values={"amount": 5_000.0, "invoice_amount": 5_000.0},
            ),
            "process_payment": ToolPolicy(
                name="process_payment",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["invoice_id", "amount", "vendor_id"],
                max_values={"amount": 5_000.0, "payment_amount": 5_000.0},
            ),
            "update_erp": ToolPolicy(
                name="update_erp",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
            ),
            # HR operations
            "update_employee_record": ToolPolicy(
                name="update_employee_record",
                risk_tier="high",
                forbid_when_tainted=True,
                require_human_approval=True,
                required_args=["employee_id"],
            ),
            "generate_report": ToolPolicy(
                name="generate_report",
                risk_tier="low",
            ),
            # Orchestrator interactions
            "start_job": ToolPolicy(
                name="start_job",
                risk_tier="high",
                required_args=["process_name"],
            ),
            "action_center_task": ToolPolicy(
                name="action_center_task",
                risk_tier="low",
                produces_untrusted_output=True,
            ),
        },
    ),
)
