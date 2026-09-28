import json
import logging
from datetime import datetime, timezone
from halcyon.store import Store

logger = logging.getLogger("siem.audit")

INTERNAL_TOKEN_DISCLOSED = "internal_token_disclosed"
POLICY_OVERRIDE = "policy_override"
INPUT_FILTERED = "input_filtered"
SYSTEM_PROMPT_DISCLOSED = "system_prompt_disclosed"
XSS_BEACON = "xss_beacon"
POISONED_CHUNK_IN_CONTEXT = "poisoned_chunk_in_context"
RAG_INJECTION_FIRED = "rag_injection_fired"
RESTRICTED_DOC_RETRIEVED = "restricted_doc_retrieved"
RESTRICTED_DOC_DISCLOSED = "restricted_doc_disclosed"
INGESTION_INJECTION_FLAGGED = "ingestion_injection_flagged"
MALICIOUS_ARTIFACT_IDENTIFIED = "malicious_artifact_identified"
VULNERABLE_DEPENDENCY_IDENTIFIED = "vulnerable_dependency_identified"
TOOL_CALL = "tool_call"
UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"
UNAUTHORIZED_ACCOUNT_MODIFICATION = "unauthorized_account_modification"
MCP_POISONED_INVOCATION = "mcp_poisoned_invocation"
MCP_DESC_MUTATION_ACCEPTED = "mcp_desc_mutation_accepted"
TOKEN_READ = "token_read"
INTER_AGENT_INJECTION_PROPAGATED = "inter_agent_injection_propagated"
UNAUTHORIZED_APPROVAL = "unauthorized_approval"
SUPERVISOR_PROVENANCE_BYPASSED = "supervisor_provenance_bypassed"
GUARDRAIL_BYPASSED = "guardrail_bypassed"
GUARDRAIL_HARDENED_BLOCK = "guardrail_hardened_block"
GUARDRAIL_DECISION = "guardrail_decision"

# S11 treasury-heist capstone (module "chain")
INGEST_KEY_ACCEPTED = "ingest_key_accepted"
POLICY_DOC_INGESTED = "policy_doc_ingested"
POISONED_DOC_RETRIEVED = "poisoned_doc_retrieved"
TREASURY_TRANSFER_EXECUTED = "treasury_transfer_executed"

CHAIN_CORE_PASSED = "chain_core_passed"

# High-severity events that trigger real-time SIEM alerts
HIGH_RISK_EVENTS = {
    POISONED_CHUNK_IN_CONTEXT,
    RAG_INJECTION_FIRED,
    RESTRICTED_DOC_DISCLOSED,
    INGESTION_INJECTION_FLAGGED,
    UNAUTHORIZED_TOOL_CALL,
}


def dispatch_siem_alert(session_id: str, module: str, event_type: str, details: dict) -> None:
    """Dispatches a real-time SIEM security alert payload for high-severity events."""
    alert_payload = {
        "severity": "CRITICAL" if event_type in HIGH_RISK_EVENTS else "INFO",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "event_type": event_type,
        "session_id": session_id,
        "details": details,
    }
    # SIEM log output (compatible with Splunk / Datadog / ELK ingestion)
    logger.warning("SIEM_ALERT: %s", json.dumps(alert_payload))


def record(
    store: Store,
    session_id: str,
    module: str,
    event_type: str,
    actor: str,
    details: dict | None = None,
) -> None:
    evt_details = details or {}
    store.append_event(session_id, module, event_type, actor, evt_details)
    # Structured SIEM Telemetry & Alert Dispatch
    dispatch_siem_alert(session_id, module, event_type, evt_details)


def has_event(store: Store, session_id: str, module: str, event_type: str) -> bool:
    return any(
        e.event_type == event_type for e in store.events_since_reset(session_id, module)
    )

