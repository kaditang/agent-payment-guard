"""Python drop-in for the 402Sentinel pre-pay firewall — the same gate as the JS
`paymentGuard`, for LangChain / CrewAI / any Python agent.

MOCK (default): a deterministic mirror of 402Sentinel's hard-block rules — stdlib only,
runs with no funds. Swap `_mock_firewall` for a live x402-paid POST to
https://402sentinel.com/api/firewall when you're ready to use the real service (it adds
learned per-signal precision, per-agent velocity/history state, and counterparty risk).

Fail-CLOSED by default: if the check can't run, BLOCK rather than pay (a safety gate that
fails open gives false confidence). Pass fail_open=True to prefer availability.
"""
from typing import Any, Optional


def _mock_firewall(payment: dict, intended: Optional[dict], untrusted_text: str) -> dict:
    signals = []
    payto = str(payment.get("payto_address", "")).lower()
    if intended and intended.get("payto") and str(intended["payto"]).lower() != payto:
        signals.append({"signal": "intent_mismatch", "severity": "block"})
    if intended and intended.get("max_amount") is not None and float(payment.get("amount", 0) or 0) > float(intended["max_amount"]):
        signals.append({"signal": "amount_anomaly", "severity": "block"})
    if untrusted_text and payto and payto in untrusted_text.lower():
        signals.append({"signal": "injection_destination", "severity": "block"})
    decision = "block" if any(s["severity"] == "block" for s in signals) else "allow"
    return {"decision": decision, "signals": signals}


def payment_guard(
    payment: dict,
    intended: Optional[dict] = None,
    untrusted_text: str = "",
    fail_open: bool = False,
) -> dict[str, Any]:
    """Return {allow, decision, reason, signals}. Call this right before your agent pays."""
    if not payment.get("payto_address") or payment.get("amount") is None:
        return {"allow": True, "decision": "allow", "reason": "not a payment", "signals": []}
    try:
        v = _mock_firewall(payment, intended, untrusted_text)
    except Exception as e:  # fail-CLOSED
        return {"allow": fail_open, "decision": "allow" if fail_open else "block",
                "reason": f"firewall error (failing {'OPEN' if fail_open else 'CLOSED'}): {e}", "signals": []}
    allow = v["decision"] == "allow"
    reason = "402Sentinel: allow" if allow else \
        f"402Sentinel {v['decision'].upper()} — " + ", ".join(s["signal"] for s in v["signals"])
    return {"allow": allow, "decision": v["decision"], "reason": reason, "signals": v["signals"]}
