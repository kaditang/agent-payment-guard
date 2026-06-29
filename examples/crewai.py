# CrewAI — gate a payment tool with agent-payment-guard.
#   pip install crewai
#   (uses pay_guard.py in this folder)
from crewai.tools import tool
from pay_guard import payment_guard

APPROVED = {"payto": "0xSELLER_THE_USER_APPROVED", "max_amount": "1.00"}


@tool("pay_x402")
def pay_x402(payto_address: str, amount: str, resource_url: str = "") -> str:
    """Pay an x402 seller in USDC on Base, gated by a pre-pay risk check."""
    v = payment_guard(
        {"payto_address": payto_address, "amount": amount, "resource_url": resource_url},
        intended=APPROVED,
    )
    if not v["allow"]:
        return f"BLOCKED by agent-payment-guard: {v['reason']}"

    # ...perform the x402 payment here...
    return f"Paid {amount} USDC to {payto_address}."
