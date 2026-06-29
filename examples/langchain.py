# LangChain / LangGraph — gate a payment tool with agent-payment-guard.
#   pip install langchain-core
#   (uses pay_guard.py in this folder)
from langchain_core.tools import tool
from pay_guard import payment_guard

APPROVED = {"payto": "0xSELLER_THE_USER_APPROVED", "max_amount": "1.00"}


@tool
def pay_x402(payto_address: str, amount: str, resource_url: str = "") -> str:
    """Pay an x402 seller in USDC on Base."""
    verdict = payment_guard(
        {"payto_address": payto_address, "amount": amount, "resource_url": resource_url},
        intended=APPROVED,
        # untrusted_text=<any page/tool output the agent acted on>,
    )
    if not verdict["allow"]:
        return f"Payment blocked by agent-payment-guard: {verdict['reason']}"

    # ...sign + send the actual x402 payment here...
    return f"Paid {amount} USDC to {payto_address}."
