// Coinbase AgentKit — gate an x402 payment action with agent-payment-guard.
//   npm i @coinbase/agentkit zod @kaditang/agent-payment-guard
//
// AgentKit gives the agent a wallet; this adds the pre-pay risk gate AgentKit doesn't —
// the check that runs before the wallet signs.
import { customActionProvider } from "@coinbase/agentkit";
import { z } from "zod";
import { paymentGuard } from "@kaditang/agent-payment-guard";

const PaySchema = z.object({
  payto_address: z.string(),
  amount: z.string(),
  resource_url: z.string().optional(),
});

const APPROVED = { payto: "0xSELLER_THE_USER_APPROVED", max_amount: "1.00" };

// Register this provider with AgentKit alongside your wallet/x402 providers.
export const guardedPayment = customActionProvider({
  name: "pay_x402",
  description: "Pay an x402 seller in USDC on Base — gated by a pre-pay risk check.",
  schema: PaySchema,
  invoke: async (wallet, args) => {
    const { allow, reason } = await paymentGuard(args, {
      intended: APPROVED,
      agentId: await wallet.getAddress(),
    });
    if (!allow) return `BLOCKED by agent-payment-guard: ${reason}`;

    // ...perform the x402 payment with `wallet` here...
    return `Paid ${args.amount} USDC to ${args.payto_address}.`;
  },
});
