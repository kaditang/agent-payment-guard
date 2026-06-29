// Vercel AI SDK — gate a payment tool with agent-payment-guard.
//   npm i ai zod @kaditang/agent-payment-guard
//
// The universal pattern: call paymentGuard() at the TOP of your money-moving tool's
// `execute`, and return a blocked message instead of paying when it says no.
import { tool } from "ai";
import { z } from "zod";
import { paymentGuard } from "@kaditang/agent-payment-guard";

// What the human/task actually authorized (enables intent-mismatch detection).
const APPROVED = { payto: "0xSELLER_THE_USER_APPROVED", max_amount: "1.00" };

// Track the last untrusted tool/page output the agent acted on, so the guard can catch a
// payTo that was injected by scraped content. Wire this to your own source.
let lastUntrustedText = "";
export function noteUntrusted(text: string) { lastUntrustedText = text; }

export const payX402 = tool({
  description: "Pay an x402 seller in USDC on Base.",
  inputSchema: z.object({
    payto_address: z.string(),
    amount: z.string(),
    resource_url: z.string().optional(),
  }),
  execute: async (input) => {
    const { allow, reason } = await paymentGuard(input, {
      intended: APPROVED,
      untrustedText: lastUntrustedText,
    });
    if (!allow) return `Payment blocked by agent-payment-guard: ${reason}`;

    // ...sign + send the actual x402 payment here...
    return `Paid ${input.amount} USDC to ${input.payto_address}.`;
  },
});
