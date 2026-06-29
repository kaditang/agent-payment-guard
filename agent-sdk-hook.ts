// ── Claude Agent SDK integration ─────────────────────────────────────────────
// Wire 402Sentinel as a PreToolUse gate so your agent CANNOT sign a dangerous payment.
// This is the piece the agent frameworks don't give you: a pre-dispatch approval gate.
//
//   npm i @anthropic-ai/claude-agent-sdk
//   ANTHROPIC_API_KEY=…  npx tsx agent-sdk-hook.ts
//
// @ts-nocheck  (illustrative — runs once @anthropic-ai/claude-agent-sdk is installed)
import { query } from "@anthropic-ai/claude-agent-sdk";
import { paymentGuard } from "./guard.mjs";

// Tool names in YOUR agent that move money (x402 pay, wallet transfer, AgentKit action…).
const PAYMENT_TOOLS = ["pay", "x402_pay", "send_payment", "transfer", "make_payment"];

// What the human/task actually authorized — the gate compares the real payment against this.
const APPROVED = { payto: "0xSELLER_THE_USER_APPROVED", max_amount: "1.00" };

// Track the last untrusted tool/page output the agent saw, so the gate can catch a payTo
// that was injected by scraped content (prompt-injection destination).
let lastUntrustedText = "";

const q = query({
  prompt: "Buy the dataset from the seller and pay for it.",
  options: {
    hooks: {
      PreToolUse: [
        {
          callback: async ({ tool_name, tool_input }) => {
            // Remember untrusted content the agent just read (web/tool output).
            if (/fetch|search|browse|read|scrape/i.test(tool_name)) {
              lastUntrustedText = JSON.stringify(tool_input);
              return { permissionDecision: "allow" };
            }
            if (!PAYMENT_TOOLS.includes(tool_name)) return { permissionDecision: "allow" };

            // A money-moving tool is about to fire — gate it through 402Sentinel.
            const v = await paymentGuard(tool_input, {
              agentId: APPROVED.payto,
              intended: APPROVED,
              untrustedText: lastUntrustedText,
              source: "agent_loop",
              // live: true, payerKey: process.env.CLIENT_PRIVATE_KEY,  // ← real firewall call
            });

            return v.allow
              ? { permissionDecision: "allow" }
              : { permissionDecision: "deny", message: v.reason }; // ⛔ the agent literally cannot pay
          },
        },
      ],
    },
  },
});

for await (const msg of q) {
  if (msg.type === "result") console.log(msg.result);
}
