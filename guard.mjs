// paymentGuard — a framework-agnostic PRE-PAY risk gate for autonomous payment agents.
//
// Drop it in front of whatever tool your agent uses to move money (an x402 pay, a wallet
// transfer, an AgentKit action). Before the payment executes, it asks 402Sentinel's firewall
// whether THIS payment is safe in the context of what the agent was actually asked to do —
// and blocks routing swaps, prompt-injected destinations, overcharges and drains.
//
// The agent frameworks give you the orchestration loop; none of them give you this gate.
// (Claude Agent SDK PreToolUse adapter is in agent-sdk-hook.ts.)

import { assessPayment } from "./sentinel.mjs";

// Pull {payto, amount, resource_url} out of a payment tool's input, whatever it's named.
function extractPayment(toolInput) {
  const i = toolInput || {};
  const payto = i.payto_address || i.payTo || i.payto || i.to || i.recipient || i.destination || i.address;
  const amount = i.amount ?? i.value ?? i.usd ?? i.amount_usdc;
  const resource_url = i.resource_url || i.resource || i.url || i.endpoint;
  if (!payto || amount == null) return null;
  return { payto_address: String(payto), amount: String(amount), resource_url: resource_url ? String(resource_url) : undefined };
}

/**
 * @param toolInput  the arguments the agent wants to call its payment tool with
 * @param ctx        { agentId, intended:{payto,max_amount}, untrustedText, source, live, payerKey, failOpen }
 *                   `intended` = what the human/task actually authorized (enables intent-mismatch
 *                   detection); `untrustedText` = any tool/page output the agent acted on
 *                   (enables prompt-injection-destination detection).
 *                   `failOpen` (default false) = if the firewall can't be reached, ALLOW the
 *                   payment instead of blocking it. Leave it false — a safety gate that can't
 *                   verify safety should not let money move.
 * @returns { allow:boolean, decision, reason, signals }
 */
export async function paymentGuard(toolInput, ctx = {}) {
  const payment = extractPayment(toolInput);
  if (!payment) return { allow: true, decision: "allow", reason: "not a payment tool call", signals: [] };

  let verdict;
  try {
    verdict = await assessPayment(
      {
        agent_id: ctx.agentId || "demo-agent",
        payment,
        context: { source: ctx.source, untrusted_text: ctx.untrustedText, intended: ctx.intended },
      },
      { live: ctx.live, payerKey: ctx.payerKey },
    );
  } catch (err) {
    // FAIL-CLOSED by default: if we can't verify the payment is safe, don't let it through.
    // A gate that fails open is worse than no gate — it gives false confidence. Opt out with
    // ctx.failOpen=true only if you'd rather the agent keep paying when 402Sentinel is down.
    const msg = err?.message || String(err);
    return ctx.failOpen
      ? { allow: true, decision: "allow", reason: `firewall unreachable — failing OPEN: ${msg}`, signals: [], error: true }
      : { allow: false, decision: "block", reason: `firewall unreachable — failing CLOSED: ${msg}`, signals: [], error: true };
  }

  const allow = verdict.decision === "allow";
  const reason = allow
    ? "402Sentinel: allow"
    : `402Sentinel ${verdict.decision.toUpperCase()} — ${(verdict.signals || []).map((s) => s.signal).join(", ") || "policy"}`;
  return { allow, decision: verdict.decision, reason, signals: verdict.signals || [], mocked: verdict.mocked };
}
