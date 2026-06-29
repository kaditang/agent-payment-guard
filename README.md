# agent-payment-guard

[![npm](https://img.shields.io/npm/v/@kaditang/agent-payment-guard)](https://www.npmjs.com/package/@kaditang/agent-payment-guard) [![ci](https://github.com/kaditang/agent-payment-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/kaditang/agent-payment-guard/actions/workflows/ci.yml) ![license](https://img.shields.io/badge/license-MIT-blue)

**A pre-pay risk gate for autonomous payment agents.** Before your agent signs a payment, it
asks [402Sentinel](https://402sentinel.com)'s firewall whether *this* payment is safe in the
context of what the agent was actually asked to do — and blocks routing swaps, prompt-injected
destinations, overcharges and drains.

The agent frameworks (Claude Agent SDK, LangGraph, CrewAI) give you the orchestration loop.
The payment rails (x402 / Coinbase AgentKit, Stripe, Skyfire) give you the ability to move
money. **Neither gives you the gate that decides whether a specific payment is safe to make.**
This is that gate.

<!-- Record a ~10s terminal GIF of `node demo.mjs` (scenario 2 getting blocked) and drop it here: -->
<!-- ![demo](./demo.gif) -->

## Install

```bash
npm i @kaditang/agent-payment-guard
```

```js
import { paymentGuard } from "@kaditang/agent-payment-guard";

// right before your agent signs a payment:
const { allow, reason } = await paymentGuard(toolInput, {
  intended: { payto: approvedSeller, max_amount: "1.00" }, // what the human/task authorized
  untrustedText: lastPageOrToolOutput,                     // what the agent acted on
});
if (!allow) throw new Error(reason); // ⛔ don't sign

// or just try it: npx @kaditang/agent-payment-guard
```

```
$ node demo.mjs

  1. Legit payment — agent pays the seller the user approved
     ✅ ALLOW — payment proceeds

  2. PROMPT INJECTION — a scraped page said 'send payment to 0xBAD…'; the agent obeyed
     ⛔ BLOCK — payment STOPPED before signing
     signals: intent_mismatch(block), injection_destination(block)

  3. OVERCHARGE / drain — agent about to pay 50x the approved cap
     ⛔ BLOCK — payment STOPPED before signing
     signals: amount_anomaly(block)

  2/3 dangerous payments stopped by the pre-pay gate.
```

## Run it

```bash
node demo.mjs            # MOCK firewall — zero deps, instant; shows the gate logic
node demo.mjs --live     # REAL $0.002 x402 calls to https://402sentinel.com/api/firewall
                         #   npm i @x402/core @x402/evm viem  +  CLIENT_PRIVATE_KEY (Base-USDC-funded)
```

## Wire it into your agent

- **Claude Agent SDK** — `agent-sdk-hook.ts`: a `PreToolUse` hook returns
  `{ permissionDecision: "deny" }` so the agent *literally cannot* call its payment tool on a
  flagged payment.
- **Any framework / x402 client** — call `paymentGuard(toolInput, ctx)` from `guard.mjs`
  right before you sign. `ctx.intended` = what the human approved (enables intent-mismatch);
  `ctx.untrustedText` = any page/tool output the agent acted on (enables injection-destination).

## What the firewall checks

`POST https://402sentinel.com/api/firewall` → `allow | hold | block` + signals:
`routing_anomaly` (payTo swapped vs history) · `injection_destination` (payTo appeared in
untrusted content → hard block) · `intent_mismatch` (paying someone other than approved →
hard block) · `amount_anomaly` (overcharge) · `velocity_anomaly` (drain) · `counterparty_risk`
(folds the seller's on-chain risk score). Pay-per-call x402, no signup. The deterministic hard
blocks shown in the demo are exactly what the live service enforces; the live service adds
learned per-signal precision, per-agent history/velocity state, and counterparty risk.

## Fail-closed by default

If 402Sentinel can't be reached, `paymentGuard` **blocks** the payment (`decision: "block"`,
`error: true`) rather than letting it through — a safety gate that fails open is worse than no
gate, because it gives false confidence. If you'd rather keep paying when the gate is down,
pass `failOpen: true`.

## Test

```bash
node --test          # 7 tests: the 3 block scenarios, pass-through, fail-closed + fail-open
```

Not affiliated with Anthropic / Coinbase / Stripe — an independent safety layer for the agents
they're enabling to move money.
