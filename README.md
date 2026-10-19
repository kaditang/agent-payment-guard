# agent-payment-guard

> [!WARNING]
> **Retirement notice.** The optional online checks (the Bazaar payee registry check and the Sentinel firewall) call **402sentinel.com**, which will be retired on **31 October 2026**; the domain will not be renewed and lapses in May 2027. The local policy checks keep working offline. Turn the online checks off (no `registry: true`, no Sentinel calls), or point them only at an endpoint you trust — **do not trust responses from 402sentinel.com after May 2027.** The package is deprecated; the code stays here under its licence.
>
> **0.5.0 (final release):** the online checks have no default endpoint any more, and `402sentinel.com` is refused even if you configure it. `registry: true` alone now turns the registry check off (with one warning); `--live` needs `SENTINEL_BASE_URL`. The local policy checks are unchanged.

[![npm](https://img.shields.io/npm/v/@kaditang/agent-payment-guard)](https://www.npmjs.com/package/@kaditang/agent-payment-guard) [![ci](https://github.com/kaditang/agent-payment-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/kaditang/agent-payment-guard/actions/workflows/ci.yml) ![license](https://img.shields.io/badge/license-MIT-blue)

**A pre-pay risk gate for autonomous payment agents.** Before your agent signs a payment, it
asks [402Sentinel](https://402sentinel.com)'s firewall whether *this* payment is safe in the
context of what the agent was actually asked to do — and blocks routing swaps, prompt-injected
destinations, overcharges and drains.

The agent frameworks (Claude Agent SDK, LangGraph, CrewAI) give you the orchestration loop.
The payment rails (x402 / Coinbase AgentKit, Stripe, Skyfire) give you the ability to move
money. **Neither gives you the gate that decides whether a specific payment is safe to make.**
This is that gate.

**Works with:** Claude Agent SDK · Vercel AI SDK · Coinbase AgentKit · LangChain / LangGraph · CrewAI · any x402 client (JS + Python). One line, fail-closed by default.

**New in 0.3 — [drop it onto the x402 payment path itself](#drop-in-for-the-x402-clients).** No per-call wiring: wrap the fetch once and every 402 your agent answers is vetted before a signature exists.

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

## Drop-in for the x402 clients

`paymentGuard()` protects the payments you remembered to wrap. This protects **all of them** —
it sits on the path your x402 client already runs, and reads the 402 challenge before
`createPaymentHeader()` is ever called.

Both client generations are supported and tested against the real libraries:
`@x402/fetch` + `@x402/axios` (v2 — challenge in the `payment-required` header) and
`x402-fetch` + `x402-axios` (v1 — challenge in the JSON body).

### `@x402/fetch` (v2)

```diff
  import { wrapFetchWithPayment } from "@x402/fetch";
+ import { guardedFetch } from "@kaditang/agent-payment-guard/x402";

- const fetchWithPay = wrapFetchWithPayment(fetch, client);
+ const fetchWithPay = wrapFetchWithPayment(
+   guardedFetch(fetch, { maxAmount: 0.05, dailyBudget: 5 }),
+   client,
+ );
```

Full runnable version: [`examples/x402-fetch-v2.ts`](./examples/x402-fetch-v2.ts).

### `x402-fetch` (v1)

Same shape — the guard reads either challenge format, so the wrapping is identical
([`examples/x402-fetch.ts`](./examples/x402-fetch.ts)):

```diff
  import { wrapFetchWithPayment } from "x402-fetch";
+ import { guardedFetch } from "@kaditang/agent-payment-guard/x402";

- const fetchWithPay = wrapFetchWithPayment(fetch, signer);
+ const fetchWithPay = wrapFetchWithPayment(
+   guardedFetch(fetch, { maxAmount: 0.05, dailyBudget: 5 }),
+   signer,
+ );
```

A blocked payment throws `PaymentBlockedError` — the agent never signs, and no second
(paid) request is made.

For **axios**, guard the instance before `withPaymentInterceptor` attaches to it:

```js
import axios from "axios";
import { withPaymentInterceptor } from "x402-axios";
import { guardAxios } from "@kaditang/agent-payment-guard/x402";

const client = withPaymentInterceptor(
  await guardAxios(axios.create(), { maxAmount: 0.05, dailyBudget: 5 }),
  signer,
);
```

`guardAxios` is async because axios stores `defaults.adapter` as a list of adapter *names*
(`["xhr","http","fetch"]`), and resolving it to a function needs axios' own `getAdapter`.
If you would rather not touch the adapter, pass `guardSelector(opts)` as the
`paymentRequirementsSelector` argument instead — local checks only, since that hook is sync.

### What it checks — locally, free, on every call

| signal | what it catches |
| --- | --- |
| `payto_changed` | this resource's `payTo` is not the one you paid last time — a hijacked or spoofed endpoint. Pinned trust-on-first-use per **host + path + rail** (query strings excluded). Not per host: real sellers split collection across product lines — blockrun.ai pays `/exa/*` to one address, `/pm/*` to a second and `/surf/*` to a third, all on Base — and a host-level pin calls the second and third a hijack. |
| `resource_host_mismatch` | the challenge advertises a different host than the one that served it — an attempt to borrow, or poison, another seller's pin. The host used for policy is always the URL the request actually reached, never the one the challenge claims. |
| `amount_over_cap` | the challenge asks for more than `maxAmount` |
| `amount_unparseable` | the price can't be read, so the cap can't be enforced — blocked rather than waved through |
| `hourly_budget` / `daily_budget` | a slow drain across many small, individually-fine payments |
| `denylisted_payto` / `not_allowlisted` | counterparties you have ruled in or out (matched case-insensitively for EVM, exactly for base58 Solana) |
| `insecure_transport` | the challenge arrived over plaintext HTTP, where it can be rewritten in flight |
| `payto_rotation` | a host presenting more than `maxNewPayToPerHost` (default 8) distinct new `payTo` addresses within an hour. A seller with a few collection addresses stays well under it; one minting a fresh address per challenge blows past it in seconds. The rotation *is* the fraud signal — and blocking it is also what stops a hostile seller from billing your agent for an unbounded number of paid checks. |
| `network_not_allowed` | narrows *which* rail to pay; it never silently blocks a seller you trust |

Both live challenge formats are parsed: v2 (`payment-required` header, `amount`, CAIP-2
networks) and v1 (JSON body, `maxAmountRequired`, short network names).

A **counterparty** failure blocks the payment outright — a bad seller is not repaired by
paying it on a different chain. A **selection** failure only drops that one option.

### Escalating to the paid firewall

The local checks cost nothing. 402Sentinel's full firewall ($0.002/call) is opt-in, and by
default fires only on a `payTo` this agent has never paid before:

```js
guardedFetch(fetch, {
  maxAmount: 0.05,
  sentinel: { on: "new-payto", live: true, payerKey: process.env.CLIENT_PRIVATE_KEY },
});
```

`on: "always"` checks every payment; `"never"` disables it. Verdicts are cached per `payTo`
for 24h. If 402Sentinel is unreachable the local verdict stands and a `sentinel_unreachable`
signal is emitted — an add-on outage should not strand an agent the local policy already
cleared. Set `sentinel.strict: true` to make unreachability a hard stop instead.

Every escalation spends **your** money, so escalations are capped at
`sentinel.maxChecksPerHour` (default 50). Hitting the ceiling stops the spending, not the
agent — otherwise a hostile seller could deny you service just by burning the budget.

### First payment: is this the payee the seller registered? (free, opt-in)

Pins protect every payment after the first one to a resource. For the first, turn on the
registry check: on a payee this agent has never paid, the guard asks 402Sentinel's free
`/api/payee` whether the seller registered that payTo in the x402 Bazaar catalog.

```js
guardedFetch(fetch, { maxAmount: 0.05, registry: true });
```

A payee the seller never registered for that host (`not_listed`), or one it has since replaced
(`previously_listed`), is blocked through `onBlock`; a registered or unknown host passes with an
info signal. An outage passes with `registry_unreachable` (`registry: { strict: true }` to stop
instead). It sends the resource URL and the payTo to 402sentinel.com, which is why it is off by
default. Try the endpoint directly:
`curl "https://402sentinel.com/api/payee?url=https://stockwaves.net/api/rotation&payto=0x…"`

### Budgets and pins

Spend is committed on the **paid retry**, not on the challenge, so a failed payment never
eats budget. Pins live in `~/.agent-payment-guard/pins.json` (`pins: { file }` to relocate,
`pins: { persist: false }` for in-process only). When a seller legitimately rotates its
address, re-pin deliberately:

```js
const policy = createPolicy({ maxAmount: 0.05 });
policy.trustPayTo("https://seller.example/api", newPayTo, "eip155:8453"); // host+path+rail
guardedFetch(fetch, { policy });
```

## Wire it into your agent

**The universal pattern:** call `paymentGuard()` at the top of whatever tool moves money, and
don't pay when it says no. Drop-in examples for every major framework:

| Framework | Example |
| --- | --- |
| Claude Agent SDK (`PreToolUse` hook → `permissionDecision: "deny"`) | [`agent-sdk-hook.ts`](./agent-sdk-hook.ts) |
| Vercel AI SDK (gate a `tool({ execute })`) | [`examples/vercel-ai-sdk.ts`](./examples/vercel-ai-sdk.ts) |
| Coinbase AgentKit (gate a `customActionProvider` action) | [`examples/coinbase-agentkit.ts`](./examples/coinbase-agentkit.ts) |
| LangChain / LangGraph (Python `@tool`) | [`examples/langchain.py`](./examples/langchain.py) |
| CrewAI (Python `@tool`) | [`examples/crewai.py`](./examples/crewai.py) |

JS/TS imports `paymentGuard` from this package. Python uses the matching
[`examples/pay_guard.py`](./examples/pay_guard.py) drop-in (same fail-closed gate, stdlib only).
`ctx.intended` = what the human approved (enables intent-mismatch); `ctx.untrustedText` = any
page/tool output the agent acted on (enables injection-destination).

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
