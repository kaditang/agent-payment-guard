# Changelog

## 0.4.0

**First-payment payee check (opt-in, free).** Trust-on-first-use pinning protects every payment
after the first one to a resource; the first payee seen becomes the pin, so a server that is
already hijacked when the agent first meets it gets the attacker's payTo pinned. `registry: true`
closes that gap: on a NEW payee the guard asks 402Sentinel's free `GET /api/payee` whether that
payTo is the one the seller registered in the CDP Bazaar catalog (built from daily snapshots; the
catalog itself keeps no history and cannot be queried per resource).

- `not_listed` (host registered, this payee never) and `previously_listed` (rotated away) block
  through the normal `onBlock` path; `listed_for_resource`, `listed_for_host` and `unknown_host`
  pass with an info signal. Runs before the paid Sentinel escalation, so a mismatch costs nothing.
- Fails open on an outage (`registry_unreachable`), closed with `registry: { strict: true }`.
- Cached 24h per resource + payee; capped at 30 lookups/min client-side.
- Matches on the address only: Bazaar names the same chain "base" or "eip155:8453" depending on
  the seller, and an EVM payee is one address on every chain.
- Opt-in because the local checks make no network call; this one sends the resource URL and the
  payTo (both public, registered by the seller) to 402sentinel.com.

## 0.3.2

Docs only — no behaviour change.

- The README led with `x402-fetch` (v1). Measured 2026-09-06 against `axios` as a reference for
  what real developer adoption looks like (weekend/weekday download ratio 0.45): **`@x402/fetch`
  (v2) is 0.68 — human-shaped, ~426k installs/mo — while `x402-fetch` (v1) is 0.90, i.e. flat
  across weekends and therefore mirrors and CI, not people.** That matches v1 being the older
  generation, which cannot pay a v2 server at all. So the v2 client now comes first; v1 stays
  documented right below it, unchanged and still tested.
- `description` and keywords now name `@x402/fetch` / `@x402/axios`, which they never did.
- New `examples/x402-fetch-v2.ts` — the README now leads with v2 while `examples/` only had a v1 file.

## 0.3.1

- Verified and now covered by tests against **`@x402/fetch`** (v2, ~426k installs/mo) as well as
  `x402-fetch` (v1, ~96k). The two generations read the challenge from different places — a
  `payment-required` header vs the JSON body — and the guard sits correctly on both. 0.3.0 already
  behaved correctly here; only the test coverage was aimed at the smaller client.
- A seller offering two rails usually fails both for the same reason, and the block message
  printed that reason twice. One reason, stated once.

## 0.3.0

**The guard now drops onto the x402 payment path itself** (`@kaditang/agent-payment-guard/x402`),
instead of only being a gate you call per payment.

- `guardedFetch(fetch, opts)` — wrap the fetch you hand to `x402-fetch`'s
  `wrapFetchWithPayment`. The 402 challenge is vetted before `createPaymentHeader()` runs, so a
  blocked payment never produces a signature and never makes the second, paid request.
- `guardAxios(instance, opts)` (async) and `guardSelector(opts)` for `x402-axios`. Two axios details
  the adapter has to respect: `defaults.adapter` is a list of adapter *names*, not a function (hence
  the async `getAdapter` resolution), and axios' adapters apply `validateStatus` themselves — so a
  402 arrives as a *thrown* AxiosError, and must be re-thrown unchanged, because x402-axios hooks the
  response **error** interceptor and would never fire otherwise.
- `wrapFetchWithPaymentGuard(...)` — full drop-in replacement, lazily importing `x402-fetch`.
- Local, zero-network policy (`./policy`): `payto_changed` trust-on-first-use pinning keyed per
  **host + path + rail** (query strings excluded), `amount_over_cap`, `amount_unparseable`,
  hourly/daily budgets, allow/deny lists, `insecure_transport`, network filtering. Host-level
  keys were wrong against real sellers: blockrun.ai collects to three addresses on one host and
  one rail, and 2 of its 4 endpoints were being hard-blocked as hijacks.
- Parses BOTH live challenge shapes: v2 (`payment-required` header) and v1 (JSON body).
- The paid 402Sentinel firewall becomes an opt-in escalation, defaulting to first-payment-only
  so a $0.002 check never rides on every $0.008 call.
- Verified end-to-end against the real `x402-fetch@1.2.0` **and `x402-axios@1.2.0`**: over-cap and
  payTo-swap payments are stopped with the signer never reached; in-policy payments are handed through.
- Abuse hardening, from attacking the finished guard: escalation spends the *agent's* money, so a
  seller rotating its `payTo` on every 402 could bill it for unlimited $0.002 checks. New
  `payto_rotation` hard block (the rotation is itself the fraud signal), plus a
  `sentinel.maxChecksPerHour` ceiling (default 50) that stops the spending without stranding the
  agent. Guarding the same axios instance — or nesting `guardedFetch` with the same policy —
  is now idempotent; stacking previously committed one payment twice, so it ate double budget.

## 0.2.1
- README: "Works with" framework line + changelog.

## 0.2.0
- Framework wirings in `examples/`: Vercel AI SDK, Coinbase AgentKit, LangChain / LangGraph, CrewAI.
- `examples/pay_guard.py` — a stdlib-only Python drop-in with the same fail-closed gate (JS↔Python parity).

## 0.1.1
- **Fail-closed by default** when the firewall is unreachable (a safety gate that fails open gives false confidence); opt out with `ctx.failOpen`.
- `node:test` suite (7 tests) + GitHub Actions CI.

## 0.1.0
- Initial release: `paymentGuard()` + Claude Agent SDK `PreToolUse` hook + 402Sentinel firewall (mock + live x402).
