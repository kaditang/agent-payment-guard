# Changelog

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
