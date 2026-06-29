# Changelog

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
