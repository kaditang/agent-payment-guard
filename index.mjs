// @kaditang/agent-payment-guard — public entry.
// A pre-pay risk gate for autonomous payment agents, backed by 402Sentinel.
export { paymentGuard } from "./guard.mjs";
export { assessPayment, mockFirewall, liveFirewall } from "./sentinel.mjs";
export { guardedFetch, guardSelector, guardAxios, wrapFetchWithPaymentGuard, vetChallenge } from "./x402.mjs";
export { createPolicy, normalizeChallenge, PaymentBlockedError } from "./policy.mjs";
