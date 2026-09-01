// Drop-in guard for x402-fetch — the whole integration is the one wrapped argument.
//
//   npm i x402-fetch @kaditang/agent-payment-guard
//
// Every 402 this agent answers is now vetted before a signature exists. Nothing else in the
// agent's code changes, and there is no per-payment wiring to remember.

import { wrapFetchWithPayment } from "x402-fetch";
import { privateKeyToAccount } from "viem/accounts";
import { guardedFetch, PaymentBlockedError } from "@kaditang/agent-payment-guard/x402";

const signer = privateKeyToAccount(process.env.CLIENT_PRIVATE_KEY as `0x${string}`);

const fetchWithPay = wrapFetchWithPayment(
  guardedFetch(fetch, {
    maxAmount: 0.05, // never pay more than 5c for a single call
    dailyBudget: 5, // ...or more than $5 in a day, however many calls that takes
    // pinPayTo is on by default: the first payTo seen for a host+rail is pinned, and a
    // later change is blocked. That is the check that catches a hijacked resource.

    // Optional: escalate to 402Sentinel's full firewall, but only the first time this agent
    // pays a given address — a $0.002 check on every $0.008 call is overhead nobody keeps on.
    sentinel: { on: "new-payto", live: true, payerKey: process.env.CLIENT_PRIVATE_KEY },
  }),
  signer,
);

try {
  const res = await fetchWithPay("https://stockwaves.net/api/cn/pulse?since=30");
  console.log(await res.json());
} catch (err) {
  if (err instanceof PaymentBlockedError) {
    // The agent never signed. `err.signals` says exactly which check fired.
    console.error("payment refused:", err.detail, err.signals);
  } else {
    throw err;
  }
}
