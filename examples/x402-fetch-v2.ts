// Drop-in guard for @x402/fetch — the v2 client, and the one most people are actually on
// (~426k installs/mo, and the only x402 client whose download curve has a weekday/weekend
// shape, i.e. real developers rather than mirrors).
//
//   npm i @x402/fetch @x402/core @x402/evm viem @kaditang/agent-payment-guard
//
// The integration is the one wrapped argument. Every 402 this agent answers is vetted before
// a signature exists; nothing else in the agent's code changes.

import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { guardedFetch, PaymentBlockedError } from "@kaditang/agent-payment-guard/x402";

const account = privateKeyToAccount(process.env.CLIENT_PRIVATE_KEY as `0x${string}`);

const client = new x402Client();
registerExactEvmScheme(client, { signer: account });

const fetchWithPay = wrapFetchWithPayment(
  guardedFetch(fetch, {
    maxAmount: 0.05, // never pay more than 5c for a single call
    dailyBudget: 5, // ...or more than $5 in a day, however many calls that takes
    // pinPayTo is on by default: the first payTo seen for a host+path+rail is pinned, and a
    // later change is blocked. That is the check that catches a hijacked resource.

    // Optional: escalate to 402Sentinel's full firewall, but only the first time this agent
    // pays a given address — a $0.002 check on every $0.008 call is overhead nobody keeps on.
    sentinel: { on: "new-payto", live: true, payerKey: process.env.CLIENT_PRIVATE_KEY },
  }),
  new x402HTTPClient(client),
);

try {
  const res = await fetchWithPay("https://stockwaves.net/api/cn/pulse?since=30");
  console.log(await res.json());
} catch (err) {
  if (err instanceof PaymentBlockedError) {
    // The agent never signed. `err.signals` says exactly which check fired, and
    // `signals.tradeable_on`-style detail lives on the response, not here.
    console.error("payment refused:", err.detail, err.signals);
  } else {
    throw err;
  }
}
