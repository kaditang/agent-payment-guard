// Drop-in guard for x402-axios. Guard the instance FIRST, then let x402 attach its
// interceptor — the guard wraps the adapter, so it sees the 402 before any interceptor does.
//
//   npm i axios x402-axios @kaditang/agent-payment-guard

import axios from "axios";
import { withPaymentInterceptor } from "x402-axios";
import { privateKeyToAccount } from "viem/accounts";
import { guardAxios, PaymentBlockedError } from "@kaditang/agent-payment-guard/x402";

const signer = privateKeyToAccount(process.env.CLIENT_PRIVATE_KEY as `0x${string}`);

// `await`: axios stores defaults.adapter as a list of adapter NAMES, so resolving it to a
// function goes through axios' own getAdapter.
const client = withPaymentInterceptor(
  await guardAxios(axios.create(), {
    maxAmount: 0.05,
    dailyBudget: 5,
    // pinPayTo is on by default — the first payTo seen for a host+rail is pinned, and a
    // later change is blocked as a hijacked resource.
  }),
  signer,
);

try {
  const { data } = await client.get("https://stockwaves.net/api/cn/pulse?since=30");
  console.log(data);
} catch (err) {
  if (err instanceof PaymentBlockedError) {
    console.error("payment refused:", err.detail, err.signals);
  } else {
    throw err;
  }
}
