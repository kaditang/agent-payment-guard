// 402Sentinel buyer-side payment firewall client.
//
// assessPayment() POSTs a candidate payment to <SENTINEL_BASE_URL>/api/firewall and
// returns the verdict (allow | hold | block) + the signals that drove it. This is the
// "pre-pay risk gate" an autonomous payment agent should consult BEFORE it signs.
//
// Two modes:
//   MOCK (default)  — zero-dependency, instant. Faithfully mirrors 402Sentinel's DETERMINISTIC
//                     hard-block rules so anyone can run the demo with no funds / no install.
//   LIVE (--live)   — a real x402-paid call to a firewall you run. The hosted 402Sentinel was retired
//                     on 2026-10-31: since 0.5.0 SENTINEL_BASE_URL is required and 402sentinel.com is refused.
//
// The real service adds learned per-signal precision, velocity/history state, sock-puppet
// detection and counterparty risk on top of these deterministic rules — but the hard blocks
// below (prompt-injection destination, intent mismatch) are exactly what it enforces.

import { checkEndpoint } from "./retired.mjs";

/** Deterministic mirror of 402Sentinel's hard-block firewall signals. */
export function mockFirewall({ payment, context }) {
  const signals = [];
  const payTo = String(payment.payto_address || "").toLowerCase();
  const intended = context?.intended;
  const untrusted = String(context?.untrusted_text || "");

  // intent_mismatch — the agent is paying someone OTHER than the human-approved recipient,
  // or more than the approved cap. Mid-flight redirect / overcharge → hard block.
  if (intended?.payto && String(intended.payto).toLowerCase() !== payTo) {
    signals.push({ signal: "intent_mismatch", severity: "block", detail: `payTo ${shorten(payTo)} != approved ${shorten(intended.payto)}` });
  }
  if (intended?.max_amount != null && Number(payment.amount) > Number(intended.max_amount)) {
    signals.push({ signal: "amount_anomaly", severity: "block", detail: `amount ${payment.amount} > approved max ${intended.max_amount}` });
  }

  // injection_destination — the payTo appears inside untrusted tool/page output the agent
  // acted on. Classic prompt-injection: the content told the agent where to send money.
  if (untrusted && payTo && untrusted.toLowerCase().includes(payTo)) {
    signals.push({ signal: "injection_destination", severity: "block", detail: "payTo was present in untrusted source text" });
  }

  // provenance_flag — acting on an untrusted source at all is a soft warning.
  if (context?.source && /web|tool|page|email|untrusted/i.test(String(context.source)) && !signals.length) {
    signals.push({ signal: "provenance_flag", severity: "review", detail: `payment destination derived from ${context.source}` });
  }

  const hardBlock = signals.some((s) => s.severity === "block");
  const review = signals.some((s) => s.severity === "review");
  const decision = hardBlock ? "block" : review ? "hold" : "allow";
  return { decision, signals, mocked: true };
}

/** Live x402-paid call to the production firewall. Lazy-imports the x402 client deps. */
export async function liveFirewall({ agent_id, payment, context }, payerKey) {
  const ep = checkEndpoint(process.env.SENTINEL_BASE_URL, "live firewall");
  if (!ep.ok) throw new Error(ep.reason);
  let createPaymentPayload, encodePaymentSignatureHeader, registerExactEvmScheme, x402Client, x402HTTPClient, privateKeyToAccount;
  try {
    ({ x402Client, x402HTTPClient } = await import("@x402/core/client"));
    ({ encodePaymentSignatureHeader } = await import("@x402/core/http"));
    ({ registerExactEvmScheme } = await import("@x402/evm/exact/client"));
    ({ privateKeyToAccount } = await import("viem/accounts"));
  } catch {
    throw new Error("--live needs: npm i @x402/core @x402/evm viem  (and CLIENT_PRIVATE_KEY = a Base-mainnet USDC-funded key)");
  }
  const url = `${ep.url}/api/firewall`;
  const body = JSON.stringify({ agent_id, payment, context });
  const post = { method: "POST", headers: { "content-type": "application/json" }, body };
  const probe = await fetch(url, post);
  if (probe.status !== 402) return { ...(await probe.json()), mocked: false };
  const challenge = JSON.parse(Buffer.from(probe.headers.get("payment-required"), "base64").toString());
  const account = privateKeyToAccount(payerKey.startsWith("0x") ? payerKey : `0x${payerKey}`);
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account });
  const http = new x402HTTPClient(client);
  const sig = encodePaymentSignatureHeader(await http.createPaymentPayload(challenge));
  const paid = await fetch(url, { ...post, headers: { ...post.headers, "PAYMENT-SIGNATURE": sig } });
  return { ...(await paid.json()), mocked: false, paid: paid.status < 400 };
}

export async function assessPayment(req, { live = false, payerKey } = {}) {
  return live ? liveFirewall(req, payerKey) : mockFirewall(req);
}

function shorten(a) { const s = String(a); return s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s; }
