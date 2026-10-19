// 402Sentinel was retired on 2026-10-31 and 402sentinel.com is not renewed (it lapses in May 2027). From 0.5.0
// the online checks have NO default endpoint, and the retired domain is refused even when configured: once it
// lapses, whoever registers it could answer "safe to pay" (registry) or take x402 payments (live firewall).

export const RETIRED_HOSTS = ["402sentinel.com"];

/** @returns {{ok: true, url: string} | {ok: false, reason: string}} */
export function checkEndpoint(raw, what) {
  const v = String(raw ?? "").trim();
  if (!v) return { ok: false, reason: `${what}: 402Sentinel was retired on 31 October 2026 and there is no default endpoint; pass one you run and trust.` };
  let u;
  try { u = new URL(v); } catch { return { ok: false, reason: `${what}: not a valid URL: ${v}` }; }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (RETIRED_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {
    return { ok: false, reason: `${what}: ${host} is the retired 402Sentinel domain (ended 31 October 2026; it lapses in May 2027 and may then belong to someone else) — refused.` };
  }
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(host);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return { ok: false, reason: `${what}: must use https (http only for localhost).` };
  return { ok: true, url: v.replace(/\/+$/, "") };
}

const warned = new Set();
export function warnOnce(msg) {
  if (warned.has(msg)) return;
  warned.add(msg);
  console.warn(`agent-payment-guard: ${msg}`);
}
