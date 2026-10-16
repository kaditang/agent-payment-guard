// First-payment payee check against the sellers' own Bazaar registrations.
//
// Trust-on-first-use pinning (policy.mjs) protects every payment AFTER the first one to a
// resource: the first payTo seen becomes the pin. That leaves the first payment itself
// unprotected — a server already hijacked or spoofed when the agent first meets it gets its
// attacker payTo pinned as "the" payee.
//
// x402 has no binding between a domain and its payTo, but most sellers DO declare their payTo in
// the CDP Bazaar catalog. 402Sentinel keeps daily snapshots of it (the catalog keeps no history
// and cannot be queried per resource) and answers, free:
//   GET https://402sentinel.com/api/payee?url=<resource>&payto=<payTo from the 402>
// → listed_for_resource | listed_for_host | previously_listed | not_listed | unknown_host
//
// OPT-IN (`registry: true`). This package's local checks make no network call; this one sends
// the resource URL and the payTo (both public: they are what the seller registered) to
// 402sentinel.com, once per new payee. Measured 2026-10-16 across 38,601 listings: a registered
// payee was fully REPLACED on only 9 resources in 4 days, so a mismatch is rare and worth a stop.

const DEFAULT_ENDPOINT = "https://402sentinel.com/api/payee";

// verdict -> how the guard treats it. "block" goes through the normal onBlock override path.
const RULES = {
  listed_for_resource: { decision: "allow", severity: "info" },
  listed_for_host: { decision: "allow", severity: "info" },
  unknown_host: { decision: "allow", severity: "info" },
  previously_listed: { decision: "block", severity: "block" },
  not_listed: { decision: "block", severity: "block" },
};

/**
 * @param cfg  true | { on?: "new-payto"|"always", endpoint?, strict?, timeoutMs?, maxChecksPerMinute?, ttlMs?, fetch? }
 * @returns    async ({resourceUrl, payTo, firstSeen}) => null | {decision, signals}
 */
export function createRegistryCheck(cfg) {
  if (!cfg) return null;
  const c = cfg === true ? {} : cfg;
  if (c.on === "never") return null;
  const {
    on = "new-payto",
    endpoint = DEFAULT_ENDPOINT,
    strict = false,
    timeoutMs = 5000,
    maxChecksPerMinute = 30, // the service allows 60/min per IP; stay well under it
    ttlMs = 24 * 3600_000,
  } = c;
  const doFetch = c.fetch ?? globalThis.fetch;
  const cache = new Map(); // resource|payTo -> {ts, result}
  const MAX_CACHE = 5000;
  let windowStart = 0;
  let inWindow = 0;

  return async function check({ resourceUrl, payTo, firstSeen }) {
    if (!resourceUrl || !payTo) return null;
    if (on === "new-payto" && !firstSeen) return null;
    const key = `${resourceUrl}|${payTo}`;
    const hit = cache.get(key);
    if (hit && Date.now() - hit.ts < ttlMs) return hit.result;

    const now = Date.now();
    if (now - windowStart > 60_000) {
      windowStart = now;
      inWindow = 0;
    }
    if (++inWindow > maxChecksPerMinute) {
      // Out of lookups this minute: say so and let the local verdict stand (or stop, if strict).
      return unreachable("registry_rate_capped", `more than ${maxChecksPerMinute} lookups this minute`);
    }

    let body;
    try {
      // No network parameter on purpose: Bazaar lists some sellers as "base" and others as
      // "eip155:8453"; an EVM payTo is one address on every chain, so matching on the address
      // alone avoids blocking a genuine payee over a naming difference.
      const u = `${endpoint}?url=${encodeURIComponent(resourceUrl)}&payto=${encodeURIComponent(payTo)}`;
      const r = await doFetch(u, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
      if (!r.ok) throw new Error(`registry HTTP ${r.status}`);
      body = await r.json();
    } catch (err) {
      return unreachable("registry_unreachable", String(err?.message ?? err));
    }
    const rule = RULES[body?.verdict];
    if (!rule) return unreachable("registry_unreadable", `unexpected verdict ${JSON.stringify(body?.verdict)}`);
    const listed = (body.listed_payees ?? []).map((p) => p.payto).slice(0, 3).join(", ");
    const result = {
      decision: rule.decision,
      signals: [{
        signal: `payee_${body.verdict}`,
        severity: rule.severity,
        kind: "counterparty",
        detail: rule.decision === "block"
          ? `${hostOf(resourceUrl)} registered ${listed || "other payee(s)"} in Bazaar, not ${payTo}${body.verdict === "previously_listed" ? " (it did in an earlier snapshot)" : ""} — confirm with the seller before paying`
          : body.how_to_read ?? body.verdict,
      }],
    };
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(key, { ts: Date.now(), result });
    return result;
  };

  function unreachable(signal, detail) {
    // An add-on check: an outage must not stop an agent the local policy already cleared,
    // unless the caller asked for strict. Never cached, so the next payment asks again.
    return strict
      ? { decision: "block", signals: [{ signal, severity: "block", detail }] }
      : { decision: "allow", signals: [{ signal, severity: "info", detail }], degraded: true };
  }
}

function hostOf(u) {
  try {
    return new URL(u).hostname;
  } catch {
    return "this host";
  }
}
