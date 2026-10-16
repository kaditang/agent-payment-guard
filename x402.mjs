// Drop-in guards for the x402 buyer-side clients.
//
// The existing paymentGuard() is a gate you call yourself, per payment. That only protects
// the payments you remembered to wrap. These adapters instead sit ON the payment path — the
// same path `x402-fetch` (~96k installs/mo) and `x402-axios` (~20k/mo) already run — so
// every 402 an agent answers is vetted before a signature is ever created, with a one-line
// change and no per-call wiring.
//
//   -  const fetchWithPay = wrapFetchWithPayment(fetch, signer);
//   +  const fetchWithPay = wrapFetchWithPayment(guardedFetch(fetch, { maxAmount: 0.05 }), signer);
//
// Interception point: the guard wraps the fetch that x402-fetch calls, so it reads the 402
// challenge BEFORE createPaymentHeader() runs. A blocked payment throws, so the agent never
// signs — as opposed to signing and then regretting it.
//
// Checks are local and free by default (see policy.mjs). The paid 402Sentinel firewall is an
// opt-in escalation, and even then only fires on payTo addresses this agent has not paid
// before — a $0.002 check on every $0.008 call would be 25% overhead and would get switched off.

import { createPolicy, normalizeChallenge, PaymentBlockedError, hostOf, canonAddress } from "./policy.mjs";
import { assessPayment } from "./sentinel.mjs";
import { createRegistryCheck } from "./registry.mjs";

export { PaymentBlockedError, createPolicy, normalizeChallenge, createRegistryCheck };

// ---------------------------------------------------------------------------

const HEADER_NAMES = ["x-payment", "payment-signature"];

// Cap on challenges awaiting their paid retry. A client that abandons challenges (or is
// blocked upstream) would otherwise grow this map for the life of the process.
const MAX_PENDING = 1000;

// Marks an adapter this library installed, and carries the adapter it replaced. Guarding the
// same axios instance twice would otherwise STACK guards: the payment is vetted twice and, far
// worse, `commit()` runs twice per payment — so one call eats double its budget.
const GUARD_MARK = Symbol.for("@kaditang/agent-payment-guard.adapter");

// Tags a fetch this library wrapped, with the policy it enforces. Wrapping an already-guarded
// fetch with the SAME policy stacks two guards over one payment, and both commit it — so a
// single call consumes double its budget. Two DIFFERENT policies stacking is legitimate
// (each tracks its own budget), so only the shared-policy case collapses.
const GUARD_FETCH = Symbol.for("@kaditang/agent-payment-guard.fetch");

function requestHasPaymentHeader(input, init) {
  const seen = [];
  const h = init?.headers;
  if (h) {
    if (typeof h.forEach === "function" && !Array.isArray(h)) h.forEach((_v, k) => seen.push(String(k).toLowerCase()));
    else if (Array.isArray(h)) for (const [k] of h) seen.push(String(k).toLowerCase());
    else for (const k of Object.keys(h)) seen.push(k.toLowerCase());
  }
  if (input && typeof input === "object" && input.headers && typeof input.headers.forEach === "function")
    input.headers.forEach((_v, k) => seen.push(String(k).toLowerCase()));
  return seen.some((k) => HEADER_NAMES.includes(k));
}

function urlOf(input) {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input?.url ?? null;
}

// ---------------------------------------------------------------------------
// Sentinel escalation, with a per-payTo verdict cache.
// ---------------------------------------------------------------------------

export function createSentinelEscalation(cfg) {
  if (!cfg || cfg.on === "never") return null;
  const { on = "new-payto", live = true, payerKey, agentId, strict = false, ttlMs = 24 * 3600_000, maxChecksPerHour = 50 } = cfg;
  const cache = new Map(); // canon payTo -> {ts, verdict}
  const MAX_CACHE = 5000;
  // Every escalation spends the AGENT's money. `payto_rotation` blocks the deliberate flood,
  // but this is the backstop for any other way the "never seen this address" branch gets hit
  // repeatedly — a spend ceiling, so the safety feature can never become the drain.
  let windowStart = 0;
  let checksInWindow = 0;

  return async function escalate({ payTo, amount, resourceUrl, network, firstSeen }) {
    if (on === "new-payto" && !firstSeen) return null;
    const key = canonAddress(payTo);
    const hit = cache.get(key);
    if (hit && Date.now() - hit.ts < ttlMs) return hit.verdict;

    const now = Date.now();
    if (now - windowStart > 3600_000) {
      windowStart = now;
      checksInWindow = 0;
    }
    if (++checksInWindow > maxChecksPerHour) {
      // Stop SPENDING, don't stop the agent: the local policy already cleared this payment,
      // and blocking here would let a hostile seller cause a denial of service just by
      // exhausting the check budget.
      return { decision: "allow", signals: [{ signal: "sentinel_rate_capped", severity: "info", detail: `escalation budget of ${maxChecksPerHour}/h reached` }], degraded: true };
    }

    let verdict;
    try {
      verdict = await assessPayment(
        {
          agent_id: agentId,
          payment: { payto_address: payTo, amount: String(amount ?? ""), asset: "USDC", resource_url: resourceUrl ?? undefined },
          context: { source: "x402-challenge", network },
        },
        { live, payerKey },
      );
    } catch (err) {
      // The escalation is an ADD-ON to checks that already passed locally. Failing closed
      // here would mean 402Sentinel being unreachable stops an agent the local policy already
      // cleared — so the default is to fall through to that verdict and say so in a signal.
      // `sentinel.strict: true` opts into treating unreachability as a hard stop.
      if (strict)
        return { decision: "block", signals: [{ signal: "sentinel_unreachable", severity: "block", detail: String(err?.message ?? err) }] };
      return { decision: "allow", signals: [{ signal: "sentinel_unreachable", severity: "info", detail: String(err?.message ?? err) }], degraded: true };
    }
    // Only cache a verdict we actually got; never cache a degraded fallback, or one outage
    // would mint a 24h "allow" for an address nobody ever checked.
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value);
    cache.set(key, { ts: Date.now(), verdict });
    return verdict;
  };
}

// ---------------------------------------------------------------------------
// Core: vet one 402 challenge.
// ---------------------------------------------------------------------------

/**
 * @returns {{allow:boolean, payable:Array, signals:Array, detail:string}}
 */
export async function vetChallenge(policy, norm, escalate, registry) {
  const signals = [];
  const payable = [];
  let hardDetail = null;

  // A challenge that advertises a different host than the one that served it is claiming to
  // be somebody else — the setup for borrowing (or poisoning) another seller's payTo pin.
  const realHost = hostOf(norm.resourceUrl);
  const claimedHost = hostOf(norm.advertisedUrl);
  if (realHost && claimedHost && realHost !== claimedHost) {
    const detail = `challenge served by ${realHost} claims to be ${claimedHost}`;
    signals.push({ signal: "resource_host_mismatch", severity: "block", kind: "counterparty", detail });
    return { allow: false, payable: [], signals, detail };
  }

  for (const acc of norm.accepts) {
    const res = policy.evaluate({ payTo: acc.payTo, amount: acc.amount, network: acc.network, resourceUrl: norm.resourceUrl });
    for (const s of res.signals) signals.push({ ...s, network: acc.network });
    if (res.decision === "block") {
      // A counterparty failure is not repaired by picking the other rail: the seller itself
      // is what failed. Stop, rather than quietly paying via whichever option still passes.
      // Both rails usually fail for the SAME reason (one price, one seller), so joining the
      // per-option details verbatim prints the same sentence twice at the user.
      hardDetail = hardDetail ? (hardDetail.includes(res.detail) ? hardDetail : `${hardDetail}; ${res.detail}`) : res.detail;
      continue;
    }
    if (res.decision === "skip") continue;
    payable.push({ acc, firstSeen: res.signals.some((s) => s.signal === "payto_first_seen") });
  }

  if (hardDetail) return { allow: false, payable: [], signals, detail: hardDetail };
  if (!payable.length)
    return { allow: false, payable: [], signals, detail: "no payment option satisfies the policy (all filtered by network/scheme rules)" };

  // Free, opt-in: is this payTo the one the seller registered in Bazaar? Runs on new payees only
  // (the pin covers the rest) and BEFORE the paid escalation, so a mismatch never costs a check.
  if (registry) {
    for (const p of payable) {
      const r = await registry({ resourceUrl: norm.resourceUrl, payTo: p.acc.payTo, firstSeen: p.firstSeen });
      if (!r) continue;
      for (const s of r.signals ?? []) signals.push({ ...s, source: "bazaar-registry", network: p.acc.network });
      if (r.decision === "block") {
        const d = r.signals?.[0]?.detail ?? "payee not registered";
        hardDetail = hardDetail ? (hardDetail.includes(d) ? hardDetail : `${hardDetail}; ${d}`) : d;
      }
    }
    if (hardDetail) return { allow: false, payable: [], signals, detail: hardDetail };
  }

  if (escalate) {
    const remaining = [];
    for (const p of payable) {
      const verdict = await escalate({
        payTo: p.acc.payTo,
        amount: p.acc.amount,
        network: p.acc.network,
        resourceUrl: norm.resourceUrl,
        firstSeen: p.firstSeen,
      });
      if (!verdict) {
        remaining.push(p);
        continue;
      }
      for (const s of verdict.signals ?? []) signals.push({ ...s, source: "402sentinel", network: p.acc.network });
      if (verdict.decision === "allow") remaining.push(p);
      else hardDetail = hardDetail ? `${hardDetail}; 402Sentinel ${verdict.decision}` : `402Sentinel ${verdict.decision}: ${(verdict.signals ?? []).map((s) => s.signal).join(", ") || "policy"}`;
    }
    if (hardDetail) return { allow: false, payable: [], signals, detail: hardDetail };
    if (!remaining.length) return { allow: false, payable: [], signals, detail: "402Sentinel cleared no payment option" };
    payable.length = 0;
    payable.push(...remaining);
  }

  return { allow: true, payable, signals, detail: "ok" };
}

// ---------------------------------------------------------------------------
// The adapters.
// ---------------------------------------------------------------------------

/**
 * Wrap a fetch so that any 402 it returns is vetted before the x402 client can pay it.
 * Pass the result INTO x402-fetch's wrapFetchWithPayment (or any x402 client that takes a fetch).
 *
 * @param baseFetch  the underlying fetch (default: globalThis.fetch)
 * @param opts       policy options (see createPolicy) plus:
 *                     onBlock  — callback instead of throwing (return true to allow anyway)
 *                     sentinel — { on:"new-payto"|"always"|"never", live, payerKey, agentId }
 *                     registry — true | { on, strict, endpoint, timeoutMs }: free Bazaar payee check on
 *                                new payees (see registry.mjs). Opt-in: it calls 402sentinel.com.
 *                     policy   — reuse an existing policy object
 */
export function guardedFetch(baseFetch = globalThis.fetch, opts = {}) {
  const policy = opts.policy ?? createPolicy(opts);
  if (baseFetch?.[GUARD_FETCH] === policy) return baseFetch; // already guarded by this policy
  const escalate = createSentinelEscalation(opts.sentinel);
  const registry = createRegistryCheck(opts.registry);
  // url -> {payTo, amount, network, resourceUrl}, awaiting its paid retry. Bounded: a client
  // that abandons challenges (or is blocked upstream) would otherwise grow this forever.
  const pending = new Map();

  async function guarded(input, init) {
    const url = urlOf(input);
    const isRetry = requestHasPaymentHeader(input, init);
    const response = await baseFetch(input, init);

    if (isRetry) {
      // The payment went out and was accepted — only now is it real spend, and only now is
      // the payTo confirmed as one this agent actually transacted with.
      const rec = pending.get(url);
      if (rec && response.status < 400) {
        policy.commit(rec);
        pending.delete(url);
      }
      return response;
    }

    if (response.status !== 402) return response;

    // Read the challenge WITHOUT consuming the body: x402-fetch calls response.json() on
    // this same object, and a consumed body would break every payment we allow.
    let bodyText = null;
    try {
      bodyText = await response.clone().text();
    } catch {
      bodyText = null;
    }
    // response.url is where the 402 ACTUALLY came from (after any redirect) — that, not the
    // URL we asked for and not the challenge body, is the counterparty being paid.
    const norm = normalizeChallenge({ headers: response.headers, body: bodyText, requestUrl: response.url || url });
    if (!norm) return response; // a 402 we can't parse is not a payment we can vet — leave it to the client

    const verdict = await vetChallenge(policy, norm, escalate, registry);
    if (!verdict.allow) {
      const override = opts.onBlock
        ? await opts.onBlock({ ...verdict, resourceUrl: norm.resourceUrl, accepts: norm.accepts })
        : false;
      if (override !== true) throw new PaymentBlockedError("block", verdict.signals, verdict.detail);
    }

    // On an onBlock override there is no vetted option, so there is nothing to pre-record:
    // the human took the call, and budget/pin state deliberately does not learn from it.
    const chosen = verdict.payable[0]?.acc;
    if (chosen) {
      if (pending.size >= MAX_PENDING) pending.delete(pending.keys().next().value);
      pending.set(url, { payTo: chosen.payTo, amount: chosen.amount, network: chosen.network, resourceUrl: norm.resourceUrl });
    }
    if (opts.onAllow) {
      try {
        opts.onAllow({ ...verdict, resourceUrl: norm.resourceUrl });
      } catch {
        /* a logger must never break a payment */
      }
    }
    return response;
  };

  guarded[GUARD_FETCH] = policy;
  return guarded;
}

/**
 * A synchronous paymentRequirementsSelector that drops every option the policy rejects
 * before the x402 client can choose one. Works for BOTH x402-fetch and x402-axios, which
 * is why it exists alongside guardedFetch — axios never touches fetch, but it does take a
 * selector. Local checks only: the selector is sync, so it cannot await 402Sentinel.
 */
export function guardSelector(opts = {}, innerSelector) {
  const policy = opts.policy ?? createPolicy(opts);
  return function select(paymentRequirements, network, scheme) {
    const kept = [];
    let hardDetail = null;
    const signals = [];
    for (const req of paymentRequirements) {
      const amount = normalizeChallenge({ body: { accepts: [req] } })?.accepts?.[0]?.amount ?? null;
      const res = policy.evaluate({ payTo: req.payTo, amount, network: req.network, resourceUrl: opts.resourceUrl ?? req.resource });
      signals.push(...res.signals);
      if (res.decision === "block") hardDetail = hardDetail ? `${hardDetail}; ${res.detail}` : res.detail;
      else if (res.decision === "allow") kept.push(req);
    }
    if (hardDetail) throw new PaymentBlockedError("block", signals, hardDetail);
    if (!kept.length) throw new PaymentBlockedError("block", signals, "no payment option satisfies the policy");
    return innerSelector ? innerSelector(kept, network, scheme) : kept[0];
  };
}

/**
 * Full drop-in for x402-fetch's wrapFetchWithPayment — same positional arguments, with the
 * guard already inserted. Lazily imports x402-fetch so this package stays dependency-free
 * for anyone using guardedFetch/guardSelector on their own client.
 */
export async function wrapFetchWithPaymentGuard(fetchImpl, walletClient, opts = {}, maxValue, selector, config) {
  let wrapFetchWithPayment;
  try {
    ({ wrapFetchWithPayment } = await import("x402-fetch"));
  } catch {
    throw new Error("wrapFetchWithPaymentGuard needs x402-fetch installed: npm i x402-fetch");
  }
  const policy = opts.policy ?? createPolicy(opts);
  return wrapFetchWithPayment(
    guardedFetch(fetchImpl ?? globalThis.fetch, { ...opts, policy }),
    walletClient,
    maxValue,
    selector ? guardSelector({ ...opts, policy }, selector) : guardSelector({ ...opts, policy }),
    config,
  );
}

/**
 * Guard an axios instance that x402-axios' withPaymentInterceptor is (or will be) attached to.
 * Wraps the adapter, so the 402 is vetted before any interceptor — including x402's — sees it.
 * Call this BEFORE withPaymentInterceptor.
 *
 * Async, because `defaults.adapter` on a real axios instance is a list of adapter NAMES
 * (`["xhr","http","fetch"]`), not a function — resolving it needs axios' own `getAdapter`,
 * which has to be imported.
 */
export async function guardAxios(axiosInstance, opts = {}) {
  const policy = opts.policy ?? createPolicy(opts);
  const escalate = createSentinelEscalation(opts.sentinel);
  const registry = createRegistryCheck(opts.registry);

  // Re-wrap the ORIGINAL adapter, never a guard we installed earlier.
  const installed = axiosInstance.defaults.adapter;
  const configured = installed?.[GUARD_MARK] ?? installed;
  let resolved;
  if (typeof configured === "function") {
    resolved = configured;
  } else {
    let getAdapter;
    try {
      ({ getAdapter } = await import("axios"));
    } catch {
      throw new Error("guardAxios needs axios installed: npm i axios");
    }
    if (typeof getAdapter !== "function")
      throw new Error("guardAxios: this axios build exposes no getAdapter — pass guardSelector(opts) to withPaymentInterceptor instead");
    resolved = getAdapter(configured);
  }

  const pending = new Map(); // full URL -> the vetted option awaiting its paid retry

  axiosInstance.defaults.adapter = async function guardedAdapter(config) {
    // x402-axios retries the SAME config with a payment header. That retry is the only
    // point where money has actually moved, so — as in guardedFetch — budgets and pins are
    // committed there and not on the challenge, or a payment that fails still eats budget.
    const retryFor = pendingKey(config);
    const isRetry = configHasPaymentHeader(config);

    // axios' adapters apply `validateStatus` themselves, so a 402 arrives here as a THROWN
    // AxiosError carrying `.response` — not as a return value. And it must keep arriving that
    // way: x402-axios hooks the response ERROR interceptor, so swallowing the rejection here
    // would disable payments entirely. Unwrap it, vet it, then re-throw it untouched.
    let res;
    let thrown = null;
    try {
      res = await resolved(config);
    } catch (err) {
      if (!err?.response) throw err; // a transport failure, not a status rejection
      thrown = err;
      res = err.response;
    }
    const passThrough = () => {
      if (thrown) throw thrown;
      return res;
    };

    if (isRetry) {
      const rec = pending.get(retryFor);
      if (rec && res?.status < 400) {
        policy.commit(rec);
        pending.delete(retryFor);
      }
      return passThrough();
    }
    if (res?.status !== 402) return passThrough();

    const headers = {
      get: (k) => {
        const h = res.headers;
        if (!h) return null;
        if (typeof h.get === "function") return h.get(k) ?? null;
        return h[k] ?? h[String(k).toLowerCase()] ?? null;
      },
    };
    const norm = normalizeChallenge({
      headers,
      body: res.data,
      requestUrl: res.request?.res?.responseUrl || absoluteUrl(config),
    });
    if (!norm) return passThrough();

    const verdict = await vetChallenge(policy, norm, escalate, registry);
    if (!verdict.allow) {
      const override = opts.onBlock ? await opts.onBlock({ ...verdict, resourceUrl: norm.resourceUrl, accepts: norm.accepts }) : false;
      if (override !== true) throw new PaymentBlockedError("block", verdict.signals, verdict.detail);
      return passThrough(); // human took the call; nothing vetted to pre-record
    }
    if (opts.onAllow) {
      try {
        opts.onAllow({ ...verdict, resourceUrl: norm.resourceUrl });
      } catch {
        /* a logger must never break a payment */
      }
    }

    const chosen = verdict.payable[0].acc;
    if (pending.size >= MAX_PENDING) pending.delete(pending.keys().next().value);
    pending.set(retryFor, { payTo: chosen.payTo, amount: chosen.amount, network: chosen.network, resourceUrl: norm.resourceUrl });
    return passThrough();
  };
  axiosInstance.defaults.adapter[GUARD_MARK] = configured;

  return axiosInstance;
}

function configHasPaymentHeader(config) {
  const h = config?.headers;
  if (!h) return false;
  const names = typeof h.toJSON === "function" ? Object.keys(h.toJSON()) : Object.keys(h);
  return names.some((k) => HEADER_NAMES.includes(String(k).toLowerCase()));
}

function pendingKey(config) {
  return absoluteUrl(config) ?? config?.url ?? "";
}

/** axios splits baseURL and url; the guard must key and pin on the full destination. */
function absoluteUrl(config) {
  const u = config?.url ?? "";
  const base = config?.baseURL ?? "";
  if (!base) return u || null;
  try {
    return new URL(u, base).href;
  } catch {
    return u || base || null;
  }
}
