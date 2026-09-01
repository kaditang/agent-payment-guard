// Local, zero-network payment policy — the part of the gate that must be FREE and instant.
//
// Everything here runs in-process with no dependencies and no calls out, because a check
// that costs money or latency on EVERY payment will simply be turned off. The paid
// 402Sentinel firewall is an *escalation* on top of this (see x402.mjs), not the default.
//
// The signal that earns its keep with no network at all is `payto_changed`: an x402 seller's
// payTo for a given resource is stable for months, so the first one seen is pinned
// (trust-on-first-use) and a later change is exactly the shape of a hijacked or spoofed
// resource — the one failure that empties a wallet silently.
//
// Pins are keyed per host + PATH + rail, not per host. Real sellers split collection by
// product line: blockrun.ai pays /exa/* and /defillama/* to one address, /pm/* to a second and
// /surf/* to a third, all on Base. A host-level pin calls the second and third endpoint a
// hijack and hard-blocks them — verified against the live BlockRun catalog, 2 of 4 endpoints
// wrongly blocked. Host-level movement is still watched, by `payto_rotation` below.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";

export class PaymentBlockedError extends Error {
  constructor(decision, signals, detail) {
    super(`agent-payment-guard: ${decision.toUpperCase()} — ${detail}`);
    this.name = "PaymentBlockedError";
    this.decision = decision;
    this.signals = signals;
    this.detail = detail;
  }
}

// ---------------------------------------------------------------------------
// Challenge normalisation. Two protocol shapes are live in the wild and a guard
// that understands only one silently waves the other through, so both are pinned
// here against real captured challenges (see test-x402.mjs):
//   v2 — base64 JSON in the `payment-required` header, accepts[].amount, CAIP-2 network
//   v1 — JSON body, accepts[].maxAmountRequired, short network names ("base")
// ---------------------------------------------------------------------------

// `0[xX]`, not `0x`: a deny list is written by hand, so it arrives checksummed or fully
// upper-cased. Anchoring on a lowercase prefix made those entries fail the EVM test, skip
// canonicalisation, and silently never match — a deny list that quietly does nothing.
const EVM_ADDR = /^0[xX][0-9a-fA-F]{40}$/;

/** EVM addresses are case-insensitive; base58 Solana addresses are NOT. Never lowercase blindly. */
export function canonAddress(a) {
  const s = String(a ?? "");
  return EVM_ADDR.test(s) ? s.toLowerCase() : s;
}

function toAmount(raw, extra) {
  if (raw == null) return null;
  let units;
  try {
    units = BigInt(String(raw));
  } catch {
    return null;
  }
  const decimals = Number(extra?.decimals ?? 6);
  if (!Number.isFinite(decimals) || decimals < 0 || decimals > 36) return null;
  return Number(units) / 10 ** decimals;
}

/** @returns {{x402Version:number, resourceUrl:string|null, accepts:Array}|null} */
export function normalizeChallenge({ headers, body, requestUrl } = {}) {
  let doc = null;
  const hdr = typeof headers?.get === "function" ? headers.get("payment-required") : null;
  if (hdr) {
    try {
      doc = JSON.parse(Buffer.from(hdr, "base64").toString("utf8"));
    } catch {
      doc = null;
    }
  }
  if (!doc && body) {
    try {
      doc = typeof body === "string" ? JSON.parse(body) : body;
    } catch {
      doc = null;
    }
  }
  if (!doc || !Array.isArray(doc.accepts)) return null;

  const accepts = doc.accepts.map((a) => ({
    scheme: a.scheme ?? null,
    network: a.network ?? null,
    payTo: a.payTo ?? a.payto ?? a.pay_to ?? null,
    asset: a.asset ?? null,
    // v2 calls it `amount`, v1 calls it `maxAmountRequired`. `?? null` (not `||`) so a
    // legitimate "0" is kept rather than falling through to the other field.
    amount: toAmount(a.amount ?? a.maxAmountRequired ?? null, a.extra),
    raw: a,
  }));
  // `resource.url` inside the challenge is written by the SERVER — i.e. it is attacker
  // controlled. Deriving the pin/policy host from it lets any host claim to be any other:
  // evil.example serves a challenge that says `resource.url: https://honest-seller.example`
  // and its payTo is written into the honest seller's pin. So the host used for policy is
  // always the URL we actually requested; the advertised one is kept only to compare.
  const advertisedUrl = doc.resource?.url ?? (typeof doc.resource === "string" ? doc.resource : null) ?? null;
  return {
    x402Version: doc.x402Version ?? 1,
    resourceUrl: requestUrl ?? advertisedUrl ?? null,
    advertisedUrl,
    accepts,
  };
}

// ---------------------------------------------------------------------------
// Trust-on-first-use payTo pin store.
// ---------------------------------------------------------------------------

const DEFAULT_PIN_FILE = join(homedir(), ".agent-payment-guard", "pins.json");
const MAX_PINS = 2000;

export function createPinStore({ file = DEFAULT_PIN_FILE, persist = true } = {}) {
  let pins = Object.create(null);
  let loaded = false;

  function load() {
    if (loaded) return;
    loaded = true;
    if (!persist) return;
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8"));
      // Null-prototype: the pin file is data on disk, and a `__proto__` key in it must not
      // reach Object.prototype through the plain `pins[key]` reads and writes below.
      if (parsed && typeof parsed === "object") pins = Object.assign(Object.create(null), parsed);
    } catch {
      // No pin file yet (or an unreadable one) — start empty. A missing pin store must
      // never block payments; it just means nothing is pinned yet.
    }
  }

  function save() {
    if (!persist) return;
    try {
      const keys = Object.keys(pins);
      if (keys.length > MAX_PINS) {
        // Bound the file: keep the most recently seen. Unbounded growth on an agent that
        // pays thousands of hosts would turn every startup into a large synchronous read.
        const trimmed = Object.create(null);
        for (const k of keys.sort((a, b) => (pins[b].seen ?? 0) - (pins[a].seen ?? 0)).slice(0, MAX_PINS)) trimmed[k] = pins[k];
        pins = trimmed;
      }
      mkdirSync(dirname(file), { recursive: true });
      // Write-then-rename: a crash mid-write must not leave a truncated pin file, which
      // would silently drop every pin and disarm the check.
      const tmp = `${file}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(pins), { mode: 0o600 });
      renameSync(tmp, file);
    } catch {
      // Persistence is best-effort; an unwritable home dir degrades to in-process pins.
    }
  }

  return {
    /**
     * `key` comes from pinKey(): host + path + rail. Host alone is wrong twice over — a
     * seller publishes a different payTo per rail (Base vs Solana), and per product line
     * (see the BlockRun note at the top of this file).
     * @returns {{status:"new"|"match"|"changed", pinned?:string}}
     */
    check(key, payTo) {
      load();
      const canon = canonAddress(payTo);
      const prev = pins[key];
      if (!prev) return { status: "new" };
      return prev.payTo === canon ? { status: "match", pinned: prev.payTo } : { status: "changed", pinned: prev.payTo };
    },
    record(key, payTo) {
      load();
      pins[key] = { payTo: canonAddress(payTo), seen: Date.now() };
      save();
    },
    /** Deliberate re-pin after a human has verified the new address. */
    trust(key, payTo) {
      this.record(key, payTo);
    },
    all() {
      load();
      return { ...pins };
    },
  };
}

// ---------------------------------------------------------------------------
// The policy engine.
// ---------------------------------------------------------------------------

const HOUR = 3600_000;
const DAY = 86_400_000;

export function createPolicy(opts = {}) {
  const {
    maxAmount = 1.0,
    hourlyBudget = null,
    dailyBudget = null,
    allow = null,
    deny = [],
    networks = null,
    requireHttps = true,
    pinPayTo = true,
    pinStore = createPinStore(opts.pins ?? {}),
    onSignal = null,
  } = opts;

  // A host that presents a DIFFERENT payTo on nearly every challenge is not a counterparty
  // worth paying to investigate — the rotation itself is the strongest fraud signal there is,
  // and treating it as "another new address to check" is what lets one hostile seller bill the
  // agent for an unbounded number of $0.002 firewall calls.
  // 8, not 3: a legitimate seller can run several collection addresses across its endpoints
  // (BlockRun runs four). An attacker minting a fresh address per challenge blows past this
  // in seconds, so the ceiling still bites where it matters.
  const maxNewPayToPerHost = opts.maxNewPayToPerHost ?? 8;
  const rotation = new Map(); // host -> { since, addrs:Set }
  const ROTATION_WINDOW = 3600_000;

  const denySet = new Set(deny.map(canonAddress));
  const allowSet = allow ? new Set(allow.map(canonAddress)) : null;
  const spend = []; // [{ts, amount}] — in-process; a budget is per-run, not global state.
  const tracksSpend = hourlyBudget != null || dailyBudget != null;

  function spentSince(windowMs) {
    const cut = Date.now() - windowMs;
    while (spend.length && spend[0].ts < cut) spend.shift();
    return spend.reduce((s, e) => s + e.amount, 0);
  }

  return {
    /**
     * Evaluate one selected payment option. Pure + synchronous, so it can run inside
     * x402's synchronous paymentRequirementsSelector as well as in the async fetch path.
     * @returns {{decision:"allow"|"skip"|"block", signals:Array, detail:string}}
     */
    evaluate({ payTo, amount, network, resourceUrl }) {
      const signals = [];
      const canon = canonAddress(payTo);
      const host = hostOf(resourceUrl);

      if (!canon) signals.push({ signal: "missing_payto", severity: "block", kind: "counterparty", detail: "challenge has no payTo" });

      if (denySet.has(canon)) signals.push({ signal: "denylisted_payto", severity: "block", kind: "counterparty", detail: `payTo ${short(canon)} is on the deny list` });

      if (allowSet && canon && !allowSet.has(canon))
        signals.push({ signal: "not_allowlisted", severity: "block", kind: "counterparty", detail: `payTo ${short(canon)} is not on the allow list` });

      if (networks && network && !networks.includes(network))
        signals.push({ signal: "network_not_allowed", severity: "block", kind: "selection", detail: `network ${network} is not in the allowed set` });

      // The loopback exemption must terminate at a host boundary: a bare `^http://localhost`
      // prefix also matches `http://localhost.evil.example`, which is a plain-HTTP bypass.
      if (requireHttps && resourceUrl && /^http:\/\//i.test(resourceUrl) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|\?|#|$)/i.test(resourceUrl))
        signals.push({ signal: "insecure_transport", severity: "block", kind: "counterparty", detail: `resource ${resourceUrl} is plaintext HTTP — the challenge can be rewritten in flight` });

      if (amount == null) {
        // An unparseable price means the cap cannot be enforced. Treat that as a block:
        // waving it through is precisely the case where an overcharge would land.
        signals.push({ signal: "amount_unparseable", severity: "block", kind: "counterparty", detail: "challenge amount could not be parsed — cap not enforceable" });
      } else {
        if (amount > maxAmount)
          signals.push({ signal: "amount_over_cap", severity: "block", kind: "counterparty", detail: `$${amount} exceeds maxAmount $${maxAmount}` });
        if (hourlyBudget != null && spentSince(HOUR) + amount > hourlyBudget)
          signals.push({ signal: "hourly_budget", severity: "block", kind: "counterparty", detail: `$${(spentSince(HOUR) + amount).toFixed(4)} would exceed hourly budget $${hourlyBudget}` });
        if (dailyBudget != null && spentSince(DAY) + amount > dailyBudget)
          signals.push({ signal: "daily_budget", severity: "block", kind: "counterparty", detail: `$${(spentSince(DAY) + amount).toFixed(4)} would exceed daily budget $${dailyBudget}` });
      }

      if (pinPayTo && host && canon) {
        const pin = pinStore.check(pinKey(resourceUrl, network), canon);
        if (pin.status === "changed")
          signals.push({
            signal: "payto_changed",
            severity: "block",
            kind: "counterparty",
            detail: `${host} previously paid ${short(pin.pinned)}, now asks for ${short(canon)} — re-pin with trustPayTo() if this is a legitimate rotation`,
          });
        else if (pin.status === "new") {
          signals.push({ signal: "payto_first_seen", severity: "info", detail: `first payment to ${host}` });
          let r = rotation.get(host);
          if (!r || Date.now() - r.since > ROTATION_WINDOW) {
            r = { since: Date.now(), addrs: new Set() };
            rotation.set(host, r);
            if (rotation.size > 1000) rotation.delete(rotation.keys().next().value);
          }
          r.addrs.add(canon);
          if (r.addrs.size > maxNewPayToPerHost)
            signals.push({
              signal: "payto_rotation",
              severity: "block",
              kind: "counterparty",
              detail: `${host} has presented ${r.addrs.size} different payTo addresses in the last hour`,
            });
        }
      }

      // `counterparty` failures mean this payment is unsafe on any rail — hard block.
      // `selection` failures only mean "don't pay THIS option"; the caller drops the option
      // and blocks solely when nothing payable is left (see x402.mjs).
      const blocked = signals.filter((s) => s.severity === "block");
      const hard = blocked.filter((s) => s.kind !== "selection");
      const decision = hard.length ? "block" : blocked.length ? "skip" : "allow";
      const detail = blocked.length ? blocked.map((s) => s.detail).join("; ") : "ok";
      if (onSignal) {
        try {
          onSignal({ decision, signals, payTo: canon, amount, network, resourceUrl });
        } catch {
          // A caller's logger must never break a payment.
        }
      }
      return { decision, signals, detail };
    },

    /** Called only after a payment is actually authorised, so budgets track real spend. */
    commit({ payTo, amount, network, resourceUrl }) {
      // Only accumulate when a budget actually reads it. `spentSince` is what prunes the
      // array, and it never runs without a budget configured — so an unbudgeted long-running
      // agent would grow this forever.
      if (amount != null && tracksSpend) {
        spend.push({ ts: Date.now(), amount });
        if (spend.length > 100_000) spend.splice(0, spend.length - 100_000);
      }
      const host = hostOf(resourceUrl);
      if (pinPayTo && host && payTo) pinStore.record(pinKey(resourceUrl, network), payTo);
    },

    trustPayTo(resourceUrl, payTo, network) {
      if (hostOf(resourceUrl)) pinStore.trust(pinKey(resourceUrl, network), payTo);
    },

    pins: pinStore,
  };
}

/**
 * host + path + rail. The query string is deliberately excluded: `?since=30` and `?since=60`
 * are the same resource with the same payTo, and keying on the full URL would mint a fresh
 * "first seen" pin per parameter value — pinning nothing at all.
 */
export function pinKey(url, network) {
  const rail = network ?? "?";
  try {
    const u = new URL(String(url));
    return `${u.host}${u.pathname}|${rail}`;
  } catch {
    return `${hostOf(url) ?? String(url)}|${rail}`;
  }
}

export function hostOf(url) {
  try {
    return new URL(String(url)).host;
  } catch {
    return null;
  }
}

function short(a) {
  const s = String(a ?? "");
  return s.length > 12 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s;
}
