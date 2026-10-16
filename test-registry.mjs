import test from "node:test";
import assert from "node:assert/strict";
import { vetChallenge, guardedFetch, PaymentBlockedError } from "./x402.mjs";
import { createPolicy, normalizeChallenge } from "./policy.mjs";
import { createRegistryCheck } from "./registry.mjs";

const PAYTO = "0x1A9Fa76f5b420e85DE147C4419638BEbE64D6dE5";
const DOC = {
  x402Version: 2,
  resource: { url: "https://seller.example/api/data" },
  accepts: [{ scheme: "exact", network: "eip155:8453", amount: "2000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: PAYTO }],
};
const NO_PINS = () => ({ pins: { persist: false } });
const norm = () => normalizeChallenge({ body: DOC });

// A fake /api/payee that answers `verdict` and records what it was asked.
function registryFetch(verdict, calls = []) {
  return async (url) => {
    calls.push(String(url));
    if (verdict instanceof Error) throw verdict;
    if (typeof verdict === "number") return new Response("x", { status: verdict });
    return Response.json({ verdict, listed_payees: [{ payto: "0xrealpayee" }], how_to_read: "ok" });
  };
}

test("not_listed and previously_listed block the first payment", async () => {
  for (const v of ["not_listed", "previously_listed"]) {
    const reg = createRegistryCheck({ fetch: registryFetch(v) });
    const r = await vetChallenge(createPolicy(NO_PINS()), norm(), null, reg);
    assert.equal(r.allow, false, v);
    assert.match(r.detail, /registered 0xrealpayee in Bazaar/);
    assert.ok(r.signals.some((s) => s.signal === `payee_${v}` && s.source === "bazaar-registry"));
  }
});

test("registered, other-path and unknown hosts are allowed with an info signal", async () => {
  for (const v of ["listed_for_resource", "listed_for_host", "unknown_host"]) {
    const reg = createRegistryCheck({ fetch: registryFetch(v) });
    const r = await vetChallenge(createPolicy(NO_PINS()), norm(), null, reg);
    assert.equal(r.allow, true, v);
    assert.ok(r.signals.some((s) => s.signal === `payee_${v}` && s.severity === "info"));
  }
});

test("asks with url + payto only (no network: Bazaar names chains inconsistently)", async () => {
  const calls = [];
  await vetChallenge(createPolicy(NO_PINS()), norm(), null, createRegistryCheck({ fetch: registryFetch("listed_for_resource", calls) }));
  const u = new URL(calls[0]);
  assert.equal(u.origin + u.pathname, "https://402sentinel.com/api/payee");
  assert.equal(u.searchParams.get("url"), "https://seller.example/api/data");
  assert.equal(u.searchParams.get("payto"), PAYTO);
  assert.equal(u.searchParams.get("network"), null);
});

test("an outage fails open by default and closed with strict", async () => {
  for (const bad of [new Error("ECONNREFUSED"), 503]) {
    const open = await vetChallenge(createPolicy(NO_PINS()), norm(), null, createRegistryCheck({ fetch: registryFetch(bad) }));
    assert.equal(open.allow, true);
    assert.ok(open.signals.some((s) => s.signal === "registry_unreachable"));
    const closed = await vetChallenge(createPolicy(NO_PINS()), norm(), null, createRegistryCheck({ strict: true, fetch: registryFetch(bad) }));
    assert.equal(closed.allow, false);
  }
});

test("only new payees are checked, results are cached, and it is off unless asked for", async () => {
  assert.equal(createRegistryCheck(undefined), null);
  assert.equal(createRegistryCheck(false), null);
  assert.equal(createRegistryCheck({ on: "never" }), null);
  const calls = [];
  const reg = createRegistryCheck({ fetch: registryFetch("listed_for_resource", calls) });
  assert.equal(await reg({ resourceUrl: "https://seller.example/api/data", payTo: PAYTO, firstSeen: false }), null);
  await reg({ resourceUrl: "https://seller.example/api/data", payTo: PAYTO, firstSeen: true });
  await reg({ resourceUrl: "https://seller.example/api/data", payTo: PAYTO, firstSeen: true });
  assert.equal(calls.length, 1);
});

test("rate cap: past maxChecksPerMinute it stops asking and lets the local verdict stand", async () => {
  const calls = [];
  const reg = createRegistryCheck({ maxChecksPerMinute: 2, fetch: registryFetch("listed_for_resource", calls) });
  for (let i = 0; i < 4; i++) await reg({ resourceUrl: `https://s${i}.example/x`, payTo: PAYTO, firstSeen: true });
  assert.equal(calls.length, 2);
});

test("guardedFetch: a not_listed payee throws before the x402 client can sign", async () => {
  const seller = async () => {
    const headers = new Headers({ "payment-required": Buffer.from(JSON.stringify(DOC)).toString("base64") });
    return new Response("{}", { status: 402, headers });
  };
  const guarded = guardedFetch(seller, { ...NO_PINS(), registry: { fetch: registryFetch("not_listed") } });
  await assert.rejects(() => guarded("https://seller.example/api/data"), PaymentBlockedError);
});
