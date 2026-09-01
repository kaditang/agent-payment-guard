import test from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync, writeFileSync } from "node:fs";
import { guardedFetch, guardSelector, vetChallenge, createSentinelEscalation, PaymentBlockedError } from "./x402.mjs";
import { createPolicy, normalizeChallenge, canonAddress, createPinStore, pinKey } from "./policy.mjs";

// A REAL v2 challenge, captured from https://402sentinel.com/api/firewall. Hand-written
// fixtures are how a guard ends up parsing a shape no server actually emits.
const REAL_V2 = {
  x402Version: 2,
  error: "Payment required",
  resource: { url: "https://402sentinel.com/api/firewall", description: "…", mimeType: "" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:8453",
      amount: "2000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0x1A9Fa76f5b420e85DE147C4419638BEbE64D6dE5",
      maxTimeoutSeconds: 300,
      extra: { name: "USD Coin", version: "2" },
    },
    {
      scheme: "exact",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      amount: "2000",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      payTo: "4uLqY8BnJuA7CFxRork2FnNMu2u9NsJquF8Cc6V5B5jB",
      maxTimeoutSeconds: 300,
      extra: { feePayer: "BENrLoUbndxoNMUS5JXApGMtNykLjFXXixMtpDwDR9SP" },
    },
  ],
};
const V2_PAYTO = REAL_V2.accepts[0].payTo;
const SOL_PAYTO = REAL_V2.accepts[1].payTo;

// The v1 shape x402-fetch@1.2.0 still reads: JSON body, maxAmountRequired, short network.
const REAL_V1 = {
  x402Version: 1,
  accepts: [
    {
      scheme: "exact",
      network: "base",
      maxAmountRequired: "10000",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      payTo: "0xDc9F94A8b93F070B58cfa580cbE740d763005FE6",
      resource: "https://stockwaves.net/api/cn/pulse",
      extra: { name: "USD Coin", version: "2" },
    },
  ],
};

const NO_PINS = () => ({ pins: { persist: false } });

function challenge402(doc, { asHeader = true } = {}) {
  const headers = new Headers({ "content-type": "application/json" });
  if (asHeader) headers.set("payment-required", Buffer.from(JSON.stringify(doc)).toString("base64"));
  return new Response(asHeader ? "{}" : JSON.stringify(doc), { status: 402, headers });
}

// --------------------------------------------------------------------------- parsing

test("parses the real v2 challenge (payment-required header, `amount`, CAIP-2)", () => {
  const n = normalizeChallenge({ headers: challenge402(REAL_V2).headers, body: "{}" });
  assert.equal(n.x402Version, 2);
  assert.equal(n.resourceUrl, "https://402sentinel.com/api/firewall");
  assert.equal(n.accepts.length, 2);
  assert.equal(n.accepts[0].payTo, V2_PAYTO);
  assert.equal(n.accepts[0].amount, 0.002); // 2000 base units / 1e6
  assert.equal(n.accepts[0].network, "eip155:8453");
});

test("parses the v1 challenge (JSON body, `maxAmountRequired`, short network)", () => {
  const n = normalizeChallenge({ headers: new Headers(), body: JSON.stringify(REAL_V1) });
  assert.equal(n.accepts[0].amount, 0.01);
  assert.equal(n.accepts[0].network, "base");
});

test("a zero-priced option is kept as 0, not dropped", () => {
  const n = normalizeChallenge({ body: { accepts: [{ amount: "0", payTo: V2_PAYTO, maxAmountRequired: "999999" }] } });
  assert.equal(n.accepts[0].amount, 0);
});

test("non-numeric amount yields null rather than NaN or 0", () => {
  const n = normalizeChallenge({ body: { accepts: [{ amount: "lots", payTo: V2_PAYTO }] } });
  assert.equal(n.accepts[0].amount, null);
});

test("EVM addresses compare case-insensitively, Solana base58 does NOT", () => {
  assert.equal(canonAddress(V2_PAYTO), V2_PAYTO.toLowerCase());
  assert.equal(canonAddress(SOL_PAYTO), SOL_PAYTO); // lowercasing base58 would be a different key
});

// --------------------------------------------------------------------------- policy

test("payment under the cap to a fresh seller is allowed", async () => {
  const p = createPolicy({ maxAmount: 0.05, ...NO_PINS() });
  const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
  assert.equal(v.allow, true);
});

test("overcharge above maxAmount is blocked", async () => {
  const p = createPolicy({ maxAmount: 0.001, ...NO_PINS() });
  const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "amount_over_cap"));
});

test("unparseable amount blocks — an unenforceable cap is not a passing cap", async () => {
  const p = createPolicy({ maxAmount: 1, ...NO_PINS() });
  const v = await vetChallenge(p, normalizeChallenge({ body: { accepts: [{ amount: "??", payTo: V2_PAYTO, network: "eip155:8453" }] } }), null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "amount_unparseable"));
});

// A deny list is hand-written, so it arrives in whatever case the human copied. All three
// spellings of the same address must match, or the list silently protects nothing.
for (const [label, spelling] of [
  ["checksummed", V2_PAYTO],
  ["lower-case", V2_PAYTO.toLowerCase()],
  ["0X-prefixed upper-case", V2_PAYTO.toUpperCase()],
]) {
  test(`denylisted payTo (${label}) blocks even though the other rail is clean`, async () => {
    const p = createPolicy({ maxAmount: 1, deny: [spelling], ...NO_PINS() });
    const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
    assert.equal(v.allow, false, "a bad seller is not repaired by paying it on Solana instead");
    assert.ok(v.signals.some((s) => s.signal === "denylisted_payto"));
  });
}

test("network filter narrows options instead of blocking", async () => {
  const p = createPolicy({ maxAmount: 1, networks: ["eip155:8453"], ...NO_PINS() });
  const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
  assert.equal(v.allow, true);
  assert.equal(v.payable.length, 1);
  assert.equal(v.payable[0].acc.network, "eip155:8453");
});

test("network filter that leaves nothing payable blocks", async () => {
  const p = createPolicy({ maxAmount: 1, networks: ["eip155:1"], ...NO_PINS() });
  const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
  assert.equal(v.allow, false);
});

test("plaintext http resource is blocked (the challenge is rewritable in flight)", async () => {
  const doc = { accepts: [{ amount: "1000", payTo: V2_PAYTO, network: "eip155:8453" }], resource: { url: "http://evil.test/x" } };
  const v = await vetChallenge(createPolicy({ maxAmount: 1, ...NO_PINS() }), normalizeChallenge({ body: doc }), null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "insecure_transport"));
});

test("budget counts only committed spend, and blocks the call that would exceed it", async () => {
  const p = createPolicy({ maxAmount: 1, dailyBudget: 0.005, ...NO_PINS() });
  const norm = normalizeChallenge({ body: REAL_V2 });
  assert.equal((await vetChallenge(p, norm, null)).allow, true);
  p.commit({ payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl });
  p.commit({ payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl });
  const v = await vetChallenge(p, norm, null); // 0.004 spent + 0.002 = 0.006 > 0.005
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "daily_budget"));
});

// --------------------------------------------------------------------------- payTo pinning

test("payTo pin is per host+network, so a two-rail seller does not flap", async () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-a.json`);
  rmSync(file, { force: true });
  const p = createPolicy({ maxAmount: 1, pins: { file } });
  const norm = normalizeChallenge({ body: REAL_V2 });
  p.commit({ payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl });
  p.commit({ payTo: SOL_PAYTO, amount: 0.002, network: REAL_V2.accepts[1].network, resourceUrl: norm.resourceUrl });
  const v = await vetChallenge(createPolicy({ maxAmount: 1, pins: { file } }), norm, null);
  assert.equal(v.allow, true, "both rails pinned to their own payTo — neither should look changed");
  assert.equal(v.signals.filter((s) => s.signal === "payto_changed").length, 0);
  rmSync(file, { force: true });
});

test("a seller that swaps its payTo is blocked (the hijack case)", async () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-b.json`);
  rmSync(file, { force: true });
  const norm = normalizeChallenge({ body: REAL_V2 });
  createPolicy({ maxAmount: 1, pins: { file } }).commit({
    payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl,
  });

  const hijacked = structuredClone(REAL_V2);
  hijacked.accepts[0].payTo = "0xBADc0ffee0000000000000000000000000000000";
  const v = await vetChallenge(createPolicy({ maxAmount: 1, pins: { file } }), normalizeChallenge({ body: hijacked }), null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "payto_changed"));
  rmSync(file, { force: true });
});

test("trustPayTo re-pins a legitimate rotation", async () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-c.json`);
  rmSync(file, { force: true });
  const norm = normalizeChallenge({ body: REAL_V2 });
  const p1 = createPolicy({ maxAmount: 1, pins: { file } });
  p1.commit({ payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl });

  const rotated = structuredClone(REAL_V2);
  rotated.accepts[0].payTo = "0x00000000000000000000000000000000000000aa";
  p1.trustPayTo(norm.resourceUrl, rotated.accepts[0].payTo, "eip155:8453");
  const v = await vetChallenge(createPolicy({ maxAmount: 1, pins: { file } }), normalizeChallenge({ body: rotated }), null);
  assert.equal(v.allow, true);
  rmSync(file, { force: true });
});

test("a corrupt pin file does not block payments", () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-d.json`);
  writeFileSync(file, "{not json");
  const store = createPinStore({ file });
  assert.deepEqual(store.check("x|y", V2_PAYTO), { status: "new" });
  rmSync(file, { force: true });
});

// --------------------------------------------------------------------------- fetch adapter

test("guardedFetch does NOT consume the 402 body — the x402 client can still read it", async () => {
  const base = async () => challenge402(REAL_V1, { asHeader: false });
  const g = guardedFetch(base, { maxAmount: 1, ...NO_PINS() });
  const res = await g("https://stockwaves.net/api/cn/pulse");
  assert.equal(res.status, 402);
  const body = await res.json(); // this is exactly what x402-fetch does next
  assert.equal(body.accepts[0].payTo, REAL_V1.accepts[0].payTo);
});

test("guardedFetch throws PaymentBlockedError before the client can sign", async () => {
  let calls = 0;
  const base = async () => {
    calls++;
    return challenge402(REAL_V2);
  };
  const g = guardedFetch(base, { maxAmount: 0.0001, ...NO_PINS() });
  await assert.rejects(() => g("https://402sentinel.com/api/firewall"), PaymentBlockedError);
  assert.equal(calls, 1, "blocked payment must not produce a second, paid request");
});

test("guardedFetch leaves non-402 responses completely alone", async () => {
  const base = async () => new Response('{"ok":true}', { status: 200 });
  const g = guardedFetch(base, { maxAmount: 0.0001, ...NO_PINS() });
  assert.equal((await g("https://x.test/")).status, 200);
});

test("an unparseable 402 is passed through, not blocked", async () => {
  const base = async () => new Response("go away", { status: 402 });
  const g = guardedFetch(base, { maxAmount: 1, ...NO_PINS() });
  assert.equal((await g("https://x.test/")).status, 402);
});

test("onBlock returning true overrides the block", async () => {
  const seen = [];
  const g = guardedFetch(async () => challenge402(REAL_V2), {
    maxAmount: 0.0001,
    ...NO_PINS(),
    onBlock: (v) => {
      seen.push(v.detail);
      return true;
    },
  });
  assert.equal((await g("https://402sentinel.com/api/firewall")).status, 402);
  assert.equal(seen.length, 1);
});

test("spend is committed on the PAID retry, not on the challenge", async () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-e.json`);
  rmSync(file, { force: true });
  const p = createPolicy({ maxAmount: 1, dailyBudget: 0.003, pins: { file } });
  const url = "https://402sentinel.com/api/firewall";
  const base = async (_i, init) => (init?.headers?.["X-PAYMENT"] ? new Response("{}", { status: 200 }) : challenge402(REAL_V2));
  const g = guardedFetch(base, { policy: p });

  await g(url);                                        // challenge — nothing spent yet
  assert.equal((await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null)).allow, true);
  await g(url, { headers: { "X-PAYMENT": "sig" } });   // paid retry — 0.002 committed
  const v = await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null);
  assert.equal(v.allow, false, "0.002 spent + 0.002 = 0.004 > 0.003 daily budget");
  rmSync(file, { force: true });
});

test("a failed paid retry does not count as spend", async () => {
  const p = createPolicy({ maxAmount: 1, dailyBudget: 0.003, ...NO_PINS() });
  const url = "https://402sentinel.com/api/firewall";
  const base = async (_i, init) => (init?.headers?.["X-PAYMENT"] ? new Response("{}", { status: 502 }) : challenge402(REAL_V2));
  const g = guardedFetch(base, { policy: p });
  await g(url);
  await g(url, { headers: { "X-PAYMENT": "sig" } });
  assert.equal((await vetChallenge(p, normalizeChallenge({ body: REAL_V2 }), null)).allow, true);
});

// --------------------------------------------------------------------------- selector

test("guardSelector drops disallowed rails and returns an allowed one", () => {
  const sel = guardSelector({ maxAmount: 1, networks: ["eip155:8453"], resourceUrl: "https://402sentinel.com/api/firewall", ...NO_PINS() });
  const picked = sel(REAL_V2.accepts, undefined, "exact");
  assert.equal(picked.network, "eip155:8453");
});

test("guardSelector throws when the seller itself fails policy", () => {
  const sel = guardSelector({ maxAmount: 1, deny: [V2_PAYTO], resourceUrl: "https://402sentinel.com/api/firewall", ...NO_PINS() });
  assert.throws(() => sel(REAL_V2.accepts, undefined, "exact"), PaymentBlockedError);
});

// --------------------------------------------------------------------------- sentinel escalation

test("sentinel escalation fires only for a payTo never paid before", async () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-f.json`);
  rmSync(file, { force: true });
  let checks = 0;
  const opts = {
    maxAmount: 1,
    networks: ["eip155:8453"],
    pins: { file },
    sentinel: { on: "new-payto", live: false },
  };
  const norm = normalizeChallenge({ body: REAL_V2 });
  const p = createPolicy(opts);
  // stub the escalation by counting calls through vetChallenge directly
  const escalate = async ({ firstSeen }) => {
    if (!firstSeen) return null;
    checks++;
    return { decision: "allow", signals: [] };
  };
  await vetChallenge(p, norm, escalate);
  assert.equal(checks, 1, "first payment to this seller → one paid check");
  p.commit({ payTo: V2_PAYTO, amount: 0.002, network: "eip155:8453", resourceUrl: norm.resourceUrl });
  await vetChallenge(createPolicy(opts), norm, escalate);
  assert.equal(checks, 1, "seller already pinned → no further paid checks");
  rmSync(file, { force: true });
});

test("a sentinel block stops the payment", async () => {
  const escalate = async () => ({ decision: "block", signals: [{ signal: "sanctioned_counterparty", severity: "block" }] });
  const v = await vetChallenge(createPolicy({ maxAmount: 1, ...NO_PINS() }), normalizeChallenge({ body: REAL_V2 }), escalate);
  assert.equal(v.allow, false);
  assert.match(v.detail, /402Sentinel/);
});

// --------------------------------------------------------------------------- bypass regressions
// Each of these was a working bypass found by attacking the guard after it was written.

test("BYPASS: the challenge body cannot dictate which host gets pinned", async () => {
  // evil.example serves a challenge claiming to BE honest-seller.example. If the advertised
  // resource.url were trusted, evil's payTo would be written into honest-seller's pin —
  // poisoning it, so the real seller later trips payto_changed and evil looks familiar.
  const doc = {
    accepts: [{ amount: "3000", payTo: "0xBADc0ffee0000000000000000000000000000000", network: "base" }],
    resource: { url: "https://honest-seller.example/api" },
  };
  const norm = normalizeChallenge({ body: doc, requestUrl: "https://evil.example/api" });
  assert.equal(norm.resourceUrl, "https://evil.example/api", "policy host must be where the request went");
  assert.equal(norm.advertisedUrl, "https://honest-seller.example/api");

  const v = await vetChallenge(createPolicy({ maxAmount: 1, ...NO_PINS() }), norm, null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "resource_host_mismatch"));
});

test("BYPASS: http://localhost.evil.example does not inherit the loopback exemption", async () => {
  const doc = { accepts: [{ amount: "3000", payTo: V2_PAYTO, network: "eip155:8453" }] };
  const v = await vetChallenge(
    createPolicy({ maxAmount: 1, ...NO_PINS() }),
    normalizeChallenge({ body: doc, requestUrl: "http://localhost.evil.example/api" }),
    null,
  );
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "insecure_transport"));
});

test("real loopback IS still exempt, so local development works", async () => {
  const doc = { accepts: [{ amount: "3000", payTo: V2_PAYTO, network: "eip155:8453" }] };
  for (const u of ["http://localhost:8787/api", "http://127.0.0.1/api", "http://localhost/api"]) {
    const v = await vetChallenge(createPolicy({ maxAmount: 1, ...NO_PINS() }), normalizeChallenge({ body: doc, requestUrl: u }), null);
    assert.equal(v.allow, true, `${u} should be allowed`);
  }
});

test("a __proto__ key in the pin file cannot leak into unrelated hosts", () => {
  const file = join(tmpdir(), `apg-pins-${process.pid}-proto.json`);
  writeFileSync(file, JSON.stringify({ __proto__: { payTo: "0xbadc0ffee0000000000000000000000000000000", seen: 1 } }));
  const store = createPinStore({ file });
  assert.deepEqual(store.check("unrelated.example|base", V2_PAYTO), { status: "new" });
  assert.equal({}.payTo, undefined, "Object.prototype must be untouched");
  rmSync(file, { force: true });
});

test("spend is not accumulated when no budget reads it", () => {
  // spentSince() is what prunes the array and it only runs for a configured budget, so an
  // unbudgeted long-running agent would grow this forever.
  const p = createPolicy({ maxAmount: 1, ...NO_PINS() });
  for (let i = 0; i < 200_000; i++) p.commit({ payTo: V2_PAYTO, amount: 0.001, network: "base", resourceUrl: "https://a.example/x" });
  const heapMb = process.memoryUsage().heapUsed / 1048576;
  assert.ok(heapMb < 200, `heap grew to ${heapMb.toFixed(0)}MB after 200k unbudgeted commits`);
});

test("a budgeted policy still prunes its spend window", () => {
  const p = createPolicy({ maxAmount: 1, dailyBudget: 1e9, ...NO_PINS() });
  for (let i = 0; i < 150_000; i++) p.commit({ payTo: V2_PAYTO, amount: 0.001, network: "base", resourceUrl: "https://a.example/x" });
  const v = p.evaluate({ payTo: V2_PAYTO, amount: 0.001, network: "eip155:8453", resourceUrl: "https://a.example/x" });
  assert.equal(v.decision, "allow"); // still functional, and the array is capped at 100k
});


// --------------------------------------------------------------------------- abuse regressions
// Found by attacking the finished guard: the safety feature itself was the drain vector.

test("ABUSE: a seller rotating its payTo cannot bill the agent for unlimited paid checks", async () => {
  // Escalation spends the AGENT's money ($0.002/check). A hostile seller that presents a
  // fresh payTo on every 402 would otherwise force one paid check per call, forever.
  // The rotation IS the fraud signal — after a few distinct addresses from one host, block
  // instead of paying to investigate.
  let paidChecks = 0;
  const policy = createPolicy({ maxAmount: 1, ...NO_PINS() });
  const escalate = async ({ firstSeen }) => {
    if (!firstSeen) return null;
    paidChecks++;
    return { decision: "allow", signals: [] };
  };
  let blocked = 0;
  for (let i = 0; i < 200; i++) {
    const doc = { accepts: [{ maxAmountRequired: "3000", payTo: `0x${String(i).padStart(40, "0")}`, network: "base" }] };
    const v = await vetChallenge(policy, normalizeChallenge({ body: doc, requestUrl: "https://hostile.example/api" }), escalate);
    if (!v.allow) blocked++;
  }
  // Ceiling is maxNewPayToPerHost (8) + the challenge that trips it.
  assert.ok(paidChecks <= 9, `200 hostile challenges must not buy 200 checks (bought ${paidChecks})`);
  assert.ok(blocked > 185, `the rotation itself must block (blocked ${blocked}/200)`);
});

test("ABUSE: paid escalations are capped per hour even across many distinct hosts", async () => {
  // payto_rotation is per host, so a flood spread across hosts slips past it. This is the
  // spend ceiling behind it.
  const esc = createSentinelEscalation({ on: "always", live: false, maxChecksPerHour: 5 });
  let real = 0;
  for (let i = 0; i < 50; i++) {
    const v = await esc({ payTo: `0x${String(i).padStart(40, "0")}`, amount: 0.003, network: "base", resourceUrl: `https://h${i}.example/api`, firstSeen: true });
    if (!v?.signals?.some((s) => s.signal === "sentinel_rate_capped")) real++;
  }
  assert.equal(real, 5, `escalations must stop at the configured ceiling (ran ${real})`);
});

test("hitting the escalation ceiling does NOT block the agent", async () => {
  // Blocking on an exhausted check budget would let a hostile seller cause a denial of
  // service just by burning it. The local policy already cleared these payments.
  const esc = createSentinelEscalation({ on: "always", live: false, maxChecksPerHour: 1 });
  await esc({ payTo: "0xaa", amount: 0.003, network: "base", resourceUrl: "https://a.example", firstSeen: true });
  const v = await esc({ payTo: "0xbb", amount: 0.003, network: "base", resourceUrl: "https://b.example", firstSeen: true });
  assert.equal(v.decision, "allow");
  assert.ok(v.signals.some((s) => s.signal === "sentinel_rate_capped"));
});

test("ABUSE: nesting guardedFetch with the same policy does not double-count spend", async () => {
  const policy = createPolicy({ maxAmount: 0.05, dailyBudget: 0.007, ...NO_PINS() });
  const url = "https://402sentinel.com/api/firewall";
  const base = async (_i, init) => (init?.headers?.["X-PAYMENT"] ? new Response("{}", { status: 200 }) : challenge402(REAL_V2));
  const outer = guardedFetch(guardedFetch(base, { policy }), { policy });

  await outer(url);
  await outer(url, { headers: { "X-PAYMENT": "sig" } });
  const v = await vetChallenge(policy, normalizeChallenge({ body: REAL_V2, requestUrl: url }), null);
  assert.equal(v.allow, true, "0.002 committed once leaves room under 0.007; twice would not");
});


// --------------------------------------------------------------------------- pin granularity
// Real addresses from the live CDP Bazaar catalog. blockrun.ai splits collection across three
// payTo addresses on ONE host and ONE rail — a host-level pin called two of its four endpoints
// a hijack and hard-blocked them.

const BLOCKRUN = [
  ["https://blockrun.ai/api/v1/exa/answer", "0xe9030014F5DAe217d0A152f02A043567b16c1aBf"],
  ["https://blockrun.ai/api/v1/pm/polymarket/events", "0x6E007731870EDe419CfB31889Cd5C4493CEcb04c"],
  ["https://blockrun.ai/api/v1/surf/market/fear-greed", "0x058a5961FbE8cD8E4B47C69d3d82E159cb5d8F17"],
  ["https://blockrun.ai/api/v1/defillama/chains", "0xe9030014F5DAe217d0A152f02A043567b16c1aBf"],
];
const oneAccept = (payTo, url, network = "base") =>
  normalizeChallenge({ body: { accepts: [{ maxAmountRequired: "3000", payTo, network }] }, requestUrl: url });

test("FALSE POSITIVE: a seller with several collection addresses is not treated as a hijack", async () => {
  const policy = createPolicy({ maxAmount: 0.05, ...NO_PINS() });
  for (const [url, payTo] of BLOCKRUN) {
    const v = await vetChallenge(policy, oneAccept(payTo, url), null);
    assert.equal(v.allow, true, `${url} was blocked: ${v.detail}`);
    policy.commit({ payTo, amount: 0.003, network: "base", resourceUrl: url });
  }
});

test("the same endpoint swapping its payTo is still a hijack", async () => {
  const policy = createPolicy({ maxAmount: 0.05, ...NO_PINS() });
  const [url, honest] = BLOCKRUN[0];
  await vetChallenge(policy, oneAccept(honest, url), null);
  policy.commit({ payTo: honest, amount: 0.003, network: "base", resourceUrl: url });

  const v = await vetChallenge(policy, oneAccept("0xBADc0ffee0000000000000000000000000000000", url), null);
  assert.equal(v.allow, false);
  assert.ok(v.signals.some((s) => s.signal === "payto_changed"));
});

test("query strings do not create new pins — otherwise nothing is ever pinned", async () => {
  const policy = createPolicy({ maxAmount: 0.05, ...NO_PINS() });
  const url = "https://stockwaves.net/api/cn/pulse";
  const honest = "0xDc9F94A8b93F070B58cfa580cbE740d763005FE6";
  await vetChallenge(policy, oneAccept(honest, `${url}?since=30`), null);
  policy.commit({ payTo: honest, amount: 0.003, network: "base", resourceUrl: `${url}?since=30` });

  const v = await vetChallenge(policy, oneAccept("0xBADc0ffee0000000000000000000000000000000", `${url}?since=60`), null);
  assert.equal(v.allow, false, "changing a query parameter must not shake off the pin");
});

test("pinKey excludes the query string and keeps host, path and rail", () => {
  assert.equal(pinKey("https://a.example/api/x?y=1#z", "base"), "a.example/api/x|base");
  assert.notEqual(pinKey("https://a.example/one", "base"), pinKey("https://a.example/two", "base"));
  assert.notEqual(pinKey("https://a.example/one", "base"), pinKey("https://a.example/one", "solana"));
});
