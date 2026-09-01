// guardAxios against REAL axios. Written after the first cut of guardAxios shipped broken:
// `axios.create().defaults.adapter` is a list of adapter NAMES (["xhr","http","fetch"]), not
// a function, so the "is it a function?" check rejected every real instance. Untested support
// is worse than no support — it is a claim in the README that fails on first use.

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { guardAxios, PaymentBlockedError } from "./x402.mjs";
import { createPolicy } from "./policy.mjs";

let axios;
try {
  ({ default: axios } = await import("axios"));
} catch {
  test("axios integration", { skip: "axios not installed (npm i -D axios)" }, () => {});
}

if (axios) {
  const SELLER = "0xDc9F94A8b93F070B58cfa580cbE740d763005FE6";
  const HIJACK = "0xBADc0ffee0000000000000000000000000000000";
  const PINS = join(tmpdir(), `apg-axios-${process.pid}.json`);

  let payTo = SELLER;
  let hits = 0;
  let paidHits = 0;
  const srv = createServer((req, res) => {
    hits++;
    if (req.headers["x-payment"] || req.headers["payment-signature"]) {
      paidHits++;
      res.writeHead(200, { "content-type": "application/json" });
      return res.end('{"ok":true}');
    }
    if (req.url.startsWith("/v2/")) {
      // v2: the challenge rides in the `payment-required` header and the body is empty. This
      // is what our own servers emit, and it reaches the guard through axios' AxiosHeaders
      // object rather than a plain map — a different read path than v1 entirely.
      const doc = {
        x402Version: 2,
        resource: { url: `http://127.0.0.1:${srv.address().port}/v2/api`, description: "d", mimeType: "" },
        accepts: [
          { scheme: "exact", network: "eip155:8453", amount: "3000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } },
        ],
      };
      res.writeHead(402, { "content-type": "application/json", "payment-required": Buffer.from(JSON.stringify(doc)).toString("base64") });
      return res.end("{}");
    }
    res.writeHead(402, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        x402Version: 1,
        accepts: [
          { scheme: "exact", network: "base", maxAmountRequired: "3000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo, resource: "https://seller.test/api/data", description: "t", mimeType: "application/json", maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } },
        ],
      }),
    );
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const ORIGIN = `http://127.0.0.1:${srv.address().port}`;
  const base = { requireHttps: false, pins: { file: PINS } };

  // Default validateStatus on purpose: x402-axios hooks the response ERROR interceptor, so
  // it only ever fires because axios REJECTS a 402. Relaxing validateStatus turns the 402
  // into a success and silently disables the very interceptor under test. The guard is
  // unaffected either way — it wraps the adapter, which runs before validateStatus is applied.
  const mk = async (opts) => guardAxios(axios.create(), opts);

  await test("REGRESSION: guardAxios resolves the default adapter list, not just a function", async () => {
    rmSync(PINS, { force: true });
    const inst = axios.create();
    assert.ok(!(typeof inst.defaults.adapter === "function"), "precondition: axios ships an adapter NAME LIST");
    const guarded = await mk({ ...base, maxAmount: 0.05 });
    assert.equal(typeof guarded.defaults.adapter, "function");
  });

  await test("in-policy payment is passed through to the x402 interceptor", async () => {
    rmSync(PINS, { force: true });
    const c = await mk({ ...base, maxAmount: 0.05 });
    const err = await c.get(`${ORIGIN}/api/data`).then(
      () => null,
      (e) => e,
    );
    assert.ok(err, "axios rejects a 402 — that rejection is what x402-axios listens for");
    assert.ok(!(err instanceof PaymentBlockedError), `guard should not have blocked: ${err.message}`);
    assert.equal(err.response.status, 402, "the challenge reaches the interceptor intact");
  });

  await test("over-cap payment is blocked before x402-axios can sign", async () => {
    rmSync(PINS, { force: true });
    hits = 0;
    const c = await mk({ ...base, maxAmount: 0.001 });
    await assert.rejects(() => c.get(`${ORIGIN}/api/data`), PaymentBlockedError);
    assert.equal(hits, 1, "no second, paid request");
  });

  // The adapter has to work whichever way the caller configures validateStatus: under the
  // default a 402 is THROWN by axios' own adapter, under a relaxed one it is RETURNED. The
  // first cut only handled the returned form, so every check silently did nothing on a
  // default instance — which is the one x402-axios actually requires.
  await test("REGRESSION: blocks under BOTH default and relaxed validateStatus", async () => {
    for (const [label, extra] of [
      ["default (402 thrown by the adapter)", {}],
      ["relaxed (402 returned)", { validateStatus: (st) => st < 500 }],
    ]) {
      rmSync(PINS, { force: true });
      const c = await guardAxios(axios.create(extra), { ...base, maxAmount: 0.001 });
      const err = await c.get(`${ORIGIN}/api/data`).then(
        () => null,
        (e) => e,
      );
      assert.ok(err instanceof PaymentBlockedError, `${label}: expected PaymentBlockedError, got ${err && err.message}`);
    }
  });

  await test("REGRESSION: a non-402 rejection is re-thrown unchanged", async () => {
    rmSync(PINS, { force: true });
    const c = await guardAxios(axios.create(), { ...base, maxAmount: 0.05 });
    const err = await c.get(`${ORIGIN}/nope-there-is-no-such-server`.replace(ORIGIN, "http://127.0.0.1:1")).then(
      () => null,
      (e) => e,
    );
    assert.ok(err, "a transport failure must still reject");
    assert.ok(!(err instanceof PaymentBlockedError), "the guard must not turn a connection error into a block");
  });

  await test("REGRESSION: guarding the same instance twice does not double-count spend", async () => {
    // Stacked guards vet twice AND commit twice, so a single payment eats double its budget.
    // Threshold picked to discriminate: one commit (0.003) stays under 0.007, two (0.006) do not.
    const run = async (wraps) => {
      rmSync(PINS, { force: true });
      const inst = axios.create();
      const policy = createPolicy({ ...base, maxAmount: 0.05, dailyBudget: 0.007 });
      for (let i = 0; i < wraps; i++) await guardAxios(inst, { ...base, policy });
      await inst.get(`${ORIGIN}/api/data`).catch(() => {});
      await inst.get(`${ORIGIN}/api/data`, { headers: { "X-PAYMENT": "sig" } }).catch(() => {});
      return policy.evaluate({ payTo: SELLER, amount: 0.003, network: "base", resourceUrl: `${ORIGIN}/api/data` }).decision;
    };
    assert.equal(await run(1), "allow", "one payment of 0.003 must leave room under a 0.007 budget");
    assert.equal(await run(2), "allow", "double-wrapping must not commit the same payment twice");
  });

  await test("v2 challenge (payment-required header) is read through axios and capped", async () => {
    rmSync(PINS, { force: true });
    const c = await mk({ ...base, maxAmount: 0.001 });
    const err = await c.get(`${ORIGIN}/v2/api`).then(
      () => null,
      (e) => e,
    );
    assert.ok(err instanceof PaymentBlockedError, `expected a block, got ${err && err.message}`);
    assert.match(err.detail, /\$0\.003 exceeds maxAmount/, "3000 base units must read as $0.003");
  });

  await test("v2 challenge within policy is passed through untouched", async () => {
    rmSync(PINS, { force: true });
    const c = await mk({ ...base, maxAmount: 0.05 });
    const err = await c.get(`${ORIGIN}/v2/api`).then(
      () => null,
      (e) => e,
    );
    assert.ok(!(err instanceof PaymentBlockedError), `guard should not have blocked: ${err && err.message}`);
    assert.equal(err.response.status, 402);
  });

  await test("PARITY: onBlock and onAllow fire on the axios path too", async () => {
    // Both are documented options. The first cut of guardAxios ignored them, so they silently
    // did nothing on this path — the same class of untested-claim bug as guardAxios itself.
    rmSync(PINS, { force: true });
    let blockCb = 0;
    const c1 = await mk({ ...base, maxAmount: 0.001, onBlock: () => (blockCb++, false) });
    await c1.get(`${ORIGIN}/api/data`).catch(() => {});
    assert.equal(blockCb, 1, "onBlock must fire when the guard blocks");

    rmSync(PINS, { force: true });
    let allowCb = 0;
    const c2 = await mk({ ...base, maxAmount: 0.05, onAllow: () => allowCb++ });
    await c2.get(`${ORIGIN}/api/data`).catch(() => {});
    assert.equal(allowCb, 1, "onAllow must fire when the guard allows");
  });

  await test("a seller that swaps its payTo is blocked", async () => {
    rmSync(PINS, { force: true });
    const opts = { ...base, maxAmount: 0.05 };
    createPolicy(opts).commit({ payTo: SELLER, amount: 0.003, network: "base", resourceUrl: `${ORIGIN}/api/data` });
    payTo = HIJACK;
    const c = await mk(opts);
    await assert.rejects(() => c.get(`${ORIGIN}/api/data`), /previously paid/);
    payTo = SELLER;
  });

  await test("budget is committed on the paid retry, not on the challenge", async () => {
    rmSync(PINS, { force: true });
    const policy = createPolicy({ ...base, maxAmount: 0.05, dailyBudget: 0.005 });
    const c = await mk({ ...base, policy });

    await c.get(`${ORIGIN}/api/data`).catch(() => {}); // challenge only (axios rejects the 402)
    assert.equal(
      policy.evaluate({ payTo: SELLER, amount: 0.003, network: "base", resourceUrl: `${ORIGIN}/api/data` }).decision,
      "allow",
      "an unpaid challenge must not consume budget",
    );
    await c.get(`${ORIGIN}/api/data`, { headers: { "X-PAYMENT": "sig" } }); // the paid retry (200)
    assert.equal(
      policy.evaluate({ payTo: SELLER, amount: 0.003, network: "base", resourceUrl: `${ORIGIN}/api/data` }).decision,
      "block",
      "0.003 spent + 0.003 = 0.006 > 0.005 daily budget",
    );
  });

  await test("baseURL + relative path is pinned as the full destination", async () => {
    rmSync(PINS, { force: true });
    const policy = createPolicy({ ...base, maxAmount: 0.05 });
    const c = await guardAxios(axios.create({ baseURL: ORIGIN }), { ...base, policy });
    await c.get("/api/data").catch(() => {});
    await c.get("/api/data", { headers: { "X-PAYMENT": "sig" } });
    const pinned = Object.keys(policy.pins.all());
    assert.ok(
      pinned.includes(`127.0.0.1:${srv.address().port}/api/data|base`),
      `expected a pin on the resolved host+path, got ${JSON.stringify(pinned)}`,
    );
  });

  // Resolved BEFORE the test so a missing x402-axios shows up as an explicit skip. A
  // `try { import } catch { return }` inside the test reports a green pass while asserting
  // nothing — which is exactly how this composition went unverified the first time.
  let withPaymentInterceptor = null;
  try {
    ({ withPaymentInterceptor } = await import("x402-axios"));
  } catch {
    /* optional devDependency */
  }

  await test(
    "composes with the real x402-axios interceptor",
    { skip: withPaymentInterceptor ? false : "x402-axios not installed" },
    async () => {
    rmSync(PINS, { force: true });
    const stubSigner = {
      account: { address: SELLER },
      chain: { id: 8453 },
      transport: {},
      signTypedData: async () => {
        throw new Error("SIGNER-REACHED");
      },
    };
    const guarded = await mk({ ...base, maxAmount: 0.001 }); // over cap → must block
    const c = withPaymentInterceptor(guarded, stubSigner);
    await assert.rejects(() => c.get(`${ORIGIN}/api/data`), /exceeds maxAmount/);

    const ok = withPaymentInterceptor(await mk({ ...base, maxAmount: 0.05 }), stubSigner);
    await assert.rejects(() => ok.get(`${ORIGIN}/api/data`), /SIGNER-REACHED/, "in-policy payment should reach signing");
    },
  );

  // Unconditional teardown. `server.close()` alone waits on live sockets, and Node keeps
  // HTTP connections alive by default — so without closeAllConnections() every test passes
  // and the process then hangs forever on an open handle.
  await test("teardown", () => {
    srv.closeAllConnections?.();
    srv.close();
    rmSync(PINS, { force: true });
  });
}
