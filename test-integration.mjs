// Integration test against the REAL x402-fetch. The unit tests prove the policy is right;
// only this proves the premise — that the guard actually sits on x402's payment path and
// stops it before a signature exists. Skipped when x402-fetch isn't installed, so the
// package stays dependency-free.

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { guardedFetch, PaymentBlockedError } from "./x402.mjs";
import { createPolicy } from "./policy.mjs";

// Two generations of buyer client are live, and the SCOPED one is much the larger:
//   x402-fetch    (v1, unscoped)  ~96k installs/mo — challenge in the JSON body
//   @x402/fetch   (v2, scoped)   ~426k installs/mo — challenge in the payment-required header
// The guard has to sit correctly on both, so both are exercised here against a real server.

let wrapFetchWithPayment;
try {
  ({ wrapFetchWithPayment } = await import("x402-fetch"));
} catch {
  test("x402-fetch integration", { skip: "x402-fetch not installed (npm i -D x402-fetch)" }, () => {});
}

if (wrapFetchWithPayment) {
  const SELLER = "0xDc9F94A8b93F070B58cfa580cbE740d763005FE6";
  const HIJACK = "0xBADc0ffee0000000000000000000000000000000";
  const PINS = join(tmpdir(), `apg-integration-${process.pid}.json`);

  let payTo = SELLER;
  let hits = 0;
  const srv = createServer((req, res) => {
    hits++;
    if (req.headers["x-payment"] || req.headers["payment-signature"]) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end('{"ok":true}');
    }
    res.writeHead(402, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        x402Version: 1,
        accepts: [
          {
            scheme: "exact",
            network: "base",
            maxAmountRequired: "3000",
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo,
            resource: "https://seller.test/api/data",
            description: "test",
            mimeType: "application/json",
            maxTimeoutSeconds: 300,
            extra: { name: "USD Coin", version: "2" },
          },
        ],
      }),
    );
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const URL_ = `http://127.0.0.1:${srv.address().port}/api/data`;

  // Structurally valid to x402-fetch but unable to sign: if the guard ever lets a payment
  // through, signTypedData throws SIGNER-REACHED — which is how the ALLOW path is proven.
  const stubSigner = {
    account: { address: SELLER },
    chain: { id: 8453 },
    transport: {},
    signTypedData: async () => {
      throw new Error("SIGNER-REACHED");
    },
  };
  const base = { requireHttps: false, pins: { file: PINS } }; // loopback test server

  const attempt = async (opts) => {
    const f = wrapFetchWithPayment(guardedFetch(fetch, opts), stubSigner);
    try {
      return { status: (await f(URL_)).status };
    } catch (e) {
      return { error: e, blocked: e instanceof PaymentBlockedError, message: e.message };
    }
  };

  // Torn down at the end of the last test, NOT in test.after(): the root-level after hook
  // fires as soon as the first awaited top-level test settles, which killed the server out
  // from under the remaining cases.
  const teardown = () => {
    srv.closeAllConnections?.(); // close() alone waits on keep-alive sockets and hangs the process
    srv.close();
    rmSync(PINS, { force: true });
  };

  await test("over-cap payment is stopped before x402-fetch can sign", async () => {
    rmSync(PINS, { force: true });
    hits = 0;
    const r = await attempt({ ...base, maxAmount: 0.001 });
    assert.ok(r.blocked, `expected PaymentBlockedError, got ${r.message ?? r.status}`);
    assert.match(r.message, /exceeds maxAmount/);
    assert.equal(hits, 1, "the challenge only — no second, paid request");
  });

  await test("an in-policy payment is handed through to the signer", async () => {
    rmSync(PINS, { force: true });
    const r = await attempt({ ...base, maxAmount: 0.05 });
    assert.match(r.message, /SIGNER-REACHED/, "guard should have let x402-fetch proceed to sign");
  });

  await test("a seller that swaps its payTo mid-relationship is stopped", async () => {
    rmSync(PINS, { force: true });
    const opts = { ...base, maxAmount: 0.05 };
    createPolicy(opts).commit({ payTo: SELLER, amount: 0.003, network: "base", resourceUrl: URL_ });
    payTo = HIJACK;
    hits = 0;
    const r = await attempt(opts);
    payTo = SELLER;
    teardown();
    assert.ok(r.blocked, `expected PaymentBlockedError, got ${r.message ?? r.status}`);
    assert.match(r.message, /previously paid/);
    assert.equal(hits, 1);
  });
}

// --------------------------------------------------------------------------- @x402/fetch (v2)

let wrapV2, x402ClientCtor, x402HTTPClientCtor;
try {
  ({ wrapFetchWithPayment: wrapV2 } = await import("@x402/fetch"));
  ({ x402Client: x402ClientCtor, x402HTTPClient: x402HTTPClientCtor } = await import("@x402/core/client"));
} catch {
  /* optional devDependency */
}

await test(
  "@x402/fetch (v2, the larger client) is guarded on a header-borne challenge",
  { skip: wrapV2 ? false : "@x402/fetch not installed" },
  async () => {
    const SELLER = "0xDc9F94A8b93F070B58cfa580cbE740d763005FE6";
    const PINS2 = join(tmpdir(), `apg-v2-${process.pid}.json`);
    rmSync(PINS2, { force: true });

    let hits = 0;
    const srv2 = createServer((req, res) => {
      hits++;
      const doc = {
        x402Version: 2,
        error: "Payment required",
        resource: { url: `http://127.0.0.1:${srv2.address().port}/api`, description: "d", mimeType: "" },
        accepts: [
          { scheme: "exact", network: "eip155:8453", amount: "3000", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: SELLER, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } },
        ],
      };
      // v2 puts the challenge in the header and leaves the body empty — the exact shape our
      // own servers emit, and the one a body-reading v1 client cannot see at all.
      res.writeHead(402, { "content-type": "application/json", "payment-required": Buffer.from(JSON.stringify(doc)).toString("base64") });
      res.end("{}");
    });
    await new Promise((r) => srv2.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${srv2.address().port}/api`;

    const client = new x402HTTPClientCtor(new x402ClientCtor());
    const guarded = wrapV2(guardedFetch(fetch, { maxAmount: 0.001, requireHttps: false, pins: { file: PINS2 } }), client);
    const err = await guarded(url).then(
      () => null,
      (e) => e,
    );
    assert.ok(err instanceof PaymentBlockedError, `expected a block, got ${err && err.message}`);
    assert.match(err.detail, /\$0\.003 exceeds maxAmount/);
    assert.equal(hits, 1, "no second, paid request");
    assert.equal((err.detail.match(/exceeds maxAmount/g) || []).length, 1, "one reason, stated once");

    srv2.closeAllConnections?.();
    srv2.close();
    rmSync(PINS2, { force: true });
  },
);
