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
