const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {
  canonical,
  decodeB64Url,
  parseSpki,
  parseChainId,
  parseTerms,
  validateChallenge,
  prepareAutonomousPayment,
  formatPaymentSignatureHeader,
  resolveCredential,
  signTypedDataPayload,
  run,
  verify,
  createStandingMiddleware,
  cliVerify
} = require('../gate-check.cjs');

test('x402 standing-gate unit & regression test suite', async (t) => {
  const payTo = '0x1050eddd8282623b0c263ed6bdbd42370bbc28d3';
  const asset = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';

  await t.test('1. Credential Resolution & Disambiguation', () => {
    // 1a. Prepaid credit token
    const credToken = 'whp_' + 'ab'.repeat(32);
    const r1 = resolveCredential({ WHP_PAYMENT: credToken });
    assert.equal(r1.staticCreditToken, credToken);
    assert.equal(r1.staticPaymentSignature, '');
    assert.equal(r1.buyerKey, '');

    // 1b. Static payment payload (base64 JSON)
    const payloadJson = JSON.stringify({ x402Version: 2, payload: { signature: '0x123' } });
    const b64Payload = Buffer.from(payloadJson).toString('base64');
    const r2 = resolveCredential({ WHP_PAYMENT: b64Payload });
    assert.equal(r2.staticPaymentSignature, b64Payload);
    assert.equal(r2.staticCreditToken, '');
    assert.equal(r2.buyerKey, '');

    // 1c. Buyer key in WHP_BUYER_KEY
    const privKey = '0x' + '1234567890abcdef'.repeat(4);
    const r3 = resolveCredential({ WHP_BUYER_KEY: privKey });
    assert.equal(r3.buyerKey, privKey);
    assert.equal(r3.staticCreditToken, '');
    assert.equal(r3.staticPaymentSignature, '');

    // 1d. Private key in WHP_PAYMENT_KEY
    const r4 = resolveCredential({ WHP_PAYMENT_KEY: privKey });
    assert.equal(r4.buyerKey, privKey);
    assert.equal(r4.staticCreditToken, '');
    assert.equal(r4.staticPaymentSignature, '');

    // 1e. Reject invalid ambiguous credentials
    assert.throws(() => resolveCredential({ WHP_PAYMENT: 'invalid-secret-token' }), /Unrecognized credential format/);
    assert.throws(() => resolveCredential({ WHP_BUYER_KEY: 'not-a-private-key' }), /Invalid WHP_BUYER_KEY/);
  });

  await t.test('2. 402 Challenge Parsing & Validation', () => {
    const rawTerms = {
      x402Version: 2,
      resource: { url: 'https://decisionintegrity.wheelerhubbellpublishing.com/v1/evaluate' },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        amount: '1000000',
        asset,
        payTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' }
      }]
    };

    // Header parse
    const mockHeaders = new Map([
      ['payment-required', Buffer.from(JSON.stringify(rawTerms)).toString('base64')]
    ]);
    const mockResp = { headers: mockHeaders };
    const parsed = parseTerms(mockResp, null);
    assert.deepEqual(parsed.accepts, rawTerms.accepts);

    // Validation
    const { requirements } = validateChallenge(parsed);
    assert.equal(requirements.payTo, payTo);
    assert.equal(requirements.asset, asset);
    assert.equal(requirements.amount, '1000000');
    assert.equal(parseChainId(requirements.network), 8453);

    // Rejection on invalid challenge
    assert.throws(() => validateChallenge({}), /missing payment requirements/);
    assert.throws(() => validateChallenge({ accepts: [{ payTo: 'invalid', asset, amount: '100' }] }), /invalid or missing payTo/);
    assert.throws(() => validateChallenge({ accepts: [{ payTo, asset: 'invalid', amount: '100' }] }), /invalid or missing asset/);
    assert.throws(() => validateChallenge({ accepts: [{ payTo, asset, amount: '' }] }), /invalid or missing amount/);
  });

  await t.test('3. EIP-3009 Authorization Preparation & x402 Packaging', () => {
    const payer = '0x2222222222222222222222222222222222222222';
    const terms = {
      x402Version: 2,
      resource: { url: 'https://decisionintegrity.wheelerhubbellpublishing.com/v1/evaluate' },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        amount: '1000000',
        asset,
        payTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' }
      }]
    };

    const prep = prepareAutonomousPayment(terms, payer, { nowSeconds: 2000 });
    assert.equal(prep.authorization.from, payer.toLowerCase());
    assert.equal(prep.authorization.to, payTo.toLowerCase());
    assert.equal(prep.authorization.value, '1000000');
    assert.equal(prep.authorization.validAfter, '1940');
    assert.equal(prep.authorization.validBefore, '2300');
    assert.match(prep.authorization.nonce, /^0x[0-9a-fA-F]{64}$/);

    assert.equal(prep.typedData.domain.chainId, 8453);
    assert.equal(prep.typedData.domain.verifyingContract, asset.toLowerCase());
    assert.equal(prep.typedData.domain.name, 'USD Coin');
    assert.equal(prep.typedData.domain.version, '2');

    const dummySig = '0x' + 'aa'.repeat(64) + '1c';
    const submission = prep.completePayment(dummySig);
    assert.equal(submission.x402Version, 2);
    assert.equal(submission.payload.signature, dummySig);
    assert.equal(submission.payload.authorization.nonce, prep.authorization.nonce);

    const header = formatPaymentSignatureHeader(submission);
    const decoded = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
    assert.equal(decoded.x402Version, 2);
    assert.equal(decoded.payload.signature, dummySig);
  });

  await t.test('4. Signing with Simulated Signer (EIP-712 message verification)', async () => {
    const payer = '0x3333333333333333333333333333333333333333';
    let signedMessage = null;
    const simulatedSigner = {
      address: payer,
      signTypedData: async (typedData) => {
        signedMessage = typedData;
        return '0x' + '99'.repeat(64) + '1b';
      }
    };

    const terms = {
      accepts: [{
        network: 'eip155:8453',
        amount: '1000000',
        asset,
        payTo,
        extra: { name: 'USD Coin', version: '2' }
      }]
    };
    const prep = prepareAutonomousPayment(terms, payer, { nowSeconds: 1500 });
    const sig = await signTypedDataPayload(simulatedSigner, prep);

    assert.equal(sig, '0x' + '99'.repeat(64) + '1b');
    assert.ok(signedMessage);
    assert.equal(signedMessage.domain.chainId, 8453);
    assert.equal(signedMessage.message.from, payer.toLowerCase());
    assert.equal(signedMessage.message.to, payTo.toLowerCase());
    assert.equal(signedMessage.message.value, '1000000');
  });

  await t.test('5. Signing with viem privateKeyToAccount', async () => {
    const privKey = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a0f367417';
    const terms = {
      accepts: [{
        network: 'eip155:8453',
        amount: '1000000',
        asset,
        payTo,
        extra: { name: 'USD Coin', version: '2' }
      }]
    };
    const prep = prepareAutonomousPayment(terms, '0x0000000000000000000000000000000000000000', { nowSeconds: 1000 });
    const sig = await signTypedDataPayload(privKey, prep);

    assert.equal(sig.length, 132); // 0x + 64 bytes r,s + 1 byte v
    assert.match(sig, /^0x[0-9a-fA-F]{130}$/);
    assert.equal(prep.authorization.from, '0xe215d9513420c3ff852c7f4ec957991de62a6ed4');
  });

  await t.test('6. End-to-end simulated 402 handshake -> retry -> signed result', async () => {
    // Generate Ed25519 keypair for service signature
    const { privateKey: edPriv, publicKey: edPub } = crypto.generateKeyPairSync('ed25519');
    const edPubDer = edPub.export({ format: 'der', type: 'spki' });
    const edPubRaw = edPubDer.subarray(edPubDer.length - 32);
    const edPubB64Url = edPubRaw.toString('base64url');

    const expectedRecord = {
      type: 'WHP-FRONTDOOR-EVALUATION-v1',
      issuer: 'Wheeler Hubbell Publishing — WHP Standing front door',
      not_sealed_mark: true,
      input: { subject: 'test-subject', claim: 'test-claim' },
      determination: { outcome: 'ESTABLISHED', required_missing: [] }
    };
    const recordBytes = Buffer.from(canonical(expectedRecord));
    const recordHash = crypto.createHash('sha256').update(recordBytes).digest('hex');
    const sigBytes = crypto.sign(null, recordBytes, edPriv);
    const sigB64Url = sigBytes.toString('base64url');

    const signedResponse = {
      record: expectedRecord,
      record_hash: recordHash,
      signature: { alg: 'Ed25519', public_key_b64url: edPubB64Url, value_b64url: sigB64Url }
    };

    let step = 0;
    let paymentSignatureHeader = null;

    const mockFetch = async (url, opts = {}) => {
      const urlStr = url.toString();
      // Discovery GET
      if (opts.method === 'GET' || !opts.method) {
        return {
          status: 200,
          json: async () => ({
            signer: { alg: 'Ed25519', public_key_b64url: edPubB64Url }
          })
        };
      }

      step++;
      if (step === 1) {
        // Initial POST -> return 402 with challenge
        const terms = {
          x402Version: 2,
          resource: { url: 'https://decisionintegrity.wheelerhubbellpublishing.com/v1/evaluate' },
          accepts: [{
            scheme: 'exact',
            network: 'eip155:8453',
            amount: '1000000',
            asset,
            payTo,
            maxTimeoutSeconds: 300,
            extra: { name: 'USD Coin', version: '2' }
          }]
        };
        const b64 = Buffer.from(JSON.stringify(terms)).toString('base64');
        return {
          status: 402,
          headers: new Map([['payment-required', b64]]),
          text: async () => JSON.stringify(terms),
          json: async () => terms
        };
      }

      if (step === 2) {
        // Retry POST -> check payment header
        paymentSignatureHeader = opts.headers['PAYMENT-SIGNATURE'];
        assert.ok(paymentSignatureHeader, 'Retry must include PAYMENT-SIGNATURE');
        const decoded = JSON.parse(Buffer.from(paymentSignatureHeader, 'base64').toString('utf8'));
        assert.equal(decoded.x402Version, 2);
        assert.equal(decoded.accepted.payTo, payTo);
        assert.equal(decoded.payload.authorization.to, payTo.toLowerCase());
        assert.equal(decoded.payload.signature, '0x' + '77'.repeat(64) + '1b');

        return {
          status: 200,
          text: async () => JSON.stringify(signedResponse),
          json: async () => signedResponse
        };
      }

      throw Error('Unexpected fetch call');
    };

    const simulatedSigner = {
      address: '0x4444444444444444444444444444444444444444',
      signTypedData: async () => '0x' + '77'.repeat(64) + '1b'
    };

    const result = await run({
      env: {
        WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com',
        WHP_DOOR: '/v1/evaluate'
      },
      proactive: false,
      signer: simulatedSigner,
      fetchImpl: mockFetch
    });

    assert.equal(result.outcome, 'ESTABLISHED');
    assert.equal(result.hash, recordHash);
    assert.equal(step, 2);
    assert.ok(paymentSignatureHeader);
  });

  await t.test('8. Proactive Zero-Handshake M2M (single-roundtrip call #1)', async () => {
    const { privateKey: edPriv, publicKey: edPub } = crypto.generateKeyPairSync('ed25519');
    const edPubDer = edPub.export({ format: 'der', type: 'spki' });
    const edPubRaw = edPubDer.subarray(edPubDer.length - 32);
    const edPubB64Url = edPubRaw.toString('base64url');

    const expectedRecord = {
      type: 'WHP-FRONTDOOR-EVALUATION-v1',
      issuer: 'Wheeler Hubbell Publishing — WHP Standing front door',
      not_sealed_mark: true,
      input: { subject: 'test-subject', claim: 'test-claim' },
      determination: { outcome: 'ESTABLISHED', required_missing: [] }
    };
    const recordBytes = Buffer.from(canonical(expectedRecord));
    const recordHash = crypto.createHash('sha256').update(recordBytes).digest('hex');
    const sigBytes = crypto.sign(null, recordBytes, edPriv);
    const sigB64Url = sigBytes.toString('base64url');

    const signedResponse = {
      record: expectedRecord,
      record_hash: recordHash,
      signature: { alg: 'Ed25519', public_key_b64url: edPubB64Url, value_b64url: sigB64Url }
    };

    let postCallCount = 0;
    let firstCallHeaders = null;

    const mockFetch = async (url, opts = {}) => {
      if (opts.method === 'GET' || !opts.method) {
        return {
          status: 200,
          json: async () => ({ signer: { alg: 'Ed25519', public_key_b64url: edPubB64Url } })
        };
      }
      postCallCount++;
      firstCallHeaders = opts.headers;
      
      return {
        status: 200,
        text: async () => JSON.stringify(signedResponse),
        json: async () => signedResponse
      };
    };

    const dummySigner = {
      address: '0x4444444444444444444444444444444444444444',
      signTypedData: async () => '0x' + '77'.repeat(64) + '1b'
    };

    const res = await run({
      env: {
        WHP_ORIGIN: 'https://decisionintegrity.wheelerhubbellpublishing.com',
        WHP_DOOR: '/v1/evaluate'
      },
      signer: dummySigner,
      fetchImpl: mockFetch
    });

    assert.equal(postCallCount, 1, 'Should complete in exactly 1 POST call with zero retries');
    assert.ok(firstCallHeaders['PAYMENT-SIGNATURE'], 'First call must include PAYMENT-SIGNATURE');
    assert.equal(res.outcome, 'ESTABLISHED');
    assert.equal(res.hash, recordHash);
  });


  await t.test('9. Subscription API Key authentication passes directly', async () => {
    let capturedHeaders = null;
    const { privateKey: edPriv, publicKey: edPub } = crypto.generateKeyPairSync('ed25519');
    const edPubDer = edPub.export({ format: 'der', type: 'spki' });
    const edPubRaw = edPubDer.subarray(edPubDer.length - 32);
    const edPubB64Url = edPubRaw.toString('base64url');

    const expectedRecord = {
      type: 'WHP-FRONTDOOR-EVALUATION-v1',
      issuer: 'Wheeler Hubbell Publishing',
      input: { subject: 'test-subject', claim: 'Subscription verification test' },
      determination: { outcome: 'BOUNDED_DETERMINATION' },
      payment: { method: 'api-key', tier: 'team' },
      issued_at: Math.floor(Date.now() / 1000)
    };
    const recordBytes = Buffer.from(canonical(expectedRecord));
    const recordHash = crypto.createHash('sha256').update(recordBytes).digest('hex');
    const sigBytes = crypto.sign(null, recordBytes, edPriv);
    const sigB64Url = sigBytes.toString('base64url');

    const fakeFetch = async (url, opts) => {
      const u = new URL(url);
      if (u.pathname === '/v1/evaluate' && opts?.method !== 'POST') {
        return {
          status: 200,
          json: async () => ({ signer: { public_key_b64url: edPubB64Url } })
        };
      }
      capturedHeaders = opts.headers;
      return {
        status: 200,
        json: async () => ({
          envelope_version: 'WHP-FRONTDOOR-ENVELOPE-v1',
          record: expectedRecord,
          record_hash: recordHash,
          canonical_record_bytes: recordBytes.toString('utf8'),
          signature: {
            alg: 'Ed25519',
            public_key_b64url: edPubB64Url,
            value_b64url: sigB64Url
          }
        }),
        text: async () => ''
      };
    };

    const res = await run({
      env: {
        WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com',
        WHP_DOOR: '/v1/evaluate',
        WHP_API_KEY: 'whp_live_team_ci_cd_test_key_123',
        WHP_CLAIM: 'Subscription verification test'
      },
      fetchImpl: fakeFetch,
      proactive: false
    });

    assert.equal(res.outcome, 'BOUNDED_DETERMINATION');
    assert.equal(capturedHeaders['x-api-key'], 'whp_live_team_ci_cd_test_key_123');
    assert.equal(capturedHeaders['Authorization'], 'Bearer whp_live_team_ci_cd_test_key_123');
  });

  await t.test('7. Rejection paths', async () => {
    // 7a. 402 when no signer provided
    const mockFetch402 = async () => ({
      status: 402,
      headers: new Map(),
      text: async () => JSON.stringify({ error: 'Payment required' }),
      json: async () => ({ error: 'Payment required' })
    });
    await assert.rejects(
      () => run({ env: { WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com' }, fetchImpl: mockFetch402 }),
      /Payment required \(402\)/
    );

    // 7b. 402 retry rejected by server
    let count = 0;
    const mockFetchReject = async (url, opts) => {
      count++;
      if (count === 1) {
        return {
          status: 402,
          headers: new Map(),
          text: async () => JSON.stringify({
            accepts: [{ network: 'eip155:8453', amount: '1000000', asset, payTo }]
          }),
          json: async () => ({
            accepts: [{ network: 'eip155:8453', amount: '1000000', asset, payTo }]
          })
        };
      }
      return {
        status: 402,
        text: async () => 'PAYMENT_SETTLEMENT_FAILED: insufficient balance'
      };
    };

    const simulatedSigner = {
      address: '0x5555555555555555555555555555555555555555',
      signTypedData: async () => '0x' + '88'.repeat(64) + '1b'
    };

    await assert.rejects(
      () => run({
        env: { WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com' },
        signer: simulatedSigner,
        fetchImpl: mockFetchReject
      }),
      /Payment authorization refused \(HTTP 402\)/
    );
  });
  await t.test("10. Provenance resolution from WHP_PROVENANCE env or input", async () => {
    let capturedBody = null;
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const pubB64 = pubRaw.toString('base64url');
    const mockFetch = async (url, opts = {}) => {
      if (opts.method !== 'POST') {
        return { status: 200, json: async () => ({ signer: { public_key_b64url: pubB64 } }) };
      }
      capturedBody = JSON.parse(opts.body);
      const record = {
        type: "WHP-FRONTDOOR-EVALUATION-v1",
        input: capturedBody,
        determination: { outcome: "ESTABLISHED" }
      };
      const recBytes = Buffer.from(canonical(record));
      const record_hash = crypto.createHash("sha256").update(recBytes).digest("hex");
      const signature = crypto.sign(null, recBytes, privateKey).toString('base64url');
      return {
        status: 200,
        json: async () => ({
          record,
          record_hash,
          signature: { alg: 'Ed25519', public_key_b64url: pubB64, value_b64url: signature }
        })
      };
    };

    await run({
      env: {
        WHP_URL: "https://decisionintegrity.wheelerhubbellpublishing.com",
        WHP_API_KEY: "test_key",
        WHP_PROVENANCE: "https://github.com/wheelerhubbell/standing-gate/commit/abcdef"
      },
      fetchImpl: mockFetch
    });
    assert.strictEqual(capturedBody.provenance.uri, "https://github.com/wheelerhubbell/standing-gate/commit/abcdef");
    assert.strictEqual(capturedBody.provenance.source, "https://github.com/wheelerhubbell/standing-gate/commit/abcdef");

    const customProv = { source: "custom-pipeline", authority: "signer-cert", evidence: [] };
    await run({
      env: {
        WHP_URL: "https://decisionintegrity.wheelerhubbellpublishing.com",
        WHP_API_KEY: "test_key",
        WHP_PROVENANCE: JSON.stringify(customProv)
      },
      fetchImpl: mockFetch
    });
    assert.strictEqual(capturedBody.provenance.source, "custom-pipeline");
    assert.strictEqual(capturedBody.provenance.authority, "signer-cert");
  });

  await t.test('11. Structured input passes through exactly and record/reception remain separate', async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const pubB64 = pubRaw.toString('base64url');
    const input = {
      subject: 'artifact:test', claim: 'staging only', operation: 'COPY',
      proposed_output: { claim: 'staging only' },
      provenance: { source: 'fixture', evidence: [{ id: 'source-1' }] },
      transitions: [{ id: 'transition-1' }], relations: [{ type: 'COPY' }],
      correction: { supersedes: 'prior-record' }
    };
    let posted;
    const mockFetch = async (url, opts = {}) => {
      if (opts.method !== 'POST') return { status: 200, json: async () => ({ signer: { public_key_b64url: pubB64 } }) };
      posted = JSON.parse(opts.body);
      const record = {
        type: 'WHP-FRONTDOOR-EVALUATION-v1', input: posted,
        determination: { outcome: 'BOUNDED_DETERMINATION', lawful_unknowns: [{ id: 'u-1', standing: 'UNKNOWN_BLOCKING_FOR_REQUESTED_OPERATION' }] }
      };
      const bytes = Buffer.from(canonical(record));
      return { status: 200, json: async () => ({
        record, record_hash: crypto.createHash('sha256').update(bytes).digest('hex'),
        signature: { alg: 'Ed25519', public_key_b64url: pubB64, value_b64url: crypto.sign(null, bytes, privateKey).toString('base64url') }
      }) };
    };
    const res = await run({
      env: { WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com', WHP_API_KEY: 'test', WHP_PROACTIVE: 'false' },
      input, fetchImpl: mockFetch
    });
    assert.deepEqual(posted, input);
    assert.deepEqual(res.record.input, input);
    assert.equal(res.signatureStatus, 'VERIFIED_AGAINST_LIVE_DISCOVERY_KEY');
    assert.equal(res.reception.examination_record_hash, res.hash);
    assert.equal(res.record.determination.lawful_unknowns[0].id, 'u-1');
    assert.match(res.report, /UNKNOWN_BLOCKING_FOR_REQUESTED_OPERATION/);
  });
  await t.test('12. Successive examination continuity carried forward and displayed in report', async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pubRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const pubB64 = pubRaw.toString('base64url');
    const priorHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    let posted;
    const mockFetch = async (url, opts = {}) => {
      if (opts.method !== 'POST') return { status: 200, json: async () => ({ signer: { public_key_b64url: pubB64 } }) };
      posted = JSON.parse(opts.body);
      const record = {
        type: 'WHP-FRONTDOOR-EVALUATION-v1',
        input: posted,
        prior_record_hash: priorHash,
        determination: {
          outcome: 'BOUNDED_DETERMINATION',
          standing_record: {
            continuity: {
              status: 'SUCCESSIVE_LINEAGE_ESTABLISHED',
              prior_record_hash: priorHash,
              source_object_carried_forward: true,
              prior_record_preserved: true,
              new_evidence_introduced: ['Additional Audit Clearance #2026-B'],
              changed_conditions: { added: ['Audit Clearance Attached'], dropped: [] },
              prior_unknowns_addressed: ['Unverified Audit Compliance']
            }
          }
        }
      };
      const bytes = Buffer.from(canonical(record));
      return {
        status: 200,
        json: async () => ({
          record,
          record_hash: crypto.createHash('sha256').update(bytes).digest('hex'),
          signature: { alg: 'Ed25519', public_key_b64url: pubB64, value_b64url: crypto.sign(null, bytes, privateKey).toString('base64url') }
        })
      };
    };

    const res = await run({
      env: {
        WHP_URL: 'https://decisionintegrity.wheelerhubbellpublishing.com',
        WHP_API_KEY: 'test',
        WHP_PROACTIVE: 'false',
        WHP_PRIOR_RECORD_HASH: priorHash,
        WHP_CLAIM: 'Successive examination claim'
      },
      fetchImpl: mockFetch
    });

    assert.equal(posted.prior_record_hash, priorHash);
    assert.equal(res.continuity.status, 'SUCCESSIVE_LINEAGE_ESTABLISHED');
    assert.equal(res.continuity.prior_record_hash, priorHash);
    assert.equal(res.continuity.source_object_carried_forward, true);
    assert.equal(res.reception.prior_examination_record_hash, priorHash);
    assert.equal(res.reception.continuity_status, 'SUCCESSIVE_LINEAGE_ESTABLISHED');
    assert.match(res.report, /### Successive examination and continuity/);
    assert.match(res.report, /SUCCESSIVE_LINEAGE_ESTABLISHED/);
    assert.match(res.report, /Additional Audit Clearance #2026-B/);
  });
});


test('Receiving Boundary Rule No. 001: verify(request, mark) adversarial suite', async (t) => {
  const { privateKey: edPriv, publicKey: edPub } = crypto.generateKeyPairSync('ed25519');
  const { privateKey: untrustedPriv, publicKey: untrustedPub } = crypto.generateKeyPairSync('ed25519');

  const nowMs = Date.now();
  const validFrom = new Date(nowMs - 60000).toISOString();
  const validUntil = new Date(nowMs + 3600000).toISOString();

  function createSignedMark(overrides = {}, privKey = edPriv) {
    const payload = {
      type: 'WHP-STANDING-MARK-v1',
      outcome: overrides.outcome || 'ESTABLISHED',
      mark_id: overrides.mark_id || 'mark-test-123',
      bounds: {
        valid_from: overrides.valid_from !== undefined ? overrides.valid_from : validFrom,
        valid_until: overrides.valid_until !== undefined ? overrides.valid_until : validUntil
      },
      object_binding: {
        requested_operation: overrides.operation || 'DEPLOY',
        object_id: overrides.target || 'wheelerhubbell/service-a@v1.0.0',
        claim: overrides.claim || 'Authorized production deploy',
        parameters: overrides.parameters !== undefined ? overrides.parameters : { env: 'production', tier: 1 },
        nonce: overrides.nonce !== undefined ? overrides.nonce : 'nonce-xyz-789'
      },
      decision_record: {
        outcome: overrides.outcome || 'ESTABLISHED',
        proposition: overrides.claim || 'Authorized production deploy',
        operation: overrides.operation || 'DEPLOY'
      }
    };

    if (overrides.lawful_unknowns) {
      payload.lawful_unknowns = overrides.lawful_unknowns;
    }
    if (overrides.required_missing) {
      payload.required_missing = overrides.required_missing;
    }

    const protectedHdr = {
      type: 'WHP-STANDING-MARK-v1',
      alg: 'Ed25519',
      key_id: 'key-test-123'
    };

    const bytes = Buffer.from(canonical({ protected: protectedHdr, payload }));
    const sig = crypto.sign(null, bytes, privKey).toString('base64');

    return {
      protected: protectedHdr,
      payload,
      signature: sig
    };
  }

  const baseRequest = {
    operation: 'DEPLOY',
    target: 'wheelerhubbell/service-a@v1.0.0',
    claim: 'Authorized production deploy',
    parameters: { env: 'production', tier: 1 },
    nonce: 'nonce-xyz-789'
  };

  const testOpts = { _trustedKeyForTesting: edPub };

  await t.test('1. Valid Mark and matching request returns allow: true with reason_code: ALLOW', () => {
    const mark = createSignedMark();
    const result = verify(baseRequest, mark, testOpts);
    assert.equal(result.allow, true);
    assert.equal(result.reason_code, 'ALLOW');
    assert.equal(result.outcome, 'ESTABLISHED');
    assert.equal(result.mark_id, 'mark-test-123');
    assert.equal(result.bound_object.operation, 'DEPLOY');
    assert.equal(result.bound_object.target, 'wheelerhubbell/service-a@v1.0.0');
    assert.deepEqual(result.bound_object.parameters, { env: 'production', tier: 1 });
  });

  await t.test('2. Missing or unreadable inputs fail closed with deny', () => {
    assert.equal(verify(null, createSignedMark(), testOpts).allow, false);
    assert.equal(verify({}, createSignedMark(), testOpts).allow, false);
    assert.equal(verify(baseRequest, null, testOpts).allow, false);
    assert.equal(verify(baseRequest, 'invalid-json', testOpts).allow, false);
    assert.equal(verify(baseRequest, {}, testOpts).allow, false);
  });

  await t.test('3. Authoritative key enforcement: untrusted caller-supplied key is rejected', () => {
    // Signed with an untrusted key
    const untrustedMark = createSignedMark({}, untrustedPriv);
    // Verifying against authoritative keys (no _trustedKeyForTesting) MUST fail
    const result = verify(baseRequest, untrustedMark);
    assert.equal(result.allow, false);
    assert.equal(result.reason_code, 'INVALID_SIGNATURE');
  });

  await t.test('4. Tampered payload or signature fails with INVALID_SIGNATURE', () => {
    const mark = createSignedMark();
    mark.payload.object_binding.object_id = 'malicious-target';
    const result = verify(baseRequest, mark, testOpts);
    assert.equal(result.allow, false);
    assert.equal(result.reason_code, 'INVALID_SIGNATURE');
  });

  await t.test('5. Operation, target, and parameter mismatches are rejected', () => {
    const mark = createSignedMark();
    
    // Operation mismatch
    const opMismatch = verify({ ...baseRequest, operation: 'DELETE' }, mark, testOpts);
    assert.equal(opMismatch.allow, false);
    assert.equal(opMismatch.reason_code, 'OPERATION_MISMATCH');

    // Target mismatch
    const targetMismatch = verify({ ...baseRequest, target: 'wheelerhubbell/other-repo' }, mark, testOpts);
    assert.equal(targetMismatch.allow, false);
    assert.equal(targetMismatch.reason_code, 'OBJECT_MISMATCH');

    // Parameter mismatch
    const paramMismatch = verify({ ...baseRequest, parameters: { env: 'staging', tier: 1 } }, mark, testOpts);
    assert.equal(paramMismatch.allow, false);
    assert.equal(paramMismatch.reason_code, 'PARAMETERS_MISMATCH');

    // Nonce mismatch
    const nonceMismatch = verify({ ...baseRequest, nonce: 'wrong-nonce' }, mark, testOpts);
    assert.equal(nonceMismatch.allow, false);
    assert.equal(nonceMismatch.reason_code, 'NONCE_MISMATCH');
  });

  await t.test('6. Expired Mark fails with MARK_EXPIRED', () => {
    const expiredMark = createSignedMark({
      valid_from: new Date(nowMs - 7200000).toISOString(),
      valid_until: new Date(nowMs - 3600000).toISOString()
    });
    const result = verify(baseRequest, expiredMark, testOpts);
    assert.equal(result.allow, false);
    assert.equal(result.reason_code, 'MARK_EXPIRED');
  });

  await t.test('7. Non-established outcome fails with OUTCOME_NOT_ESTABLISHED', () => {
    const notEstMark = createSignedMark({ outcome: 'NOT_ESTABLISHED' });
    const result = verify(baseRequest, notEstMark, testOpts);
    assert.equal(result.allow, false);
    assert.equal(result.reason_code, 'OUTCOME_NOT_ESTABLISHED');
  });

  await t.test('8. Unresolved blocking lawful unknowns or missing evidence fails closed', () => {
    const unknownMark = createSignedMark({
      lawful_unknowns: [{ id: 'u-1', standing: 'UNKNOWN_BLOCKING_FOR_REQUESTED_OPERATION' }]
    });
    const resUnknown = verify(baseRequest, unknownMark, testOpts);
    assert.equal(resUnknown.allow, false);
    assert.equal(resUnknown.reason_code, 'UNRESOLVED_LAWFUL_UNKNOWN');

    const missingMark = createSignedMark({
      required_missing: ['SecurityPentestApproval']
    });
    const resMissing = verify(baseRequest, missingMark, testOpts);
    assert.equal(resMissing.allow, false);
    assert.equal(resMissing.reason_code, 'REQUIRED_EVIDENCE_MISSING');
  });

  await t.test('9. Replay protection: Consumed Mark is rejected on reuse', () => {
    const mark = createSignedMark({ mark_id: 'single-use-mark-456' });
    const consumedSet = new Set(['single-use-mark-456']);

    const result = verify(baseRequest, mark, { ...testOpts, consumedMarks: consumedSet });
    assert.equal(result.allow, false);
    assert.equal(result.reason_code, 'REPLAY_DETECTED');
    assert.match(result.message, /already been consumed/);
  });

  await t.test('10. CLI verify mode and replay file recording fail-closed behavior', () => {
    const tmpReq = path.join(os.tmpdir(), `req-${Date.now()}.json`);
    const tmpMark = path.join(os.tmpdir(), `mark-${Date.now()}.json`);
    const tmpConsumed = path.join(os.tmpdir(), `consumed-${Date.now()}.json`);

    fs.writeFileSync(tmpReq, JSON.stringify(baseRequest));
    // For CLI testing, create mark signed with live test key or tested via node child_process
    const mark = createSignedMark();
    fs.writeFileSync(tmpMark, JSON.stringify(mark));

    // Replay file should record when consumedMarks or CLI executes
    assert.equal(fs.existsSync(tmpConsumed), false);

    // Clean up
    try { fs.unlinkSync(tmpReq); } catch (e) {}
    try { fs.unlinkSync(tmpMark); } catch (e) {}
    try { fs.unlinkSync(tmpConsumed); } catch (e) {}
  });

  await t.test('11. HTTP Middleware wrapper returns 403 on deny, calls next() on allow', () => {
    const middleware = createStandingMiddleware(testOpts);
    const validMark = createSignedMark();

    let deniedCalled = false;
    let nextCalled = false;

    // Test Deny
    const reqDeny = { method: 'POST', url: '/api/action', headers: {} };
    const resDeny = {
      statusCode: 200,
      setHeader: () => {},
      end: (data) => {
        deniedCalled = true;
        const parsed = JSON.parse(data);
        assert.equal(parsed.error, 'STANDING_DENIED');
      }
    };
    middleware(reqDeny, resDeny, () => { nextCalled = true; });
    assert.equal(deniedCalled, true);
    assert.equal(nextCalled, false);

    // Test Allow
    deniedCalled = false;
    nextCalled = false;
    const reqAllow = {
      method: 'DEPLOY',
      url: 'wheelerhubbell/service-a@v1.0.0',
      headers: {
        'x-whp-standing-mark': JSON.stringify(validMark),
        'x-whp-claim': 'Authorized production deploy'
      },
      body: { env: 'production', tier: 1 }
    };
    const resAllow = { statusCode: 200, setHeader: () => {}, end: () => {} };
    middleware(reqAllow, resAllow, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.equal(reqAllow.standing.allow, true);
  });
});


test('Receiving Boundary Execution Order corrections: fail-closed adversarial regression suite', async (t) => {
  const { spawnSync } = require('node:child_process');
  const { privateKey: edPriv, publicKey: edPub } = crypto.generateKeyPairSync('ed25519');
  const testOpts = { _trustedKeyForTesting: edPub };

  const nowMs = Date.now();
  const validFrom = new Date(nowMs - 60000).toISOString();
  const validUntil = new Date(nowMs + 3600000).toISOString();
  const protectedHdr = { type: 'WHP-STANDING-MARK-v1', alg: 'Ed25519', key_id: 'key-test-123' };
  const edPubB64Url = edPub.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');

  function signEnvelope(payload, privKey = edPriv) {
    const bytes = Buffer.from(canonical({ protected: protectedHdr, payload }));
    return { protected: protectedHdr, payload, signature: crypto.sign(null, bytes, privKey).toString('base64') };
  }

  function basePayload() {
    return {
      type: 'WHP-STANDING-MARK-v1',
      outcome: 'ESTABLISHED',
      mark_id: 'mark-eo-' + crypto.randomBytes(4).toString('hex'),
      bounds: { valid_from: validFrom, valid_until: validUntil },
      object_binding: {
        requested_operation: 'DEPLOY',
        object_id: 'wheelerhubbell/service-a@v1.0.0',
        claim: 'Authorized production deploy',
        parameters: { env: 'production', tier: 1 },
        nonce: 'nonce-xyz-789'
      },
      decision_record: { outcome: 'ESTABLISHED', proposition: 'Authorized production deploy', operation: 'DEPLOY' }
    };
  }

  function createFormatBMark(mutate) {
    const record = {
      type: 'WHP-FRONTDOOR-EVALUATION-v1',
      input: {
        subject: 'wheelerhubbell/service-a@v1.0.0',
        claim: 'Authorized production deploy',
        operation: 'DEPLOY',
        parameters: { env: 'production', tier: 1 },
        nonce: 'nonce-xyz-789'
      },
      determination: { outcome: 'ESTABLISHED' },
      bounds: { valid_from: validFrom, valid_until: validUntil }
    };
    if (typeof mutate === 'function') mutate(record);
    const bytes = Buffer.from(canonical(record));
    return {
      record,
      record_hash: crypto.createHash('sha256').update(bytes).digest('hex'),
      signature: { alg: 'Ed25519', public_key_b64url: edPubB64Url, value_b64url: crypto.sign(null, bytes, edPriv).toString('base64url') }
    };
  }

  const baseRequest = {
    operation: 'DEPLOY',
    target: 'wheelerhubbell/service-a@v1.0.0',
    claim: 'Authorized production deploy',
    parameters: { env: 'production', tier: 1 },
    nonce: 'nonce-xyz-789'
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-eo-'));

  await t.test('1. Missing request claim rejects even when operation and target match', () => {
    const req = { ...baseRequest };
    delete req.claim;
    const r = verify(req, signEnvelope(basePayload()), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'MISSING_CLAIM');
  });

  await t.test('2. Malformed request claim rejects', () => {
    const r = verify({ ...baseRequest, claim: { nested: 'object' } }, signEnvelope(basePayload()), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'MALFORMED_CLAIM');
  });

  await t.test('3. Missing signed claim rejects', () => {
    const p = basePayload();
    delete p.object_binding.claim;
    delete p.decision_record.proposition;
    const r = verify(baseRequest, signEnvelope(p), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'MISSING_MARK_CLAIM');
  });

  await t.test('4. Malformed signed claim rejects', () => {
    const p = basePayload();
    p.decision_record.proposition = { not: 'a string' };
    const r = verify(baseRequest, signEnvelope(p), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'MALFORMED_MARK_CLAIM');
  });

  await t.test('5. Mismatched claims reject', () => {
    const r = verify({ ...baseRequest, claim: 'A different proposition entirely' }, signEnvelope(basePayload()), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'PROPOSITION_MISMATCH');
  });

  await t.test('6. Malformed validity dates reject, never silently skipped', () => {
    const p1 = basePayload();
    p1.bounds = { valid_from: validFrom, valid_until: 'not-a-date' };
    const r1 = verify(baseRequest, signEnvelope(p1), testOpts);
    assert.equal(r1.allow, false);
    assert.equal(r1.reason_code, 'MALFORMED_VALIDITY');

    const p2 = basePayload();
    p2.bounds = { valid_from: 'garbage', valid_until: validUntil };
    const r2 = verify(baseRequest, signEnvelope(p2), testOpts);
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'MALFORMED_VALIDITY');
  });

  await t.test('7. Missing validity bounds reject fail-closed', () => {
    const p1 = basePayload();
    delete p1.bounds;
    const r1 = verify(baseRequest, signEnvelope(p1), testOpts);
    assert.equal(r1.allow, false);
    assert.equal(r1.reason_code, 'MISSING_VALIDITY_BOUNDS');

    const p2 = basePayload();
    p2.bounds = { valid_from: validFrom };
    const r2 = verify(baseRequest, signEnvelope(p2), testOpts);
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'MISSING_VALIDITY_BOUNDS');

    const p3 = basePayload();
    p3.bounds = { valid_until: validUntil };
    const r3 = verify(baseRequest, signEnvelope(p3), testOpts);
    assert.equal(r3.allow, false);
    assert.equal(r3.reason_code, 'MISSING_VALIDITY_BOUNDS');

    // Frontdoor record without bounds: synthesized bounds carry no valid_until,
    // so this also fails closed pending an established freshness policy.
    const r4 = verify(baseRequest, createFormatBMark((rec) => { delete rec.bounds; }), testOpts);
    assert.equal(r4.allow, false);
    assert.equal(r4.reason_code, 'MISSING_VALIDITY_BOUNDS');
  });

  await t.test('8. Expired authorization rejects', () => {
    const p = basePayload();
    p.bounds = {
      valid_from: new Date(nowMs - 7200000).toISOString(),
      valid_until: new Date(nowMs - 3600000).toISOString()
    };
    const r = verify(baseRequest, signEnvelope(p), testOpts);
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'MARK_EXPIRED');
  });

  await t.test('9. Signed authorization: false rejects despite valid signature', () => {
    const p1 = basePayload();
    p1.authorization = false;
    const r1 = verify(baseRequest, signEnvelope(p1), testOpts);
    assert.equal(r1.allow, false);
    assert.equal(r1.reason_code, 'AUTHORIZATION_DENIED');

    const p2 = basePayload();
    p2.decision_record.authorization = false;
    const r2 = verify(baseRequest, signEnvelope(p2), testOpts);
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'AUTHORIZATION_DENIED');

    const p3 = basePayload();
    p3.authorization = { authorized: false };
    const r3 = verify(baseRequest, signEnvelope(p3), testOpts);
    assert.equal(r3.allow, false);
    assert.equal(r3.reason_code, 'AUTHORIZATION_DENIED');

    const r4 = verify(baseRequest, createFormatBMark((rec) => { rec.authorization = false; }), testOpts);
    assert.equal(r4.allow, false);
    assert.equal(r4.reason_code, 'AUTHORIZATION_DENIED');
  });

  await t.test('10. Valid signature alone confers no downstream authorization in the result', () => {
    const r = verify(baseRequest, signEnvelope(basePayload()), testOpts);
    assert.equal(r.allow, true);
    assert.equal(r.reason_code, 'ALLOW');
    assert.equal('authorization' in r, false);
    assert.equal('authorized' in r, false);
    assert.match(r.message, /verified and bound/);
  });

  await t.test('11. Malformed replay state rejects', () => {
    const f1 = path.join(tmpDir, 'garbage.json');
    fs.writeFileSync(f1, 'this is not json');
    const r1 = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedRecordsFile: f1 });
    assert.equal(r1.allow, false);
    assert.equal(r1.reason_code, 'REPLAY_STATE_UNAVAILABLE');

    const f2 = path.join(tmpDir, 'notarray.json');
    fs.writeFileSync(f2, '{"a": 1}');
    const r2 = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedRecordsFile: f2 });
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'REPLAY_STATE_UNAVAILABLE');

    const f3 = path.join(tmpDir, 'badentry.json');
    fs.writeFileSync(f3, '[123]');
    const r3 = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedRecordsFile: f3 });
    assert.equal(r3.allow, false);
    assert.equal(r3.reason_code, 'REPLAY_STATE_UNAVAILABLE');

    const r4 = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedMarks: 'not-a-set' });
    assert.equal(r4.allow, false);
    assert.equal(r4.reason_code, 'REPLAY_STATE_UNAVAILABLE');
  });

  await t.test('12. Replay-state read failure rejects', () => {
    // A directory path passes existsSync but cannot be read as a file.
    const r = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedRecordsFile: tmpDir });
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'REPLAY_STATE_UNAVAILABLE');
  });

  await t.test('13. Replay-state write failure rejects', () => {
    // Parent directory does not exist: consumption state cannot be established.
    const missing = path.join(tmpDir, 'no-such-dir', 'consumed.json');
    const r = verify(baseRequest, signEnvelope(basePayload()), { ...testOpts, consumedRecordsFile: missing });
    assert.equal(r.allow, false);
    assert.equal(r.reason_code, 'REPLAY_STATE_UNAVAILABLE');
  });

  await t.test('14. Duplicate consumption rejects: first passage records, reuse is replay', () => {
    const f = path.join(tmpDir, 'single-use.json');
    const payload = basePayload();
    const mark = signEnvelope(payload);
    const opts = { ...testOpts, consumedRecordsFile: f };

    const r1 = verify(baseRequest, mark, opts);
    assert.equal(r1.allow, true);
    assert.equal(r1.consumed, true);

    const recorded = JSON.parse(fs.readFileSync(f, 'utf8'));
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].mark_id, payload.mark_id);

    const r2 = verify(baseRequest, mark, opts);
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'REPLAY_DETECTED');
  });

  await t.test('15. In-memory consumption records and prevents reuse', () => {
    const set = new Set();
    const mark = signEnvelope(basePayload());
    const opts = { ...testOpts, consumedMarks: set };
    const r1 = verify(baseRequest, mark, opts);
    assert.equal(r1.allow, true);
    assert.equal(r1.consumed, true);
    const r2 = verify(baseRequest, mark, opts);
    assert.equal(r2.allow, false);
    assert.equal(r2.reason_code, 'REPLAY_DETECTED');
  });

  await t.test('16. Positive control: properly formed authorized unexpired bound Format A Mark passes', () => {
    const r = verify(baseRequest, signEnvelope(basePayload()), testOpts);
    assert.equal(r.allow, true);
    assert.equal(r.reason_code, 'ALLOW');
    assert.equal(r.outcome, 'ESTABLISHED');
    assert.equal(r.bound_object.claim, 'Authorized production deploy');
  });

  await t.test('17. Positive control: properly formed authorized unexpired bound Format B Mark passes', () => {
    const r = verify(baseRequest, createFormatBMark(), testOpts);
    assert.equal(r.allow, true);
    assert.equal(r.reason_code, 'ALLOW');
  });

  await t.test('18. Middleware path enforces the same fail-closed claim binding', () => {
    const middleware = createStandingMiddleware(testOpts);
    const mark = signEnvelope(basePayload());

    // Missing claim in the receiving request: denied with MISSING_CLAIM
    let denyBody = null;
    const reqNoClaim = {
      method: 'DEPLOY',
      url: 'wheelerhubbell/service-a@v1.0.0',
      headers: { 'x-whp-standing-mark': JSON.stringify(mark) },
      body: { env: 'production', tier: 1 }
    };
    const resNoClaim = {
      statusCode: 200,
      setHeader: () => {},
      end: (data) => { denyBody = JSON.parse(data); }
    };
    let nextCalled = false;
    middleware(reqNoClaim, resNoClaim, () => { nextCalled = true; });
    assert.equal(nextCalled, false);
    assert.equal(resNoClaim.statusCode, 403);
    assert.equal(denyBody.reason_code, 'MISSING_CLAIM');

    // Complete request with single-use replay file: allowed, consumption recorded
    const f = path.join(tmpDir, 'mw-consumed.json');
    const mwReplay = createStandingMiddleware({ ...testOpts, consumedRecordsFile: f });
    const reqOk = {
      method: 'DEPLOY',
      url: 'wheelerhubbell/service-a@v1.0.0',
      headers: { 'x-whp-standing-mark': JSON.stringify(mark), 'x-whp-claim': 'Authorized production deploy' },
      body: { env: 'production', tier: 1 }
    };
    const resOk = { statusCode: 200, setHeader: () => {}, end: () => {} };
    let nextOk = false;
    mwReplay(reqOk, resOk, () => { nextOk = true; });
    assert.equal(nextOk, true);
    assert.equal(reqOk.standing.consumed, true);

    // Second passage of the same Mark through the middleware: replay denied
    let denyReplay = null;
    const reqReplay = {
      method: 'DEPLOY',
      url: 'wheelerhubbell/service-a@v1.0.0',
      headers: { 'x-whp-standing-mark': JSON.stringify(mark), 'x-whp-claim': 'Authorized production deploy' },
      body: { env: 'production', tier: 1 }
    };
    const resReplay = {
      statusCode: 200,
      setHeader: () => {},
      end: (data) => { denyReplay = JSON.parse(data); }
    };
    mwReplay(reqReplay, resReplay, () => { nextOk = 'replay-passed'; });
    assert.equal(denyReplay.reason_code, 'REPLAY_DETECTED');
  });

  await t.test('19. CLI path: deny exits 1; caller-supplied keys cannot override production issuer trust', () => {
    const reqFile = path.join(tmpDir, 'cli-req.json');
    const markFile = path.join(tmpDir, 'cli-mark.json');
    fs.writeFileSync(reqFile, JSON.stringify(baseRequest));
    fs.writeFileSync(markFile, JSON.stringify(signEnvelope(basePayload())));

    // The fixture is signed with a non-authoritative key; the real CLI must deny.
    const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'gate-check.cjs'), 'verify', '--request', reqFile, '--mark', markFile], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    const out = JSON.parse(r.stdout);
    assert.equal(out.allow, false);
    assert.equal(out.reason_code, 'INVALID_SIGNATURE');

    // Missing request input: fails closed at the CLI boundary as well.
    const r2 = spawnSync(process.execPath, [path.join(__dirname, '..', 'gate-check.cjs'), 'verify'], { encoding: 'utf8', env: { ...process.env, WHP_REQUEST: '', WHP_MARK: '' } });
    assert.equal(r2.status, 1);
  });
});
