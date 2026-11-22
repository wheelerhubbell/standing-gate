const { createHash, createPublicKey, randomBytes, verify: cryptoVerify } = require('node:crypto');
const fs = require('node:fs');

function canonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0)) return String(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort((a,b) => {
      const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0));
      for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
      return x.length - y.length;
    }).map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  throw Error('Unsupported canonical value');
}

function decodeB64Url(v, size) {
  if (typeof v !== 'string' || !/^[A-Za-z0-9_-]+$/.test(v)) throw Error('Invalid signature encoding');
  const b = Buffer.from(v, 'base64url');
  if (size && b.length !== size) throw Error(`Expected signature length ${size}, got ${b.length}`);
  return b;
}

function parseSpki(pubKeyInput) {
  if (typeof pubKeyInput !== 'string') throw Error('Invalid public key format');
  const trimmed = pubKeyInput.trim();
  if (trimmed.length === 64 && /^[0-9a-fA-F]+$/.test(trimmed)) {
    const raw = Buffer.from(trimmed, 'hex');
    return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
  }
  try {
    const rawB64 = Buffer.from(trimmed, 'base64');
    if (rawB64.length === 44 && rawB64[0] === 0x30) {
      return createPublicKey({ key: rawB64, format: 'der', type: 'spki' });
    }
  } catch (err) { }
  try {
    const rawUrl = Buffer.from(trimmed, 'base64url');
    if (rawUrl.length === 32) {
      return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawUrl]), format: 'der', type: 'spki' });
    }
  } catch (err) { }
  throw Error('Unable to parse Ed25519 public key');
}

function parseChainId(network) {
  if (typeof network === 'string' && network.startsWith('eip155:')) {
    return parseInt(network.slice(7), 10);
  }
  if (typeof network === 'number') return network;
  return 8453; // Base default
}

function parseTerms(response, responseBody) {
  const reqHeader = response.headers.get('payment-required');
  if (reqHeader) {
    try {
      const decoded = Buffer.from(reqHeader, 'base64').toString('utf8');
      return JSON.parse(decoded);
    } catch (err) { }
  }
  if (responseBody && typeof responseBody === 'object') {
    return responseBody;
  }
  return {};
}

function validateChallenge(terms) {
  const reqs = terms.payment_requirements || terms.requirements || terms.accepted || (Array.isArray(terms.accepts) ? terms.accepts[0] : null);
  if (!reqs) {
    throw Error('Invalid 402 challenge: missing payment requirements');
  }
  if (!reqs.payTo || !/^0x[0-9a-fA-F]{40}$/.test(reqs.payTo)) {
    throw Error('Invalid 402 challenge: invalid or missing payTo address');
  }
  if (!reqs.asset || !/^0x[0-9a-fA-F]{40}$/.test(reqs.asset)) {
    throw Error('Invalid 402 challenge: invalid or missing asset address');
  }
  if (!reqs.amount || !/^[0-9]+$/.test(String(reqs.amount))) {
    throw Error('Invalid 402 challenge: invalid or missing amount');
  }
  if (reqs.network && !/^eip155:[0-9]+$/.test(reqs.network)) {
    throw Error('Invalid 402 challenge: unsupported network: ' + reqs.network);
  }
  return { requirements: reqs, resource: terms.resource || {} };
}

function generateRandomNonce() {
  return '0x' + randomBytes(32).toString('hex');
}

function deriveStandingNonce(quotePayload) {
  const preimage = canonical({
    domain: 'WHP-STANDING-PURCHASE-BINDING-v1',
    quote: quotePayload,
  });
  return '0x' + createHash('sha256').update(preimage).digest('hex');
}

function prepareAutonomousPayment(terms, payerAddress, options = {}) {
  const { requirements: reqs, resource } = validateChallenge(terms);
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const buffer = options.timeoutBufferSeconds ?? Math.min(reqs.maxTimeoutSeconds || 300, 300);

  let nonce;
  if (reqs.nonce && /^0x[0-9a-fA-F]{64}$/.test(reqs.nonce)) {
    nonce = reqs.nonce.toLowerCase();
  } else if (terms.quote?.payload) {
    nonce = deriveStandingNonce(terms.quote.payload);
  } else {
    nonce = generateRandomNonce();
  }

  const validAfter = String(Math.max(0, now - 60));
  const validBefore = String(terms.expires_at ? Math.min(terms.expires_at, now + buffer) : now + buffer);

  const authorization = {
    from: payerAddress.toLowerCase(),
    to: reqs.payTo.toLowerCase(),
    value: String(reqs.amount),
    validAfter,
    validBefore,
    nonce,
  };

  const domain = {
    name: reqs.extra?.name || 'USD Coin',
    version: reqs.extra?.version || '2',
    chainId: parseChainId(reqs.network),
    verifyingContract: reqs.asset.toLowerCase(),
  };

  const types = {
    TransferWithAuthorization: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' },
      { name: 'nonce', type: 'bytes32' },
    ],
  };

  const typedData = {
    domain,
    types,
    primaryType: 'TransferWithAuthorization',
    message: authorization,
  };

  const completePayment = (signature) => ({
    x402Version: 2,
    resource,
    accepted: reqs,
    payload: {
      signature,
      authorization,
    },
  });

  return {
    typedData,
    authorization,
    requirements: reqs,
    resource,
    completePayment,
  };
}

function formatPaymentSignatureHeader(submission) {
  return Buffer.from(JSON.stringify(submission)).toString('base64');
}

function resolveCredential(env = process.env) {
  let buyerKey = (env.WHP_BUYER_KEY || '').trim();
  let staticCreditToken = '';
  let staticPaymentSignature = '';

  const rawPayment = (env.WHP_PAYMENT || env.WHP_PAYMENT_KEY || '').trim();
  if (rawPayment) {
    if (/^whp_[0-9a-fA-F]{64}$/.test(rawPayment)) {
      staticCreditToken = rawPayment;
    } else if (rawPayment.startsWith('{') || isBase64JsonPayload(rawPayment)) {
      staticPaymentSignature = rawPayment;
    } else if (/^(0x)?[0-9a-fA-F]{64}$/.test(rawPayment)) {
      if (!buyerKey) {
        buyerKey = rawPayment;
      }
    } else {
      throw Error('Unrecognized credential format in WHP_PAYMENT / WHP_PAYMENT_KEY. Expected prepaid credit token (whp_...), x402 payment signature payload, or 32-byte hex private key.');
    }
  }

  if (buyerKey && !/^(0x)?[0-9a-fA-F]{64}$/.test(buyerKey)) {
    throw Error('Invalid WHP_BUYER_KEY: must be a 32-byte hex private key.');
  }

  return { buyerKey, staticCreditToken, staticPaymentSignature };
}

function isBase64JsonPayload(str) {
  try {
    const dec = Buffer.from(str, 'base64').toString('utf8');
    if (!dec.startsWith('{')) return false;
    const parsed = JSON.parse(dec);
    return !!(parsed && (parsed.x402Version || parsed.payload || parsed.signature));
  } catch (err) { 
    return false;
  }
}

async function signTypedDataPayload(signerOrKey, prep) {
  // If an external/simulated signer object is provided
  if (signerOrKey && typeof signerOrKey === 'object') {
    if (typeof signerOrKey.signTypedData === 'function') {
      const from = (signerOrKey.address || prep.authorization.from).toLowerCase();
      prep.authorization.from = from;
      prep.typedData.message.from = from;
      const sig = await signerOrKey.signTypedData(prep.typedData);
      return typeof sig === 'string' ? sig : sig.signature;
    }
    if (typeof signerOrKey.request === 'function') {
      // EIP-1193 provider
      const from = (signerOrKey.address || prep.authorization.from).toLowerCase();
      prep.authorization.from = from;
      prep.typedData.message.from = from;
      return signerOrKey.request({
        method: 'eth_signTypedData_v4',
        params: [from, JSON.stringify(prep.typedData)],
      });
    }
  }

  // If a private key string is provided
  if (typeof signerOrKey === 'string' && /^(0x)?[0-9a-fA-F]{64}$/.test(signerOrKey)) {
    const key = signerOrKey.startsWith('0x') ? signerOrKey : '0x' + signerOrKey;
    let viemAccounts;
    try {
      viemAccounts = await import('viem/accounts');
    } catch (e) {
      throw Error('Dynamic EIP-3009 signing with WHP_BUYER_KEY requires viem dependency: ' + e.message);
    }
    const acct = viemAccounts.privateKeyToAccount(key);
    prep.authorization.from = acct.address.toLowerCase();
    prep.typedData.message.from = acct.address.toLowerCase();
    return acct.signTypedData({
      domain: prep.typedData.domain,
      types: prep.typedData.types,
      primaryType: prep.typedData.primaryType,
      message: {
        ...prep.authorization,
        value: BigInt(prep.authorization.value),
        validAfter: BigInt(prep.authorization.validAfter),
        validBefore: BigInt(prep.authorization.validBefore),
      },
    });
  }

  throw Error('No supported signer available to sign EIP-3009 TransferWithAuthorization');
}


function parseStructuredInput(raw, label = 'WHP_INPUT_JSON') {
  if (!raw || !String(raw).trim()) return null;
  let value;
  try {
    value = JSON.parse(String(raw));
  } catch (error) {
    throw Error(`${label} must contain valid JSON: ${error.message}`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw Error(`${label} must be a JSON object matching the evaluation request contract`);
  }
  return value;
}

function formatAdjudicationReport(record, signature, recordHash, signatureStatus, disposition, continuity) {
  const lines = [
    '## Decision Integrity Examination',
    '',
    '### Submitted examination',
    '```json',
    JSON.stringify(record.input ?? null, null, 2),
    '```',
    '',
    '### Evaluator determination (verbatim record content)',
    '```json',
    JSON.stringify(record.determination ?? null, null, 2),
    '```',
    ''
  ];

  if (continuity && (continuity.status || continuity.prior_record_hash)) {
    lines.push(
      '### Successive examination and continuity',
      `- Lineage status: **${continuity.status || 'UNSPECIFIED'}**`,
      `- Prior examination record hash: \`${continuity.prior_record_hash || record.prior_record_hash || 'none'}\``,
      `- Source object identity preserved: **${continuity.source_object_carried_forward ? 'Yes' : continuity.source_object_comparison?.identity_preserved ? 'Yes' : 'No'}**`,
      `- Prior record preserved immutable: **${continuity.prior_record_preserved ? 'Yes' : 'N/A'}**`,
      `- New evidence introduced: ${Array.isArray(continuity.new_evidence_introduced) ? continuity.new_evidence_introduced.length : 0}`
    );
    if (Array.isArray(continuity.new_evidence_introduced) && continuity.new_evidence_introduced.length > 0) {
      for (const item of continuity.new_evidence_introduced) {
        lines.push(`  * \`${typeof item === 'string' ? item : JSON.stringify(item)}\``);
      }
    }
    if (continuity.changed_conditions) {
      lines.push(
        `- Changed conditions: added=${Array.isArray(continuity.changed_conditions.added) ? continuity.changed_conditions.added.length : 0}, dropped=${Array.isArray(continuity.changed_conditions.dropped) ? continuity.changed_conditions.dropped.length : 0}`
      );
    }
    if (Array.isArray(continuity.prior_unknowns_addressed) && continuity.prior_unknowns_addressed.length > 0) {
      lines.push(`- Prior unknowns resolved by new evidence: ${continuity.prior_unknowns_addressed.join(', ')}`);
    }
    lines.push('');
  }

  lines.push(
    '### Record integrity',
    `- Record type: \`${record.type || 'not supplied'}\``,
    `- Record hash (SHA-256 of canonical record): \`${recordHash}\``,
    `- Signature algorithm: \`${signature?.alg || 'not supplied'}\``,
    `- Signature public key: \`${signature?.public_key_b64url || 'not supplied'}\``,
    `- Signature check: **${signatureStatus}**`,
    '- Verification endpoint: https://decisionintegrity.wheelerhubbellpublishing.com/v1/verification',
    '',
    '### Client reception (separate from the examination)',
    `- Workflow disposition: **${disposition}**`,
    '- This is a client-side reception event. It does not alter, extend, or authenticate the signed examination record.',
    '- The workflow allowlist is not a statement that consequential action is authorized.',
    ''
  );
  return lines.join('\n');
}

function makeReceptionEvent(recordHash, outcome, continued, continuity) {
  return {
    type: 'WHP-CLIENT-RECEPTION-EVENT-v1',
    received_at: new Date().toISOString(),
    examination_record_hash: recordHash,
    prior_examination_record_hash: continuity?.prior_record_hash ?? null,
    continuity_status: continuity?.status ?? null,
    examination_outcome: outcome ?? null,
    workflow_disposition: continued ? 'CONTINUED_BY_CONFIGURED_OUTCOME_ALLOWLIST' : 'BLOCKED_BY_CONFIGURED_OUTCOME_ALLOWLIST',
    authority_boundary: 'Client workflow disposition only; not evaluator authorization and not a mutation of the examination record.'
  };
}

function appendMultilineOutput(filePath, name, value) {
  const delimiter = `WHP_${name}_${randomBytes(12).toString('hex')}`;
  fs.appendFileSync(filePath, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

async function run(options = {}) {
  const env = options.env || process.env;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const customSigner = options.signer || null;

  const origin = new URL(env.WHP_URL || 'https://decisionintegrity.wheelerhubbellpublishing.com');
  if (origin.protocol !== 'https:' && origin.hostname !== 'localhost' && origin.hostname !== '127.0.0.1') {
    throw Error('HTTPS service required');
  }
  const door = env.WHP_DOOR || '/v1/evaluate';
  const mock = env.WHP_MOCK === 'true';
  let provenance = {
    source: 'github-actions',
    authority: 'repository-workflow',
    evidence: [{
      repository: env.WHP_REPOSITORY || 'wheelerhubbell/standing-gate',
      sha: env.WHP_SHA || 'head',
      ref: env.WHP_REF || 'refs/heads/main',
      actor: env.WHP_ACTOR || 'github-actions',
      timestamp: new Date().toISOString()
    }]
  };

  const rawProv = (env.WHP_PROVENANCE || '').trim();
  if (rawProv) {
    try {
      provenance = JSON.parse(rawProv);
    } catch {
      provenance = {
        source: rawProv,
        uri: rawProv,
        authority: 'repository-workflow',
        evidence: [{
          repository: env.WHP_REPOSITORY || 'wheelerhubbell/standing-gate',
          sha: env.WHP_SHA || 'head',
          ref: env.WHP_REF || 'refs/heads/main',
          actor: env.WHP_ACTOR || 'github-actions',
          timestamp: new Date().toISOString()
        }]
      };
    }
  }

  const structuredInput = options.input ?? parseStructuredInput(env.WHP_INPUT_JSON, 'WHP_INPUT_JSON');
  const priorRecordHash = (options.priorRecordHash || env.WHP_PRIOR_RECORD_HASH || env.INPUT_PRIOR_RECORD_HASH || '').trim();
  const rawPriorRecord = (options.priorRecord || env.WHP_PRIOR_RECORD_JSON || env.INPUT_PRIOR_RECORD_JSON || '');
  let priorRecordObj = null;
  if (rawPriorRecord) {
    try {
      priorRecordObj = typeof rawPriorRecord === 'string' ? JSON.parse(rawPriorRecord.trim()) : rawPriorRecord;
    } catch (e) {
      throw Error(`Failed to parse prior_record JSON: ${e.message}`);
    }
  }

  let input = structuredInput
    ? { ...structuredInput }
    : {
        subject: env.WHP_SUBJECT || 'wheelerhubbell/standing-gate',
        claim: env.WHP_CLAIM || 'Release integrity verification',
        provenance
      };

  if (priorRecordHash && !input.prior_record_hash && !input.continuity?.prior_record_hash) {
    input.prior_record_hash = priorRecordHash;
  }
  if (priorRecordObj && !input.prior_record) {
    input.prior_record = priorRecordObj;
  }

  const apiKey = (env.WHP_API_KEY || '').trim();
  const { buyerKey, staticCreditToken, staticPaymentSignature } = resolveCredential(env);
  const activeSigner = customSigner || buyerKey;

  const headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; WHP-Standing-Gate/1.0)',
    'Content-Type': 'application/json'
  };
  if (mock) headers['X-Mock'] = 'true';

  // Apply API key if provided
  if (apiKey) {
    headers['x-api-key'] = apiKey;
    headers['Authorization'] = 'Bearer ' + apiKey;
  }

  // Apply pre-formed static credentials if provided
  if (staticCreditToken) {
    headers['Authorization'] = 'Bearer ' + staticCreditToken;
    headers['PAYMENT-SIGNATURE'] = staticCreditToken;
  } else if (staticPaymentSignature) {
    headers['PAYMENT-SIGNATURE'] = staticPaymentSignature;
  }

  const proactive = options.proactive !== false && env.WHP_PROACTIVE !== "false";
    // Proactive Zero-Handshake M2M: If signer is provided, pre-sign canonical terms on Call #1
  if (proactive && activeSigner && !staticCreditToken && !staticPaymentSignature && door === "/v1/evaluate") {
        try {
      const canonicalTerms = {
        accepted: {
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          payTo: "0x1050eddd8282623b0c263ed6bdbd42370bbc28d3",
          amount: "1000000",
          extra: { assetTransferMethod: "eip3009", name: "USD Coin", paymentFlow: "authorization", version: "2" },
          resource: new URL(door, origin).toString()
        }
      };
      let payerAddress = options.payer || (activeSigner && typeof activeSigner === "object" ? activeSigner.address : null);
      if (!payerAddress && typeof activeSigner === "string" && /^(0x)?[0-9a-fA-F]{64}$/.test(activeSigner)) {
        const { privateKeyToAccount } = await import("viem/accounts");
        const key = activeSigner.startsWith("0x") ? activeSigner : "0x" + activeSigner;
        payerAddress = privateKeyToAccount(key).address;
      }
      if (payerAddress) {
        const prep = prepareAutonomousPayment(canonicalTerms, payerAddress, options);
        const signature = await signTypedDataPayload(activeSigner, prep);
        const submission = prep.completePayment(signature);
        headers["PAYMENT-SIGNATURE"] = formatPaymentSignatureHeader(submission);
      }
    } catch (err) { 
      // Fallback to reactive 402 challenge flow
    }
  }

  const postUrl = new URL(door, origin);
  let response = await fetchImpl(postUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(input),
    redirect: 'error',
    signal: AbortSignal.timeout(20000)
  });

  // Handle 402 challenge
  if (response.status === 402) {
    const rawBody = await response.text().catch(() => '');
    let bodyJson = null;
    try { bodyJson = JSON.parse(rawBody); } catch (err) { }

    if (staticCreditToken || staticPaymentSignature) {
      console.error('Static payment credential refused by service (402):', bodyJson?.error || rawBody);
      throw Error('Payment required (402): static credential rejected (' + (bodyJson?.error || 'INVALID') + ')');
    }

    if (!activeSigner) {
      console.error('PAYMENT_REQUIRED: Paid door requires x402 payment authorization (1 USDC on Base or prepaid developer credits)');
      if (bodyJson?.accepts) {
        console.error('Accepts:', JSON.stringify(bodyJson.accepts, null, 2));
      }
      if (mock) {
        console.error('NOTE: Mock/dry-run bypass is discontinued in production in accordance with Decision Integrity Protocol v1.0. Supply WHP_BUYER_KEY or payment_signature for live evaluation.');
      }
      throw Error('Payment required (402)');
    }

    // Dynamic x402 Handshake
    const terms = parseTerms(response, bodyJson);
    const payerAddress = (typeof activeSigner === 'object' && activeSigner.address)
      ? activeSigner.address
      : (buyerKey ? (await import('viem/accounts')).privateKeyToAccount(buyerKey.startsWith('0x') ? buyerKey : '0x' + buyerKey).address : '0x0000000000000000000000000000000000000000');

    const prep = prepareAutonomousPayment(terms, payerAddress, options);
    const signature = await signTypedDataPayload(activeSigner, prep);
    const submission = prep.completePayment(signature);
    const paymentHeader = formatPaymentSignatureHeader(submission);

    const retryHeaders = {
      ...headers,
      'PAYMENT-SIGNATURE': paymentHeader,
    };

    response = await fetchImpl(postUrl, {
      method: 'POST',
      headers: retryHeaders,
      body: JSON.stringify(input),
      redirect: 'error',
      signal: AbortSignal.timeout(20000)
    });

    if (response.status !== 200) {
      const errText = await response.text().catch(() => '');
      throw Error(`Payment authorization refused (HTTP ${response.status}): ${errText}`);
    }
  }

  if (response.status !== 200) {
    throw Error(`HTTP ${response.status}: ${await response.text().catch(() => '')}`);
  }

  const data = await response.json();

  // Mock handling
  if (mock) {
    if ((data?.mock !== true && data?.not_a_determination !== true) || data.structurally_complete !== true) {
      throw Error('Malformed or failed requested mock check');
    }
    console.log('DRY_RUN_PASSED: non-authorizing structural check');
    if (env.GITHUB_OUTPUT) {
      fs.appendFileSync(env.GITHUB_OUTPUT, 'outcome=DRY_RUN_PASSED\nhash=\n');
    }
    return { outcome: 'DRY_RUN_PASSED', hash: '' };
  }

  // Key discovery
  let signingKeyObj = null;
  const discResp = await fetchImpl(new URL('/v1/evaluate', origin), {
    headers: { 'User-Agent': 'Mozilla/5.0' },
    cache: 'no-store',
    signal: AbortSignal.timeout(20000)
  }).catch(() => null);

  if (discResp && discResp.status === 200) {
    const disc = await discResp.json().catch(() => ({}));
    if (disc?.signer?.public_key_b64url) {
      signingKeyObj = parseSpki(disc.signer.public_key_b64url);
    } else if (disc?.signer?.public_key_base64) {
      signingKeyObj = parseSpki(disc.signer.public_key_base64);
    } else if (disc?.verification_url) {
      const verResp = await fetchImpl(new URL(disc.verification_url, origin), {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        cache: 'no-store'
      }).catch(() => null);
      if (verResp && verResp.status === 200) {
        const ver = await verResp.json().catch(() => ({}));
        const pub =
          ver?.authoritative_public_key?.public_key_base64 ||
          ver?.authoritative_public_key?.public_key_b64url ||
          ver?.authoritative_public_key?.legacy_public_key_b64url;
        if (pub) signingKeyObj = parseSpki(pub);
      }
    } else if (disc?.admission_url) {
      const admResp = await fetchImpl(new URL(disc.admission_url, origin), {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        cache: 'no-store'
      }).catch(() => null);
      if (admResp && admResp.status === 200) {
        const adm = await admResp.json().catch(() => ({}));
        const pub = adm?.issuer_certificate?.payload?.public_key;
        if (pub) signingKeyObj = parseSpki(pub);
      }
    }
  }

  // Format 1: WHP-FRONTDOOR-EVALUATION-v1
  if (data.record && data.signature) {
    const { record, signature, record_hash } = data;
    if (record.type !== 'WHP-FRONTDOOR-EVALUATION-v1') throw Error('Unexpected record type: ' + record.type);
    if (record.mock === true || record.environment === 'TEST') throw Error('Mock/test record returned in live mode');

    const bytes = Buffer.from(canonical(record));
    const computedHash = createHash('sha256').update(bytes).digest('hex');
    if (computedHash !== record_hash) throw Error('Record hash mismatch');

    if (!signingKeyObj) {
      throw Error('Could not obtain the live /v1/evaluate issuer key; refusing to label the examination signature verified');
    }
    const embeddedKey = parseSpki(signature.public_key_b64url);
    const expectedRaw = signingKeyObj.export({ format: 'der', type: 'spki' }).subarray(-32);
    const embeddedRaw = embeddedKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    if (!expectedRaw.equals(embeddedRaw)) {
      throw Error('Record signer does not match the live /v1/evaluate issuer key');
    }
    const sigBytes = decodeB64Url(signature.value_b64url, 64);
    if (!cryptoVerify(null, bytes, signingKeyObj, sigBytes)) {
      throw Error('Ed25519 signature verification failed');
    }
    const signatureStatus = 'VERIFIED_AGAINST_LIVE_DISCOVERY_KEY';

    const outcome = record.determination?.outcome;
    const positiveOutcomes = [
      'RECOGNIZED WITH BOUNDARIES',
      'ESTABLISHED',
      'ACCEPTED',
      'BOUNDED_DETERMINATION',
      'CONDITIONAL_PASS'
    ];
    if (!positiveOutcomes.includes(outcome)) {
      throw Error(`Non-positive determination: ${outcome}`);
    }

    const continuity =
      record.determination?.standing_record?.continuity ||
      record.determination?.reasoning_environment?.continuity ||
      record.continuity ||
      (record.prior_record_hash ? { status: 'PRIOR_RECORD_REFERENCED', prior_record_hash: record.prior_record_hash } : null);

    const continued = positiveOutcomes.includes(outcome);
    const reception = makeReceptionEvent(record_hash, outcome, continued, continuity);
    const report = formatAdjudicationReport(record, signature, record_hash, signatureStatus, reception.workflow_disposition, continuity);
    console.log(`WHP_EVALUATION_RECEIVED: outcome=${outcome}; workflow=${continued ? 'continued' : 'blocked'}`);
    console.log(`RECORD_HASH: ${record_hash}`);
    if (continuity?.status) {
      console.log(`CONTINUITY_STATUS: ${continuity.status} (prior: ${continuity.prior_record_hash || 'none'})`);
    }
    console.log(report);

    if (env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(env.GITHUB_STEP_SUMMARY, report + '\n');
    }
    if (env.GITHUB_OUTPUT) {
      fs.appendFileSync(env.GITHUB_OUTPUT, `outcome=${outcome}\nhash=${record_hash}\nsignature_status=${signatureStatus}\nworkflow_disposition=${continued ? 'continued' : 'blocked'}\nprior_record_hash=${continuity?.prior_record_hash || ''}\ncontinuity_status=${continuity?.status || ''}\n`);
      appendMultilineOutput(env.GITHUB_OUTPUT, 'record_json', JSON.stringify(data, null, 2));
      appendMultilineOutput(env.GITHUB_OUTPUT, 'reception_event_json', JSON.stringify(reception, null, 2));
    }

    if (!continued) throw Error(`Non-positive determination: ${outcome}`);
    return { outcome, hash: record_hash, record, signature, signatureStatus, reception, report, continuity };
  }

  // Format 2: Sealed WHP-STANDING-MARK-v2 / WHP-STANDING-RESULT-v2 / WHP-STANDING-MARK-v1
  if (data.protected && data.payload && data.signature) {
    const envelope = data;
    const kind = envelope.protected.type;
    const bytes = Buffer.from(canonical({ protected: envelope.protected, payload: envelope.payload }));

    let signatureStatus = 'UNVERIFIED';
    if (signingKeyObj) {
      const sigBytes = Buffer.from(envelope.signature, 'base64');
      if (!cryptoVerify(null, bytes, signingKeyObj, sigBytes)) {
        throw Error('Sealed Mark Ed25519 signature verification failed');
      }
      signatureStatus = 'VERIFIED';
    } else {
      signatureStatus = 'KEY_UNRESOLVED';
    }

    const outcome = envelope.payload.decision_record?.outcome || envelope.payload.outcome;
    const disposition =
      envelope.payload.finding_disposition ||
      (outcome === 'ESTABLISHED' ? 'POSITIVE_STANDING_MARK' : 'NEGATIVE_STANDING_FINDING');
    const refHash =
      envelope.payload.mark_id ||
      envelope.payload.decision_record_ref ||
      createHash('sha256').update(bytes).digest('hex');

    const continued = outcome === 'ESTABLISHED';
    const reception = makeReceptionEvent(refHash, outcome, continued, null);

    const summary = [
      `### WHP Standing Mark Result: \`${outcome}\``,
      `- **Type:** \`${kind}\``,
      `- **Mark ID / Hash:** \`${refHash}\``,
      `- **Disposition:** \`${disposition}\``,
      `- **Signature Status:** \`${signatureStatus}\``,
      `- **Workflow Action:** \`${continued ? 'CONTINUED' : 'BLOCKED'}\``,
    ].join('\n');

    console.log(`STANDING_RESULT: ${kind} outcome=${outcome} disposition=${disposition} sig=${signatureStatus}`);
    console.log(`RECORD_REF: ${refHash}`);
    console.log(summary);

    if (env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(env.GITHUB_STEP_SUMMARY, summary + '\n');
    }
    if (env.GITHUB_OUTPUT) {
      fs.appendFileSync(
        env.GITHUB_OUTPUT,
        `outcome=${outcome}\nhash=${refHash}\nsignature_status=${signatureStatus}\nworkflow_disposition=${continued ? 'continued' : 'blocked'}\n`
      );
      appendMultilineOutput(env.GITHUB_OUTPUT, 'record_json', JSON.stringify(data, null, 2));
      appendMultilineOutput(env.GITHUB_OUTPUT, 'reception_event_json', JSON.stringify(reception, null, 2));
    }

    if (!continued) {
      throw Error(`Standing outcome not established: ${outcome} (${disposition})`);
    }
    return { outcome, hash: refHash, mark: envelope, signatureStatus, reception };
  }

  throw Error('Unrecognized response format: expected signed front-door record or sealed Standing Mark');
}


// Authoritative WHP Signer Keys.
// The receiving boundary ONLY accepts signatures from WHP authoritative issuer keys.
// Requesting workflows and callers cannot substitute or supply their own issuer keys.
const AUTHORITATIVE_ISSUER_KEYS = [
  "MCowBQYDK2VwAyEABE1ix0WObYNYEsVQm36qIjzqajWCilAwZxbpo3aKCPY=", // Authoritative published key (key_id: baabb9cd21f367bb8467f1bce570cd1f4ef1b418172f2cb68968ebe7186f487e)
  "MCowBQYDK2VwAyEAcpFVUj6xDgsUsKJK2r2rLk6R+te2lghdHE8jvjl9SBk="  // Live PHP service key
];

function resolveKeyObj(rawInput) {
  if (!rawInput) return null;
  if (typeof rawInput === "object" && rawInput.type === "public") return rawInput;
  if (typeof rawInput === "string") {
    const trimmed = rawInput.trim();
    if (trimmed.startsWith("-----BEGIN")) {
      try { return createPublicKey(trimmed); } catch (e) { return null; }
    }
    try { return parseSpki(trimmed); } catch (e) { return null; }
  }
  return null;
}

// Returns { value } for a present, non-empty string claim, { missing: true }
// when no candidate field carries anything, or { malformed: true } when a
// defined candidate is not a usable proposition string. A defined but
// malformed claim field never falls through to a later candidate.
function strictClaim(candidates) {
  for (const c of candidates) {
    if (c === undefined || c === null) continue;
    if (typeof c === "string" && c.trim()) return { value: c.trim() };
    return { malformed: true };
  }
  return { missing: true };
}

function verify(request, mark, options = {}) {
  // 1. Missing, unreadable, or invalid input fails closed
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return {
      allow: false,
      reason_code: "MISSING_OR_INVALID_REQUEST",
      message: "Request must be a non-null object specifying the intended action"
    };
  }

  if (mark == null) {
    return {
      allow: false,
      reason_code: "MISSING_MARK",
      message: "Standing Mark is required"
    };
  }

  let envelope = mark;
  if (typeof envelope === "string") {
    try {
      envelope = JSON.parse(envelope.trim());
    } catch (err) {
      return {
        allow: false,
        reason_code: "UNREADABLE_MARK",
        message: "Standing Mark is not valid JSON"
      };
    }
  }

  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return {
      allow: false,
      reason_code: "UNREADABLE_MARK",
      message: "Standing Mark must be an object"
    };
  }

  // 2. Identify envelope format
  // Format A: Sealed envelope { protected, payload, signature }
  // Format B: Frontdoor evaluation { record, signature, record_hash }
  const isFormatA = !!(envelope.protected && envelope.payload && envelope.signature);
  const isFormatB = !!(envelope.record && envelope.signature);

  if (!isFormatA && !isFormatB) {
    return {
      allow: false,
      reason_code: "UNRECOGNIZED_MARK_FORMAT",
      message: "Mark format not recognized: expected sealed envelope or frontdoor evaluation"
    };
  }

  // 3. Authoritative Signer Key Resolution
  // The requesting workflow or caller cannot substitute or supply an arbitrary issuer key.
  // Only authoritative WHP keys are trusted. For internal unit test fixtures only,
  // options._trustedKeyForTesting may provide an isolated key.
  const trustedKeys = [];
  if (options._trustedKeyForTesting) {
    const k = resolveKeyObj(options._trustedKeyForTesting);
    if (k) trustedKeys.push(k);
  } else {
    for (const c of AUTHORITATIVE_ISSUER_KEYS) {
      const k = resolveKeyObj(c);
      if (k) trustedKeys.push(k);
    }
  }

  let payload = null;
  let record = null;
  let outcome = null;
  let markId = null;
  let bounds = null;
  let objectBinding = null;
  let proposition = null;
  let sigVerified = false;

  if (isFormatA) {
    payload = envelope.payload;
    if (!payload || typeof payload !== "object") {
      return { allow: false, reason_code: "UNREADABLE_MARK", message: "Malformed payload in sealed Mark" };
    }

    const bytes = Buffer.from(canonical({ protected: envelope.protected, payload: envelope.payload }));
    let sigBytes;
    try {
      const sigStr = String(envelope.signature);
      sigBytes = /^[A-Za-z0-9_-]+$/.test(sigStr) && !sigStr.includes("+") && !sigStr.includes("/")
        ? Buffer.from(sigStr, "base64url")
        : Buffer.from(sigStr, "base64");
    } catch (e) {
      return { allow: false, reason_code: "INVALID_SIGNATURE", message: "Unable to decode signature bytes" };
    }

    for (const keyObj of trustedKeys) {
      try {
        if (cryptoVerify(null, bytes, keyObj, sigBytes)) {
          sigVerified = true;
          break;
        }
      } catch (e) {}
    }

    if (!sigVerified) {
      return {
        allow: false,
        reason_code: "INVALID_SIGNATURE",
        message: "Signature verification failed against authoritative WHP issuer key"
      };
    }

    outcome = payload.decision_record?.outcome || payload.outcome;
    markId = payload.mark_id || payload.decision_record_ref || createHash("sha256").update(bytes).digest("hex");
    bounds = payload.bounds || { valid_from: payload.issued_at, valid_until: payload.expires_at };
    objectBinding = payload.object_binding || payload.decision_record?.object_binding || {};
    proposition = payload.decision_record?.proposition || payload.claim || objectBinding.claim;
  } else if (isFormatB) {
    record = envelope.record;
    if (!record || typeof record !== "object") {
      return { allow: false, reason_code: "UNREADABLE_MARK", message: "Malformed record in frontdoor Mark" };
    }

    const bytes = Buffer.from(canonical(record));
    const computedHash = createHash("sha256").update(bytes).digest("hex");

    if (envelope.record_hash && envelope.record_hash !== computedHash) {
      return {
        allow: false,
        reason_code: "TAMPERED_RECORD",
        message: "Record hash mismatch: canonical bytes do not match record_hash"
      };
    }

    const sigObj = envelope.signature;
    if (!sigObj || typeof sigObj !== "object") {
      return { allow: false, reason_code: "INVALID_SIGNATURE", message: "Missing signature object" };
    }

    let sigBytes;
    try {
      if (sigObj.value_b64url) {
        sigBytes = decodeB64Url(sigObj.value_b64url, 64);
      } else if (sigObj.value_base64 || sigObj.value) {
        sigBytes = Buffer.from(sigObj.value_base64 || sigObj.value, "base64");
      } else {
        return { allow: false, reason_code: "INVALID_SIGNATURE", message: "Missing signature value" };
      }
    } catch (e) {
      return { allow: false, reason_code: "INVALID_SIGNATURE", message: "Invalid signature encoding: " + e.message };
    }

    let signerKeyObj = null;
    const pubKeyInput = sigObj.public_key_b64url || sigObj.public_key_base64 || sigObj.public_key;
    if (pubKeyInput) {
      signerKeyObj = resolveKeyObj(pubKeyInput);
    }

    let keyAuthorized = false;
    if (signerKeyObj) {
      const embeddedRaw = signerKeyObj.export({ format: "der", type: "spki" }).subarray(-32);
      for (const trusted of trustedKeys) {
        const trustedRaw = trusted.export({ format: "der", type: "spki" }).subarray(-32);
        if (embeddedRaw.equals(trustedRaw)) {
          keyAuthorized = true;
          break;
        }
      }
    } else {
      for (const trusted of trustedKeys) {
        try {
          if (cryptoVerify(null, bytes, trusted, sigBytes)) {
            sigVerified = true;
            keyAuthorized = true;
            break;
          }
        } catch (e) {}
      }
    }

    if (!keyAuthorized && !sigVerified) {
      return {
        allow: false,
        reason_code: "UNAUTHORIZED_KEY",
        message: "Signer key is not an authoritative WHP issuer key"
      };
    }

    if (!sigVerified) {
      if (!cryptoVerify(null, bytes, signerKeyObj, sigBytes)) {
        return {
          allow: false,
          reason_code: "INVALID_SIGNATURE",
          message: "Ed25519 signature verification failed"
        };
      }
      sigVerified = true;
    }

    outcome = record.determination?.outcome || record.outcome;
    markId = envelope.record_hash || computedHash;
    bounds = record.bounds || { valid_from: record.timestamp, valid_until: null };
    objectBinding = record.object_binding || record.input || {};
    proposition = record.input?.claim || record.input?.proposition || objectBinding.claim;
  }

  // 4. Outcome check: must be ESTABLISHED
  if (outcome !== "ESTABLISHED") {
    return {
      allow: false,
      reason_code: "OUTCOME_NOT_ESTABLISHED",
      message: `Standing outcome is ${outcome || "UNSPECIFIED"}; required ESTABLISHED`
    };
  }

  // 4b. Signed authorization check.
  // A valid signature authenticates what the issuer signed; it cannot convert
  // an explicit signed denial of authorization into permission. An explicit
  // authorization: false in the signed content denies passage.
  const signedAuthorization = isFormatA
    ? (payload.authorization !== undefined ? payload.authorization : payload.decision_record?.authorization)
    : (record.authorization !== undefined ? record.authorization : record.determination?.authorization);
  const isExplicitDenial = signedAuthorization === false ||
    (signedAuthorization !== null && typeof signedAuthorization === "object" &&
      (signedAuthorization.authorized === false ||
       signedAuthorization.permitted === false ||
       signedAuthorization.allow === false));
  if (isExplicitDenial) {
    return {
      allow: false,
      reason_code: "AUTHORIZATION_DENIED",
      message: "The signed record explicitly denies authorization (authorization: false); a valid signature authenticates the denial, it does not convert it into permission"
    };
  }

  // 5. Temporal validation: the Mark must be current and must carry complete,
  // parseable validity bounds. Missing or malformed bounds fail closed: the
  // contract establishes no freshness policy for unbounded or partially
  // bounded Marks, and none is invented here.
  const nowMs = typeof options.now === "number"
    ? options.now
    : (options.now instanceof Date ? options.now.getTime() : Date.now());
  const toleranceMs = (options.clockToleranceSeconds || 60) * 1000;

  if (!bounds || typeof bounds !== "object") {
    return {
      allow: false,
      reason_code: "MISSING_VALIDITY_BOUNDS",
      message: "Mark carries no validity bounds; the contract establishes no freshness policy for unbounded Marks, so passage is denied"
    };
  }
  if (bounds.valid_from === undefined || bounds.valid_from === null || bounds.valid_from === "") {
    return {
      allow: false,
      reason_code: "MISSING_VALIDITY_BOUNDS",
      message: "Mark is missing valid_from; the contract establishes no freshness policy for partially bounded Marks, so passage is denied"
    };
  }
  if (bounds.valid_until === undefined || bounds.valid_until === null || bounds.valid_until === "") {
    return {
      allow: false,
      reason_code: "MISSING_VALIDITY_BOUNDS",
      message: "Mark is missing valid_until; the contract establishes no freshness policy for open-ended Marks, so passage is denied"
    };
  }

  const fromMs = Date.parse(bounds.valid_from);
  if (isNaN(fromMs)) {
    return {
      allow: false,
      reason_code: "MALFORMED_VALIDITY",
      message: `Mark valid_from is not a parseable date: ${String(bounds.valid_from)}`
    };
  }
  const untilMs = Date.parse(bounds.valid_until);
  if (isNaN(untilMs)) {
    return {
      allow: false,
      reason_code: "MALFORMED_VALIDITY",
      message: `Mark valid_until is not a parseable date: ${String(bounds.valid_until)}`
    };
  }

  if (nowMs > untilMs + toleranceMs) {
    return {
      allow: false,
      reason_code: "MARK_EXPIRED",
      message: `Standing Mark expired at ${bounds.valid_until}`
    };
  }
  if (nowMs < fromMs - toleranceMs) {
    return {
      allow: false,
      reason_code: "MARK_NOT_YET_VALID",
      message: `Standing Mark not valid until ${bounds.valid_from}`
    };
  }

  if (options.maxAgeSeconds) {
    if ((nowMs - fromMs) > (options.maxAgeSeconds * 1000 + toleranceMs)) {
      return {
        allow: false,
        reason_code: "MARK_EXPIRED",
        message: `Standing Mark exceeded maximum allowable age of ${options.maxAgeSeconds}s`
      };
    }
  }

  // 6. Exact Action Binding: Operation, Target, Parameters, Claim, Evidence
  // Operation check: mandatory on both sides
  const reqOp = (request.operation || request.action || request.requested_operation || "").trim();
  if (!reqOp) {
    return {
      allow: false,
      reason_code: "MISSING_OPERATION",
      message: "Request must specify an operation"
    };
  }

  const markOp = (
    objectBinding.requested_operation ||
    objectBinding.operation ||
    objectBinding.action ||
    ""
  ).trim();

  if (!markOp) {
    return {
      allow: false,
      reason_code: "MISSING_MARK_OPERATION",
      message: "Mark does not specify a bound operation"
    };
  }

  if (reqOp.toUpperCase() !== markOp.toUpperCase()) {
    return {
      allow: false,
      reason_code: "OPERATION_MISMATCH",
      message: `Operation mismatch: request requested ${reqOp}, Mark was bound to ${markOp}`
    };
  }

  // Target check: mandatory on both sides
  const reqTarget = (
    request.target ||
    request.subject ||
    request.object_id ||
    (request.object && (request.object.id || request.object.target)) ||
    ""
  ).toString().trim();

  if (!reqTarget) {
    return {
      allow: false,
      reason_code: "MISSING_TARGET",
      message: "Request must specify a target object"
    };
  }

  const markTarget = (
    objectBinding.object_id ||
    objectBinding.subject ||
    objectBinding.target ||
    (objectBinding.object && (objectBinding.object.id || objectBinding.object.target)) ||
    ""
  ).toString().trim();

  if (!markTarget) {
    return {
      allow: false,
      reason_code: "MISSING_MARK_TARGET",
      message: "Mark does not specify a bound target object"
    };
  }

  if (reqTarget !== markTarget) {
    return {
      allow: false,
      reason_code: "OBJECT_MISMATCH",
      message: `Object mismatch: request target is ${reqTarget}, Mark is bound to ${markTarget}`
    };
  }

  // Parameters check: exact match when present
  const reqParams = request.parameters !== undefined ? request.parameters : (request.params !== undefined ? request.params : null);
  const markParams = objectBinding.parameters !== undefined ? objectBinding.parameters : (objectBinding.params !== undefined ? objectBinding.params : null);

  if (reqParams !== null) {
    if (markParams === null) {
      return {
        allow: false,
        reason_code: "PARAMETERS_MISMATCH",
        message: "Request specified parameters, but Mark has no parameter bindings"
      };
    }
    const reqCanonicalParams = canonical(reqParams);
    const markCanonicalParams = canonical(markParams);
    if (reqCanonicalParams !== markCanonicalParams) {
      return {
        allow: false,
        reason_code: "PARAMETERS_MISMATCH",
        message: "Parameter mismatch: request parameters do not match Mark parameters"
      };
    }
  }

  // Claim / proposition check: mandatory on both sides, exact comparison.
  // Neither a matching operation nor a matching target can substitute for a
  // missing proposition. Missing, malformed, or mismatched claims reject.
  const reqC = strictClaim([request.claim, request.proposition, request.statement, request.text]);
  if (reqC.missing) {
    return {
      allow: false,
      reason_code: "MISSING_CLAIM",
      message: "Request must carry the proposition (claim) it asks to have bound; a matching operation and target cannot substitute for it"
    };
  }
  if (reqC.malformed) {
    return {
      allow: false,
      reason_code: "MALFORMED_CLAIM",
      message: "Request claim is present but is not a non-empty proposition string"
    };
  }

  const markC = strictClaim(isFormatA
    ? [payload.decision_record?.proposition, payload.claim, objectBinding.claim, objectBinding.proposition]
    : [record.input?.claim, record.input?.proposition, objectBinding.claim, objectBinding.proposition]);
  if (markC.missing) {
    return {
      allow: false,
      reason_code: "MISSING_MARK_CLAIM",
      message: "The signed Mark carries no proposition to bind against the request; a matching operation and target cannot substitute for it"
    };
  }
  if (markC.malformed) {
    return {
      allow: false,
      reason_code: "MALFORMED_MARK_CLAIM",
      message: "The signed Mark's proposition is present but is not a non-empty proposition string"
    };
  }

  const reqClaim = reqC.value;
  const markClaim = markC.value;

  if (reqClaim !== markClaim) {
    return {
      allow: false,
      reason_code: "PROPOSITION_MISMATCH",
      message: "Proposition mismatch: request claim does not match Mark proposition"
    };
  }

  // Evidence and Lawful Unknowns check
  const unknowns = payload?.lawful_unknowns || record?.lawful_unknowns || [];
  for (const u of unknowns) {
    if (u && typeof u === "object") {
      const standing = (u.standing || u.status || "").toUpperCase();
      if (standing.includes("BLOCKING") || standing.includes("UNRESOLVED") || standing.includes("PREVENT")) {
        return {
          allow: false,
          reason_code: "UNRESOLVED_LAWFUL_UNKNOWN",
          message: `Mark contains blocking lawful unknown: ${u.id || u.description || "unresolved"}`
        };
      }
    }
  }

  const missingEvidence = record?.required_missing || payload?.required_missing || [];
  if (Array.isArray(missingEvidence) && missingEvidence.length > 0) {
    return {
      allow: false,
      reason_code: "REQUIRED_EVIDENCE_MISSING",
      message: `Mark notes missing required evidence: ${missingEvidence.join(", ")}`
    };
  }

  // 7. Replay Protection and Single-Use Consumption
  // Where single-use enforcement is configured, any inability to establish,
  // read, validate, or write consumption state prevents authorization.
  // There is no warning-followed-by-passage path.
  const replayStateError = (detail) => ({
    allow: false,
    reason_code: "REPLAY_STATE_UNAVAILABLE",
    message: `Single-use replay protection is configured but consumption state cannot be established: ${detail}`
  });

  const parseConsumedRecords = (content) => {
    // Returns the raw consumed-record entries, or throws on malformed state.
    const trimmed = content.trim();
    if (!trimmed) return [];
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      throw Error("consumption records file is not valid JSON");
    }
    if (!Array.isArray(parsed)) {
      throw Error("consumption records file does not contain an array");
    }
    for (const entry of parsed) {
      const id = typeof entry === "string" ? entry : (entry && typeof entry === "object" ? (entry.mark_id || entry.id) : undefined);
      if (typeof id !== "string" || !id) {
        throw Error("consumption records file contains a malformed entry");
      }
    }
    return parsed;
  };
  const consumedIdOf = (entry) => (typeof entry === "string" ? entry : entry.mark_id || entry.id);

  let consumedSet = null;
  let consumedSource = null;
  if (options.consumedMarks !== undefined && options.consumedMarks !== null) {
    if (options.consumedMarks instanceof Set) {
      consumedSet = options.consumedMarks;
      consumedSource = "set";
    } else if (Array.isArray(options.consumedMarks)) {
      consumedSet = new Set(options.consumedMarks);
      consumedSource = "array";
    } else {
      return replayStateError("consumedMarks must be a Set or an Array of consumed Mark IDs");
    }
  }

  if (!consumedSet && options.consumedRecordsFile) {
    consumedSource = "file";
    if (!fs.existsSync(options.consumedRecordsFile)) {
      // First use: establish the consumption state file. Inability to
      // establish it prevents authorization.
      try {
        fs.writeFileSync(options.consumedRecordsFile, "[]\n", { encoding: "utf8", flag: "wx" });
      } catch (e) {
        if (e.code !== "EEXIST") {
          return replayStateError(`cannot create consumption records file (${e.message})`);
        }
      }
    }
    let content;
    try {
      content = fs.readFileSync(options.consumedRecordsFile, "utf8");
    } catch (e) {
      return replayStateError(`cannot read consumption records file (${e.message})`);
    }
    try {
      consumedSet = new Set(parseConsumedRecords(content).map(consumedIdOf));
    } catch (e) {
      return replayStateError(e.message);
    }
  }

  if (consumedSet && consumedSet.has(markId)) {
    return {
      allow: false,
      reason_code: "REPLAY_DETECTED",
      message: `Replay detected: Mark ${markId} has already been consumed and cannot authorize repeated execution`
    };
  }

  // Nonce check if requested
  const reqNonce = request.nonce !== undefined ? String(request.nonce) : null;
  const markNonce = objectBinding.nonce !== undefined ? String(objectBinding.nonce) : (payload?.nonce !== undefined ? String(payload.nonce) : null);
  if (reqNonce !== null) {
    if (!markNonce || reqNonce !== markNonce) {
      return {
        allow: false,
        reason_code: "NONCE_MISMATCH",
        message: `Nonce mismatch: request requires nonce ${reqNonce}, Mark has ${markNonce || "none"}`
      };
    }
  }

  // Single-use consumption is recorded before passage is granted. If the
  // consumption record cannot be written, passage is denied.
  let consumedRecorded = false;
  if (consumedSet) {
    if (consumedSource === "file") {
      const lockDir = options.consumedRecordsFile + ".lock";
      let locked = false;
      for (let attempt = 0; attempt < 100 && !locked; attempt++) {
        try {
          fs.mkdirSync(lockDir);
          locked = true;
        } catch (e) {
          if (e.code !== "EEXIST") {
            return replayStateError(`cannot acquire consumption lock (${e.message})`);
          }
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        }
      }
      if (!locked) {
        return replayStateError("consumption records lock held by another process");
      }
      try {
        let lockedContent;
        try {
          lockedContent = fs.readFileSync(options.consumedRecordsFile, "utf8");
        } catch (e) {
          return replayStateError(`cannot re-read consumption records file (${e.message})`);
        }
        let records;
        try {
          records = parseConsumedRecords(lockedContent);
        } catch (e) {
          return replayStateError(e.message);
        }
        if (records.map(consumedIdOf).includes(markId)) {
          return {
            allow: false,
            reason_code: "REPLAY_DETECTED",
            message: `Replay detected: Mark ${markId} has already been consumed and cannot authorize repeated execution`
          };
        }
        records.push({
          mark_id: markId,
          operation: markOp,
          target: markTarget,
          consumed_at: new Date().toISOString()
        });
        const tmpFile = `${options.consumedRecordsFile}.tmp-${process.pid}`;
        try {
          fs.writeFileSync(tmpFile, JSON.stringify(records, null, 2) + "\n", "utf8");
          fs.renameSync(tmpFile, options.consumedRecordsFile);
        } catch (e) {
          try { fs.unlinkSync(tmpFile); } catch (ignored) {}
          return replayStateError(`cannot write consumption records file (${e.message})`);
        }
        consumedRecorded = true;
      } finally {
        try { fs.rmdirSync(lockDir); } catch (ignored) {}
      }
    } else {
      consumedSet.add(markId);
      if (consumedSource === "array") {
        options.consumedMarks.push(markId);
      }
      consumedRecorded = true;
    }
  }

  return {
    allow: true,
    reason_code: "ALLOW",
    message: "Standing Mark verified and bound to requested action",
    mark_id: markId,
    outcome: "ESTABLISHED",
    consumed: consumedRecorded,
    bound_object: {
      operation: markOp,
      target: markTarget,
      parameters: markParams !== null ? markParams : undefined,
      claim: markClaim || undefined
    }
  };
}

function createStandingMiddleware(options = {}) {
  return function standingMiddleware(req, res, next) {
    const markHeader = req.headers["x-whp-standing-mark"] || req.headers["x-standing-mark"];
    let mark = markHeader;
    if (!mark && req.body && req.body._standing_mark) {
      mark = req.body._standing_mark;
    }

    const requestDesc = options.extractRequest ? options.extractRequest(req) : {
      operation: req.method,
      target: req.originalUrl || req.url,
      parameters: req.body,
      claim: req.headers["x-whp-claim"] || (req.body && req.body.claim)
    };

    const result = verify(requestDesc, mark, options);

    if (!result.allow) {
      if (typeof options.onDeny === "function") {
        return options.onDeny(result, req, res, next);
      }
      res.statusCode = 403;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({
        error: "STANDING_DENIED",
        reason_code: result.reason_code,
        message: result.message
      }));
    }

    req.standing = result;
    if (typeof next === "function") next();
  };
}

function cliVerify(argv = process.argv.slice(2)) {
  let reqArg = process.env.WHP_REQUEST || null;
  let markArg = process.env.WHP_MARK || null;
  let consumedFileArg = process.env.WHP_CONSUMED_RECORDS_FILE || null;

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--request" || argv[i] === "-r") {
      reqArg = argv[++i];
    } else if (argv[i] === "--mark" || argv[i] === "-m") {
      markArg = argv[++i];
    } else if (argv[i] === "--consumed-records-file" || argv[i] === "-c") {
      consumedFileArg = argv[++i];
    }
  }

  function readInput(val) {
    if (!val) return null;
    const trimmed = typeof val === "string" ? val.trim() : val;
    if (typeof trimmed !== "string") return trimmed;
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try { return JSON.parse(trimmed); } catch (e) { return null; }
    }
    if (fs.existsSync(trimmed)) {
      try { return JSON.parse(fs.readFileSync(trimmed, "utf8")); } catch (e) { return null; }
    }
    return trimmed;
  }

  const reqObj = readInput(reqArg);
  const markObj = readInput(markArg);
  const options = {};
  if (consumedFileArg) {
    options.consumedRecordsFile = consumedFileArg;
  }

  const result = verify(reqObj, markObj, options);
  console.log(JSON.stringify(result, null, 2));

  // Single-use consumption is recorded inside verify() before passage is
  // granted; a failed recording denies passage there. No warning-then-pass.
  const consumed = result.consumed === true;

  if (process.env.GITHUB_OUTPUT) {
    try {
      fs.appendFileSync(
        process.env.GITHUB_OUTPUT,
        `allow=${result.allow}\nreason_code=${result.reason_code}\nmark_id=${result.mark_id || ""}\nconsumed=${consumed}\noutcome=${result.allow ? "ESTABLISHED" : "DENIED"}\n`
      );
    } catch (e) {}
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      const summary = [
        `### WHP Receiving Boundary Verification: \`${result.allow ? "ALLOW" : "DENY"}\``,
        `- **Determination:** \`${result.allow ? "ALLOWED" : "BLOCKED"}\``,
        `- **Reason Code:** \`${result.reason_code}\``,
        `- **Message:** ${result.message}`,
        result.mark_id ? `- **Mark ID:** \`${result.mark_id}\`` : "",
        result.bound_object ? `- **Bound Object:** \`${JSON.stringify(result.bound_object)}\`` : "",
        consumed ? `- **Consumed for Replay Prevention:** \`true\`` : ""
      ].filter(Boolean).join("\n");
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
    } catch (e) {}
  }

  if (!result.allow) {
    console.error(`BLOCKED [RECEIVING_BOUNDARY]: ${result.reason_code} - ${result.message}`);
    process.exit(1);
  }
  process.exit(0);
}

if (require.main === module) {
  if (
    process.env.WHP_MODE === "verify" ||
    process.argv[2] === "verify" ||
    process.argv.includes("--verify")
  ) {
    cliVerify(process.argv.slice(2));
  } else {
    run().catch(err => {
      console.error("BLOCKED:", err.message);
      process.exitCode = 1;
    });
  }
}

module.exports = {
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
  parseStructuredInput,
  formatAdjudicationReport,
  makeReceptionEvent,
  run,
  verify,
  createStandingMiddleware,
  cliVerify
};
