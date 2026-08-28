import crypto from 'crypto';

// Global memory cache across warm invocations
const freezeStore = globalThis.__freezeStore || (globalThis.__freezeStore = new Map());

const utf8Sort = (a, b) => {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.compare(bufB);
};

const sha256 = (str) => crypto.createHash('sha256').update(str, 'utf8').digest('hex');
const round12 = (num) => Math.round(num * 1e12) / 1e12;
const isBinary = (val) => val === 0 || val === 1;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  // Robust body parsing for Vercel
  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  const { phase } = body;

  // -------------------------------------------------------------------------
  // PHASE: FREEZE
  // -------------------------------------------------------------------------
  if (phase === 'freeze') {
    const {
      freezeId,
      calibrationDigest,
      tokenizerDigest,
      allowedUnsupportedReasons = [],
      candidates
    } = body;

    // HTTP 400 condition: empty/non-array freeze candidate list or invalid freezeId
    if (!Array.isArray(candidates) || candidates.length === 0 || typeof freezeId !== 'string' || freezeId.length === 0 || freezeId.length > 128) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const serializedPayload = JSON.stringify(body);
    if (freezeStore.has(freezeId)) {
      const stored = freezeStore.get(freezeId);
      if (stored.rawPayload === serializedPayload) {
        return res.status(200).json(stored.response);
      }
      return res.status(409).json({ error: 'FREEZE_ID_CONFLICT' });
    }

    const allowedReasonSet = new Set(Array.isArray(allowedUnsupportedReasons) ? allowedUnsupportedReasons : []);

    const processedCandidates = candidates.map((cand) => {
      const reasons = [];
      let inventory = [];
      let totalBytes = null;
      let packageDigest = null;

      if (!cand || typeof cand !== 'object' || typeof cand.name !== 'string' || cand.name.length === 0) {
        reasons.push('INVALID_INPUT');
        return {
          name: cand?.name || '',
          status: 'invalid',
          inventory: [],
          totalBytes: null,
          packageDigest: null,
          reasonCodes: ['INVALID_INPUT']
        };
      }

      // Validate files
      const filesValid =
        cand.files &&
        typeof cand.files === 'object' &&
        !Array.isArray(cand.files) &&
        Object.keys(cand.files).length > 0 &&
        Object.entries(cand.files).every(
          ([k, v]) => typeof k === 'string' && k.length > 0 && typeof v === 'string'
        );

      if (!filesValid) {
        reasons.push('INVALID_INPUT');
      } else {
        let sumBytes = 0;
        const sortedFilenames = Object.keys(cand.files).sort(utf8Sort);
        inventory = sortedFilenames.map((filename) => {
          const content = cand.files[filename];
          const byteLen = Buffer.byteLength(content, 'utf8');
          sumBytes += byteLen;
          return {
            name: filename,
            bytes: byteLen,
            sha256: sha256(content)
          };
        });

        totalBytes = sumBytes;
        const compactJson = JSON.stringify(inventory, ['name', 'bytes', 'sha256']);
        packageDigest = sha256(compactJson);
      }

      // Check unsupported vs digests
      const hasReason = typeof cand.unsupportedReason === 'string' && cand.unsupportedReason.length > 0;
      let isUnsupportedAllowed = false;

      if (hasReason) {
        if (allowedReasonSet.has(cand.unsupportedReason)) {
          isUnsupportedAllowed = true;
        } else {
          reasons.push('UNALLOWED_UNSUPPORTED_REASON');
        }
      } else {
        if (cand.loadable !== true) reasons.push('NOT_LOADABLE');
        if (cand.calibrationDigest !== calibrationDigest) reasons.push('CALIBRATION_MISMATCH');
        if (cand.tokenizerDigest !== tokenizerDigest) reasons.push('TOKENIZER_MISMATCH');
      }

      let status = 'frozen';
      if (reasons.length > 0) {
        status = 'invalid';
      } else if (isUnsupportedAllowed) {
        status = 'unsupported';
      }

      return {
        name: cand.name,
        status,
        inventory,
        totalBytes,
        packageDigest,
        reasonCodes: Array.from(new Set(reasons)).sort(utf8Sort)
      };
    });

    processedCandidates.sort((a, b) => utf8Sort(a.name, b.name));

    const freezeResponse = {
      freezeId,
      candidates: processedCandidates
    };

    freezeStore.set(freezeId, {
      rawPayload: serializedPayload,
      response: freezeResponse
    });

    return res.status(200).json(freezeResponse);
  }

  // -------------------------------------------------------------------------
  // PHASE: SELECT
  // -------------------------------------------------------------------------
  if (phase === 'select') {
    const { freezeId, candidates, policy, latencies = {}, rows } = body;

    // HTTP 400 condition: without array candidates and rows plus an object policy
    if (
      !Array.isArray(candidates) ||
      !Array.isArray(rows) ||
      !policy ||
      typeof policy !== 'object' ||
      Array.isArray(policy)
    ) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const { maxBytes, aggregateFloor, requiredSlices = {}, maxLatencyMs, candidateOrder } = policy;

    // Validate policy
    const policyValid =
      Number.isSafeInteger(maxBytes) &&
      maxBytes >= 0 &&
      typeof aggregateFloor === 'number' &&
      isFinite(aggregateFloor) &&
      aggregateFloor >= 0 &&
      aggregateFloor <= 1 &&
      typeof maxLatencyMs === 'number' &&
      isFinite(maxLatencyMs) &&
      maxLatencyMs >= 0 &&
      typeof requiredSlices === 'object' &&
      !Array.isArray(requiredSlices) &&
      Object.values(requiredSlices).every(
        (f) => typeof f === 'number' && isFinite(f) && f >= 0 && f <= 1
      ) &&
      Array.isArray(candidateOrder) &&
      new Set(candidateOrder).size === candidateOrder.length;

    const candNames = candidates.map((c) => c?.name);
    const orderMatches =
      Array.isArray(candidateOrder) &&
      candNames.length === new Set(candNames).size &&
      new Set(candNames).size === new Set(candidateOrder).size &&
      candNames.every((n) => new Set(candidateOrder).has(n));

    const isPolicyStrictlyValid = policyValid && orderMatches;

    const stored = freezeStore.get(freezeId);
    const lineageValid = stored && JSON.stringify(stored.response.candidates) === JSON.stringify(candidates);
    const storedCandMap = stored
      ? new Map(stored.response.candidates.map((c) => [c.name, c]))
      : new Map();

    const candidateResults = [];

    for (const cand of candidates) {
      const reasons = [];
      let totalBytes = null;
      let latencyMs = null;
      let aggregate = null;
      let sliceAccuracies = {};

      if (!lineageValid) {
        reasons.push('INVALID_LINEAGE');
      }

      if (!cand || cand.status !== 'frozen') {
        reasons.push('NOT_FROZEN');
      }

      if (!isPolicyStrictlyValid) {
        reasons.push('INVALID_POLICY');
      }

      // Recompute inventory manifest
      if (cand && Array.isArray(cand.inventory) && cand.inventory.length > 0) {
        let computedBytes = 0;
        const validInventory = cand.inventory.every(
          (f) =>
            typeof f.name === 'string' &&
            Number.isSafeInteger(f.bytes) &&
            f.bytes >= 0 &&
            typeof f.sha256 === 'string'
        );

        if (!validInventory) {
          reasons.push('INVALID_MANIFEST');
        } else {
          const sortedInv = [...cand.inventory].sort((a, b) => utf8Sort(a.name, b.name));
          sortedInv.forEach((f) => {
            computedBytes += f.bytes;
          });

          const compactJson = JSON.stringify(sortedInv, ['name', 'bytes', 'sha256']);
          const recomputedDigest = sha256(compactJson);

          if (cand.packageDigest !== recomputedDigest || cand.totalBytes !== computedBytes) {
            reasons.push('INVALID_MANIFEST');
          } else {
            totalBytes = computedBytes;
          }
        }
      } else {
        reasons.push('INVALID_MANIFEST');
      }

      // Size check
      if (totalBytes === null || (typeof maxBytes === 'number' && totalBytes > maxBytes)) {
        reasons.push('SIZE_LIMIT');
      }

      // Latency check
      const candLatency = latencies?.[cand?.name];
      if (typeof candLatency === 'number' && isFinite(candLatency) && candLatency >= 0) {
        latencyMs = candLatency;
        if (typeof maxLatencyMs === 'number' && latencyMs > maxLatencyMs) {
          reasons.push('LATENCY_LIMIT');
        }
      } else {
        reasons.push('LATENCY_LIMIT');
      }

      // Predictions check
      let validPredictions = rows.length > 0;
      let correctCount = 0;
      const sliceRows = {};

      if (requiredSlices && typeof requiredSlices === 'object') {
        for (const sliceName of Object.keys(requiredSlices)) {
          sliceRows[sliceName] = { total: 0, correct: 0 };
        }
      }

      for (const row of rows) {
        if (
          !row ||
          typeof row !== 'object' ||
          !isBinary(row.label) ||
          typeof row.slice !== 'string' ||
          !row.predictions ||
          !isBinary(row.predictions[cand?.name])
        ) {
          validPredictions = false;
          break;
        }

        const isMatch = row.predictions[cand.name] === row.label;
        if (isMatch) correctCount++;

        if (sliceRows[row.slice] !== undefined) {
          sliceRows[row.slice].total++;
          if (isMatch) sliceRows[row.slice].correct++;
        }
      }

      if (!validPredictions) {
        reasons.push('INVALID_PREDICTIONS');
        aggregate = null;
        if (requiredSlices && typeof requiredSlices === 'object') {
          sliceAccuracies = Object.keys(requiredSlices).reduce((acc, k) => {
            acc[k] = null;
            return acc;
          }, {});
        }
      } else {
        aggregate = round12(correctCount / rows.length);
        if (typeof aggregateFloor === 'number' && aggregate < aggregateFloor) {
          reasons.push('AGGREGATE_FLOOR');
        }

        for (const [sliceName, targetFloor] of Object.entries(requiredSlices)) {
          const sData = sliceRows[sliceName];
          if (!sData || sData.total === 0) {
            reasons.push(`MISSING_SLICE:${sliceName}`);
            sliceAccuracies[sliceName] = null;
          } else {
            const sAcc = round12(sData.correct / sData.total);
            sliceAccuracies[sliceName] = sAcc;
            if (sAcc < targetFloor) {
              reasons.push(`SLICE_FLOOR:${sliceName}`);
            }
          }
        }
      }

      const deduplicatedReasons = Array.from(new Set(reasons)).sort(utf8Sort);
      const admitted = deduplicatedReasons.length === 0;

      candidateResults.push({
        name: cand?.name || '',
        aggregate,
        slices: sliceAccuracies,
        totalBytes,
        latencyMs,
        admitted,
        reasonCodes: deduplicatedReasons
      });
    }

    // Sort candidate results by candidateOrder
    const orderIndexMap = new Map(
      Array.isArray(candidateOrder) ? candidateOrder.map((name, idx) => [name, idx]) : []
    );

    candidateResults.sort((a, b) => {
      const idxA = orderIndexMap.has(a.name) ? orderIndexMap.get(a.name) : Infinity;
      const idxB = orderIndexMap.has(b.name) ? orderIndexMap.get(b.name) : Infinity;
      if (idxA !== idxB) return idxA - idxB;
      return utf8Sort(a.name, b.name);
    });

    const admittedCandidates = candidateResults.filter((r) => r.admitted);
    let selected = null;
    let packageManifest = null;

    if (admittedCandidates.length > 0) {
      admittedCandidates.sort((a, b) => {
        if (a.totalBytes !== b.totalBytes) return a.totalBytes - b.totalBytes;
        if (a.latencyMs !== b.latencyMs) return a.latencyMs - b.latencyMs;
        return orderIndexMap.get(a.name) - orderIndexMap.get(b.name);
      });

      const winner = admittedCandidates[0];
      selected = winner.name;
      packageManifest = storedCandMap.get(winner.name) || null;
    }

    return res.status(200).json({
      freezeId,
      selected,
      results: candidateResults,
      packageManifest
    });
  }

  return res.status(400).json({ error: 'INVALID_INPUT' });
}
