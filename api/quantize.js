import crypto from 'crypto';

// In-memory store for instance lifetime
const freezeStore = new Map();

const utf8Sort = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sha256 = (str) => crypto.createHash('sha256').update(str, 'utf8').digest('hex');
const round12 = (num) => Math.round(num * 1e12) / 1e12;
const isBinary = (val) => val === 0 || val === 1;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }

  // -------------------------------------------------------------
  // PHASE 1: FREEZE
  // -------------------------------------------------------------
  if (body.phase === 'freeze') {
    const {
      freezeId,
      calibrationDigest,
      tokenizerDigest,
      allowedUnsupportedReasons,
      candidates
    } = body;

    if (
      typeof freezeId !== 'string' ||
      freezeId.length === 0 ||
      freezeId.length > 128 ||
      typeof calibrationDigest !== 'string' ||
      calibrationDigest.length === 0 ||
      typeof tokenizerDigest !== 'string' ||
      tokenizerDigest.length === 0 ||
      !Array.isArray(allowedUnsupportedReasons) ||
      !Array.isArray(candidates) ||
      candidates.length === 0
    ) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const allowedReasonSet = new Set();
    for (const reason of allowedUnsupportedReasons) {
      if (typeof reason !== 'string' || reason.length === 0 || allowedReasonSet.has(reason)) {
        return res.status(400).json({ error: 'INVALID_INPUT' });
      }
      allowedReasonSet.add(reason);
    }

    const candidateNameSet = new Set();
    for (const cand of candidates) {
      if (!cand || typeof cand !== 'object' || typeof cand.name !== 'string' || cand.name.length === 0) {
        return res.status(400).json({ error: 'INVALID_INPUT' });
      }
      if (candidateNameSet.has(cand.name)) {
        return res.status(400).json({ error: 'INVALID_INPUT' });
      }
      candidateNameSet.add(cand.name);
    }

    const serializedPayload = JSON.stringify(body);
    if (freezeStore.has(freezeId)) {
      const stored = freezeStore.get(freezeId);
      if (stored.rawPayload === serializedPayload) {
        return res.status(200).json(stored.response);
      }
      return res.status(409).json({ error: 'FREEZE_ID_CONFLICT' });
    }

    const processedCandidates = candidates.map((cand) => {
      const reasons = [];
      let inventory = [];
      let totalBytes = null;
      let packageDigest = null;

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
        const rawInventory = Object.keys(cand.files)
          .sort(utf8Sort)
          .map((filename) => {
            const content = cand.files[filename];
            const byteLen = Buffer.byteLength(content, 'utf8');
            sumBytes += byteLen;
            return {
              name: filename,
              bytes: byteLen,
              sha256: sha256(content)
            };
          });

        inventory = rawInventory;
        totalBytes = sumBytes;

        const compactInventoryJson = JSON.stringify(inventory, ['name', 'bytes', 'sha256']);
        packageDigest = sha256(compactInventoryJson);
      }

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

  // -------------------------------------------------------------
  // PHASE 2: SELECT
  // -------------------------------------------------------------
  if (body.phase === 'select') {
    const { freezeId, candidates, policy, latencies, rows } = body;

    if (
      typeof freezeId !== 'string' ||
      !Array.isArray(candidates) ||
      !policy ||
      typeof policy !== 'object' ||
      !Array.isArray(rows) ||
      !latencies ||
      typeof latencies !== 'object'
    ) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const { maxBytes, aggregateFloor, requiredSlices, maxLatencyMs, candidateOrder } = policy;

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
      requiredSlices &&
      typeof requiredSlices === 'object' &&
      !Array.isArray(requiredSlices) &&
      Object.values(requiredSlices).every(
        (floor) => typeof floor === 'number' && isFinite(floor) && floor >= 0 && floor <= 1
      ) &&
      Array.isArray(candidateOrder) &&
      new Set(candidateOrder).size === candidateOrder.length;

    if (!policyValid) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const candNames = candidates.map((c) => c?.name);
    const candNameSet = new Set(candNames);
    const orderSet = new Set(candidateOrder);

    if (
      candNames.length !== candNameSet.size ||
      candNameSet.size !== orderSet.size ||
      ![...candNameSet].every((n) => orderSet.has(n))
    ) {
      return res.status(400).json({ error: 'INVALID_INPUT' });
    }

    const stored = freezeStore.get(freezeId);
    const lineageValid = stored && JSON.stringify(stored.response.candidates) === JSON.stringify(candidates);

    const candidateResults = [];
    const storedCandMap = stored
      ? new Map(stored.response.candidates.map((c) => [c.name, c]))
      : new Map();

    for (const cand of candidates) {
      const reasons = [];
      let totalBytes = null;
      let latencyMs = null;
      let aggregate = null;
      let sliceAccuracies = {};

      if (!lineageValid) {
        reasons.push('INVALID_LINEAGE');
      }

      if (cand.status !== 'frozen') {
        reasons.push('NOT_FROZEN');
      }

      if (Array.isArray(cand.inventory) && cand.inventory.length > 0) {
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

      if (totalBytes === null || totalBytes > maxBytes) {
        reasons.push('SIZE_LIMIT');
      }

      const candLatency = latencies[cand.name];
      if (typeof candLatency === 'number' && isFinite(candLatency) && candLatency >= 0) {
        latencyMs = candLatency;
        if (latencyMs > maxLatencyMs) {
          reasons.push('LATENCY_LIMIT');
        }
      } else {
        reasons.push('LATENCY_LIMIT');
      }

      let validPredictions = rows.length > 0;
      let correctCount = 0;
      const sliceRows = {};

      for (const sliceName of Object.keys(requiredSlices)) {
        sliceRows[sliceName] = { total: 0, correct: 0 };
      }

      for (const row of rows) {
        if (
          !row ||
          typeof row !== 'object' ||
          !isBinary(row.label) ||
          typeof row.slice !== 'string' ||
          !row.predictions ||
          !isBinary(row.predictions[cand.name])
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
        sliceAccuracies = Object.keys(requiredSlices).reduce((acc, k) => {
          acc[k] = null;
          return acc;
        }, {});
      } else {
        aggregate = round12(correctCount / rows.length);
        if (aggregate < aggregateFloor) {
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
        name: cand.name,
        aggregate,
        slices: sliceAccuracies,
        totalBytes,
        latencyMs,
        admitted,
        reasonCodes: deduplicatedReasons
      });
    }

    const orderIndexMap = new Map(candidateOrder.map((name, idx) => [name, idx]));
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
