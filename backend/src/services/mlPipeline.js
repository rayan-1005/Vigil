"use strict";

const env = require("../config/env");
const logger = require("../utils/logger");

const HF_BASE = "https://router.huggingface.co/hf-inference/models";
const HF_HEADERS = () => ({
  Authorization: `Bearer ${env.HF_API_TOKEN}`,
  "Content-Type": "application/json",
});

// ── Compiled regex patterns ───────────────────────────────────────────────
const PATTERNS = [
  {
    name: "kyc_scam",
    re: /kyc.{0,20}(expire|update|verify)/i,
    severity: "HIGH",
    weight: 25,
  },
  {
    // FIX (Bug 3): widened .{0,20} → .{0,40} so "Send Rs.500 processing fee to UPI" matches
    name: "fake_upi_request",
    re: /(?:send|pay|transfer|approve|accept).{0,40}(?:₹|rs\.?|inr|upi|collect request|mandate)|(?:upi|collect request|mandate).{0,40}(?:approve|accept|pay|send)/i,
    severity: "HIGH",
    weight: 20,
  },
  {
    name: "bank_impersonation",
    re: /(?:sbi|hdfc|icici|axis|kotak|rbi).{0,20}(?:official|support|help|alert)/i,
    severity: "HIGH",
    weight: 20,
  },
  {
    name: "urgency_keyword",
    re: /(?:immediately|urgent|expire|block|suspend|deactivate)/i,
    severity: "MEDIUM",
    weight: 15,
  },
  {
    name: "lookalike_domain",
    re: /(?:sbi-|hdfc-|paytm-|npci-)[a-z]+\.(?:xyz|tk|ml|ga|cf|top)/i,
    severity: "CRITICAL",
    weight: 35,
  },
  {
    name: "prize_scam",
    re: /(?:won|winner|prize|lottery|reward|selected|congratulations)/i,
    severity: "MEDIUM",
    weight: 15,
  },
  {
    name: "otp_phishing",
    re: /(?:share|send|tell|give|provide).{0,20}otp/i,
    severity: "CRITICAL",
    weight: 30,
  },
  {
    name: "account_threat",
    re: /(?:account|card).{0,20}(?:block|suspend|deactivat|clos)/i,
    severity: "HIGH",
    weight: 20,
  },
  {
    name: "refund_scam",
    re: /(?:refund|cashback|bonus).{0,20}(?:click|link|visit|call)/i,
    severity: "HIGH",
    weight: 20,
  },
  {
    name: "credential_phish",
    re: /(?:password|pin|cvv|card.?number).{0,20}(?:enter|provide|share|send)/i,
    severity: "CRITICAL",
    weight: 30,
  },
  {
    name: "fake_gov",
    re: /(?:income.?tax|it.?dept|government|pm.?relief|covid.?fund)/i,
    severity: "HIGH",
    weight: 20,
  },
  // FIX (Bug 5): new pattern — advance-fee fraud ("processing fee", "registration fee", etc.)
  {
    name: "advance_fee",
    re: /(?:processing|registration|activation|delivery|handling).{0,15}fee/i,
    severity: "HIGH",
    weight: 20,
  },
];

// Entity extraction regexes
// FIX (Bug 3): relaxed local-part minimum {3,} → {2,} to catch short UPI IDs like "p@ybl"
const RE_UPI = /[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}/g;
const RE_AMOUNT = /(?:₹|Rs\.?|INR)\s*[\d,]+/gi;
const RE_URL = /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi;
const RE_PHONE = /(?:\+91|0)?[6-9]\d{9}/g;

const TRANSLATION_MODELS = {
  hi: "Helsinki-NLP/opus-mt-hi-en",
  ta: "Helsinki-NLP/opus-mt-ta-en",
  te: "Helsinki-NLP/opus-mt-te-en",
  bn: "Helsinki-NLP/opus-mt-bn-en",
  mr: "Helsinki-NLP/opus-mt-mr-en",
  gu: "Helsinki-NLP/opus-mt-gu-en",
  kn: "Helsinki-NLP/opus-mt-kn-en",
};

const LANGUAGE_MODEL = "papluca/xlm-roberta-base-language-detection";
const FRAUD_MODEL = "facebook/bart-large-mnli";
const NER_MODEL = "dslim/bert-base-NER";

// ── HF fetch with retry ───────────────────────────────────────────────────
async function hfPost(model, inputs, parameters = undefined, attempt = 0) {
  const NON_RETRYABLE_STATUS = new Set([400, 401, 403, 404]);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), env.HF_TIMEOUT_MS);

  try {
    const payload = {
      inputs,
      options: { wait_for_model: true },
    };
    if (parameters && typeof parameters === "object") {
      payload.parameters = parameters;
    }

    const res = await fetch(`${HF_BASE}/${model}`, {
      method: "POST",
      headers: HF_HEADERS(),
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timer);

    // 503 = model loading – always retry once
    if (res.status === 503 && attempt < Math.max(env.HF_RETRY_ATTEMPTS, 1)) {
      logger.warn("HF model loading (503), retrying...", { model });
      await new Promise((r) => setTimeout(r, 3000));
      return hfPost(model, inputs, parameters, attempt + 1);
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      const err = new Error(`HF API ${res.status}: ${text.slice(0, 200)}`);
      err.status = res.status;
      throw err;
    }

    return await res.json();
  } catch (err) {
    clearTimeout(timer);

    if (NON_RETRYABLE_STATUS.has(err?.status)) {
      throw err;
    }

    if (attempt < env.HF_RETRY_ATTEMPTS) {
      const delay = 1000 * Math.pow(2, attempt);
      logger.warn(`HF retry ${attempt + 1}`, {
        model,
        error: err.message,
        delay,
      });
      await new Promise((r) => setTimeout(r, delay));
      return hfPost(model, inputs, parameters, attempt + 1);
    }

    throw err;
  }
}

// ── Stage 1: Language Detection ───────────────────────────────────────────
async function detectLanguage(text) {
  try {
    // FIX (Bug 6): raised slice from 512 → 1024 chars; XLM-RoBERTa limit is
    // 512 *tokens*, not chars — 512 chars was too conservative and caused
    // mixed-script messages to be misclassified, skipping translation.
    const data = await hfPost(LANGUAGE_MODEL, text.slice(0, 1024), {
      top_k: 3,
    });
    const top = Array.isArray(data?.[0]) ? data[0][0] : data?.[0];
    if (!top?.label) return { lang: "en", confidence: 0 };
    return {
      lang: String(top.label).replace("__label__", "").toLowerCase(),
      confidence: top.score ?? 0,
    };
  } catch (err) {
    logger.warn("Language detection failed, defaulting to en", {
      error: err.message,
    });
    return { lang: "en", confidence: 0 };
  }
}

// ── Stage 2: Translation ──────────────────────────────────────────────────
async function translateToEnglish(text, srcLang) {
  const model = TRANSLATION_MODELS[srcLang];
  if (!model) return text;

  try {
    const data = await hfPost(model, text);
    const resultObj = Array.isArray(data?.[0]) ? data[0][0] : data?.[0];
    return resultObj?.translation_text ?? text;
  } catch (err) {
    logger.warn("Translation failed, proceeding untranslated", {
      srcLang,
      error: err.message,
    });
    return text;
  }
}

// ── Stage 3: Fraud Classification ────────────────────────────────────────
async function classifyFraud(englishText) {
  try {
    const data = await hfPost(FRAUD_MODEL, englishText.slice(0, 512), {
      candidate_labels: [
        "financial fraud or scam",
        "promotional or marketing spam",
        "legitimate transactional message",
      ],
      hypothesis_template: "This message is about {}.",
      multi_label: true,
    });

    // FIX (Bug 1): the HF inference router for bart-large-mnli returns either:
    //   (a) [{label, score}, …]          — flat array
    //   (b) [[{label, score}, …]]        — nested array (one extra wrapper)
    //   (c) {labels: […], scores: […]}   — object shape
    // Previously the flat-array branch called data.find() which only works if
    // data is the flat array itself; a nested array made data[0] still an array,
    // so find() was called on an array of arrays and always returned undefined
    // → every score was 0.  We now normalise to a flat array first.
    const scoreFor = (name) => {
      // Normalise all three shapes to a flat [{label, score}] array
      let flat;
      if (Array.isArray(data)) {
        flat = Array.isArray(data[0]) ? data[0] : data;
        const entry = flat.find((item) => item?.label === name);
        return entry?.score ?? 0;
      }
      // Object shape: {labels:[…], scores:[…]}
      const labels = Array.isArray(data?.labels) ? data.labels : [];
      const scores = Array.isArray(data?.scores) ? data.scores : [];
      const index = labels.indexOf(name);
      return index >= 0 ? (scores[index] ?? 0) : 0;
    };

    const fraudScore = scoreFor("financial fraud or scam");
    const spamScore = scoreFor("promotional or marketing spam");
    const legitScore = scoreFor("legitimate transactional message");

    logger.debug("Fraud classification (bart-large-mnli)", {
      fraudScore,
      spamScore,
      legitScore,
      responseShape: Array.isArray(data)
        ? Array.isArray(data[0])
          ? "nested-array"
          : "flat-array"
        : "object",
    });

    return {
      isFraud: fraudScore > 0.62 && fraudScore > legitScore,
      mlScore: fraudScore,
      spamScore,
      legitScore,
    };
  } catch (err) {
    logger.warn("Fraud classification failed", { error: err.message });
    return { isFraud: false, mlScore: 0, spamScore: 0, legitScore: 0 };
  }
}

// ── Stage 4: NER ──────────────────────────────────────────────────────────
// FIX (Bug 2): dslim/bert-base-NER on the HF inference REST API does NOT
// accept `parameters.aggregation_strategy` — that is a transformers pipeline
// constructor argument, not a model parameter.  Sending it caused a 400, which
// is in NON_RETRYABLE_STATUS, so the call threw immediately and nerEntities
// was always [].  We now:
//   1. Remove the parameters argument entirely.
//   2. Receive the raw token-level predictions (B-/I- prefix tags).
//   3. Merge consecutive tokens that belong to the same entity span in JS,
//      including stripping WordPiece "##" continuations.
async function extractEntities(englishText) {
  let nerEntities = [];

  try {
    // No parameters — raw token predictions returned
    const data = await hfPost(NER_MODEL, englishText.slice(0, 512));
    const raw = Array.isArray(data)
      ? Array.isArray(data[0])
        ? data[0]
        : data
      : [];

    // Merge B-/I- token spans into whole entities (poor-man's aggregation)
    nerEntities = mergeNerSpans(raw);
  } catch (err) {
    logger.warn("NER extraction failed", { error: err.message });
  }

  RE_UPI.lastIndex = 0;
  RE_AMOUNT.lastIndex = 0;
  RE_URL.lastIndex = 0;
  RE_PHONE.lastIndex = 0;

  const cleanNerWord = (value = "") =>
    value.replace(/^##/, "").replace(/##/g, "").replace(/\s+/g, " ").trim();

  const dedupe = (arr) => [...new Set(arr)];

  const bankNames = dedupe(
    nerEntities
      .filter((e) => e.entity_group === "ORG")
      .map((e) => cleanNerWord(e.word))
      .filter(Boolean),
  );

  const names = dedupe(
    nerEntities
      .filter((e) => e.entity_group === "PER")
      .map((e) => cleanNerWord(e.word))
      .filter(Boolean),
  );

  return {
    upiIds: [...(englishText.match(RE_UPI) ?? [])],
    amounts: [...(englishText.match(RE_AMOUNT) ?? [])],
    urls: [...(englishText.match(RE_URL) ?? [])],
    phones: [...(englishText.match(RE_PHONE) ?? [])],
    bankNames,
    names,
  };
}

// Merge raw B-/I- token predictions into aggregated entity spans.
// Each token from dslim/bert-base-NER looks like:
//   { entity: "B-ORG", word: "SBI", score: 0.99, start: 4, end: 7 }
// We collect consecutive I-* tokens that share the same type as the
// preceding B-* token into a single span, then expose entity_group.
function mergeNerSpans(tokens) {
  const spans = [];
  let current = null;

  for (const tok of tokens) {
    const entity = tok.entity ?? "";
    const prefix = entity.slice(0, 2); // "B-" | "I-" | "O"
    const type = entity.slice(2); // "ORG" | "PER" | "LOC" | "MISC"

    if (prefix === "B-") {
      if (current) spans.push(current);
      current = {
        entity_group: type,
        word: tok.word ?? "",
        score: tok.score ?? 0,
        start: tok.start,
        end: tok.end,
        count: 1,
      };
    } else if (prefix === "I-" && current && current.entity_group === type) {
      // Continuation token — append word and extend span
      const word = tok.word ?? "";
      current.word += word.startsWith("##") ? word.slice(2) : ` ${word}`;
      current.end = tok.end;
      current.score =
        (current.score * current.count + (tok.score ?? 0)) /
        (current.count + 1);
      current.count += 1;
    } else {
      // O tag or type mismatch — close current span
      if (current) {
        spans.push(current);
        current = null;
      }
    }
  }

  if (current) spans.push(current);
  return spans;
}

// ── Stage 5: Risk Aggregation ─────────────────────────────────────────────
function aggregateRisk({
  mlScore,
  spamScore,
  isFraud,
  entities,
  rawText,
  normalizedText,
}) {
  const textForPatterns = `${rawText}\n${normalizedText ?? ""}`;
  const matchedPatterns = PATTERNS.filter((p) => p.re.test(textForPatterns));
  const hasStrongPattern = matchedPatterns.some(
    (p) => p.severity === "HIGH" || p.severity === "CRITICAL",
  );
  const matchedFlags = new Set(matchedPatterns.map((p) => p.name));
  const patternScore = Math.min(
    matchedPatterns.reduce((s, p) => s + p.weight, 0),
    100,
  );

  const hasSuspiciousDomain = entities.urls.some((u) =>
    /\.xyz|\.tk|\.ml|\.top|\.ga|\.cf/i.test(u),
  );

  const entityRisk =
    (hasSuspiciousDomain ? 20 : 0) +
    (entities.urls.length > 0 ? 8 : 0) +
    (entities.upiIds.length > 0 ? 5 : 0) +
    (entities.amounts.length > 0 ? 5 : 0) +
    (entities.phones.length > 0 ? 5 : 0) +
    (entities.bankNames.length > 0 ? 4 : 0);

  let synergyBonus = 0;
  if (isFraud && hasStrongPattern) synergyBonus += 12;
  if (entities.upiIds.length > 0 && entities.amounts.length > 0)
    synergyBonus += 8;
  if (matchedFlags.has("kyc_scam") && entities.upiIds.length > 0)
    synergyBonus += 12;
  if (matchedFlags.has("bank_impersonation") && entities.bankNames.length > 0)
    synergyBonus += 8;
  if (matchedFlags.has("urgency_keyword") && matchedFlags.has("account_threat"))
    synergyBonus += 10;
  if (matchedFlags.has("otp_phishing")) synergyBonus += 12;
  if (hasSuspiciousDomain) synergyBonus += 10;
  // Extra synergy for prize + UPI advance-fee combo (test message pattern)
  if (matchedFlags.has("prize_scam") && matchedFlags.has("advance_fee"))
    synergyBonus += 10;
  if (matchedFlags.has("prize_scam") && entities.upiIds.length > 0)
    synergyBonus += 8;

  // FIX (Bug 4): original weights summed to 115% (ML 35 + patterns 55 + entities 25).
  // Renormalised to ML 30% + patterns 50% + entities 20% = 100%, preserving the
  // intended pattern-dominance when ML degrades gracefully.
  // Spam discount is unchanged — only applies when no strong scam pattern is present.
  const baseRaw =
    mlScore * 100 * 0.3 + patternScore * 0.5 + entityRisk * 0.2 + synergyBonus;
  const spamDiscount = !hasStrongPattern ? spamScore * 20 : 0;
  const raw = baseRaw - spamDiscount;
  const clamped = Math.min(Math.max(Math.round(raw), 0), 100);

  let classification;
  if (clamped >= 65 && (isFraud || hasStrongPattern))
    classification = "FRAUDULENT";
  else if (clamped >= 35) classification = "SUSPICIOUS";
  else classification = "LEGITIMATE";

  if (isFraud && classification === "LEGITIMATE") classification = "SUSPICIOUS";

  return {
    riskScore: clamped,
    riskLevel:
      clamped >= 80
        ? "CRITICAL"
        : clamped >= 60
          ? "HIGH"
          : clamped >= 35
            ? "MEDIUM"
            : "LOW",
    classification,
    flags: matchedPatterns.map((p) => p.name),
    patternMatches: matchedPatterns.map((p) => ({
      pattern: p.name,
      severity: p.severity,
    })),
  };
}

function buildExplanation(classification, flags) {
  const base =
    {
      FRAUDULENT: "This message shows strong indicators of fraud.",
      SUSPICIOUS:
        "This message has suspicious characteristics that warrant caution.",
      LEGITIMATE: "This message appears to be legitimate.",
    }[classification] ?? "This message appears to be legitimate.";

  const details = [];
  if (flags.includes("otp_phishing"))
    details.push("Never share your OTP with anyone.");
  if (flags.includes("kyc_scam"))
    details.push("Legitimate banks never ask you to send money to verify KYC.");
  if (flags.includes("credential_phish"))
    details.push("No legitimate service will ask for your PIN or CVV.");
  if (flags.includes("bank_impersonation"))
    details.push("Verify the sender through official bank channels.");
  if (flags.includes("prize_scam"))
    details.push("Unsolicited prize notifications are almost always scams.");
  if (flags.includes("fake_gov"))
    details.push(
      "Verify government scheme communications on official .gov.in sites.",
    );
  if (flags.includes("advance_fee"))
    details.push(
      "Requests for a 'processing fee' to claim a prize or refund are a classic scam.",
    );

  return details.length > 0 ? base + " " + details.join(" ") : base;
}

// ── Public: run full pipeline ─────────────────────────────────────────────
async function runPipeline(rawMessage) {
  const t0 = Date.now();

  const { lang, confidence: langConf } = await detectLanguage(rawMessage);

  const englishText =
    lang !== "en" && lang !== "mixed" && TRANSLATION_MODELS[lang]
      ? await translateToEnglish(rawMessage, lang)
      : rawMessage;

  const [{ isFraud, mlScore, spamScore }, entities] = await Promise.all([
    classifyFraud(englishText),
    extractEntities(englishText),
  ]);

  const risk = aggregateRisk({
    mlScore,
    spamScore,
    isFraud,
    entities,
    rawText: rawMessage,
    normalizedText: englishText,
  });

  logger.debug("Pipeline result", {
    lang,
    mlScore,
    isFraud,
    riskScore: risk.riskScore,
    classification: risk.classification,
    flags: risk.flags,
  });

  const hfLatencyMs = Date.now() - t0;

  return {
    detectedLanguage: lang,
    langConfidence: langConf,
    translatedMessage:
      lang !== "en" && TRANSLATION_MODELS[lang] ? englishText : null,
    ...risk,
    confidence: parseFloat(mlScore.toFixed(4)),
    explanation: buildExplanation(risk.classification, risk.flags),
    entities,
    hfLatencyMs,
  };
}

module.exports = { runPipeline };
