// src/services/mlPipeline.js
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
    name: "fake_upi_request",
    re: /(?:send|pay|transfer|approve|accept).{0,20}(?:₹|rs\.?|inr|upi|collect request|mandate)|(?:upi|collect request|mandate).{0,20}(?:approve|accept|pay|send)/i,
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
];

// Entity extraction regexes
const RE_UPI = /[a-zA-Z0-9._-]{3,}@[a-zA-Z]{2,}/g;
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

    // Fail fast for non-retryable client/auth errors.
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
    const data = await hfPost(LANGUAGE_MODEL, text.slice(0, 512), { top_k: 3 });
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
// Zero-shot classification gives us explicit fraud labels and clearer semantics.
async function classifyFraud(englishText) {
  try {
    const data = await hfPost(
      FRAUD_MODEL,
      englishText.slice(0, 512),
      {
        candidate_labels: [
          "financial fraud or scam",
          "promotional or marketing spam",
          "legitimate transactional message",
        ],
        hypothesis_template: "This message is about {}.",
        multi_label: true,
      },
    );

    const scoreFor = (name) => {
      if (Array.isArray(data)) {
        const entry = data.find((item) => item?.label === name);
        return entry?.score ?? 0;
      }

      const labels = Array.isArray(data?.labels) ? data.labels : [];
      const scores = Array.isArray(data?.scores) ? data.scores : [];
      const index = labels.indexOf(name);
      return index >= 0 ? scores[index] ?? 0 : 0;
    };
    const fraudScore = scoreFor("financial fraud or scam");
    const spamScore = scoreFor("promotional or marketing spam");
    const legitScore = scoreFor("legitimate transactional message");

    logger.debug("Fraud classification (bart-large-mnli)", {
      fraudScore,
      spamScore,
      legitScore,
      responseShape: Array.isArray(data) ? "array" : "object",
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
async function extractEntities(englishText) {
  let nerEntities = [];

  try {
    const data = await hfPost(NER_MODEL, englishText.slice(0, 512), {
      aggregation_strategy: "simple",
    });
    if (Array.isArray(data)) {
      nerEntities = Array.isArray(data[0]) ? data[0] : data;
    }
  } catch (err) {
    logger.warn("NER extraction failed", { error: err.message });
  }

  RE_UPI.lastIndex = 0;
  RE_AMOUNT.lastIndex = 0;
  RE_URL.lastIndex = 0;
  RE_PHONE.lastIndex = 0;

  const cleanNerWord = (value = "") =>
    value
      .replace(/^##/, "")
      .replace(/##/g, "")
      .replace(/\s+/g, " ")
      .trim();

  const dedupe = (arr) => [...new Set(arr)];

  const bankNames = dedupe(
    nerEntities
      .filter((e) => (e.entity_group || e.entity) === "ORG")
      .map((e) => cleanNerWord(e.word))
      .filter(Boolean),
  );

  const names = dedupe(
    nerEntities
      .filter((e) => (e.entity_group || e.entity) === "PER")
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
  if (entities.upiIds.length > 0 && entities.amounts.length > 0) synergyBonus += 8;
  if (matchedFlags.has("kyc_scam") && entities.upiIds.length > 0) synergyBonus += 12;
  if (matchedFlags.has("bank_impersonation") && entities.bankNames.length > 0) synergyBonus += 8;
  if (matchedFlags.has("urgency_keyword") && matchedFlags.has("account_threat")) synergyBonus += 10;
  if (matchedFlags.has("otp_phishing")) synergyBonus += 12;
  if (hasSuspiciousDomain) synergyBonus += 10;

  // Weights: ML 35%, patterns 55%, entities 25% with synergy boosts.
  // Spam discount only applies when strong scam evidence is absent.
  const baseRaw = mlScore * 100 * 0.35 + patternScore * 0.55 + entityRisk * 0.25 + synergyBonus;
  const spamDiscount = !hasStrongPattern ? spamScore * 20 : 0;
  const raw = baseRaw - spamDiscount;
  const clamped = Math.min(Math.max(Math.round(raw), 0), 100);

  // Classification driven by score alone – not gated on isFraud boolean
  let classification;
  if (clamped >= 65 && (isFraud || hasStrongPattern)) classification = "FRAUDULENT";
  else if (clamped >= 35) classification = "SUSPICIOUS";
  else classification = "LEGITIMATE";

  // Bump classification if ML model is confident even if score is borderline
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
