// src/services/mlPipeline.js
"use strict";

const env = require("../config/env");
const logger = require("../utils/logger");

const HF_BASE = "https://api-inference.huggingface.co/models";
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
    re: /send.{0,10}₹|pay.{0,10}upi/i,
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

// ── HF fetch with retry ───────────────────────────────────────────────────
async function hfPost(model, inputs, parameters = undefined, attempt = 0) {
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
      throw new Error(`HF API ${res.status}: ${text.slice(0, 200)}`);
    }

    return await res.json();
  } catch (err) {
    clearTimeout(timer);

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
    const data = await hfPost(
      "facebook/fasttext-language-identification",
      text.slice(0, 512),
    );
    const top = data?.[0]?.[0];
    if (!top?.label) return { lang: "en", confidence: 0 };
    return {
      lang: top.label.replace("__label__", ""),
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
    return data?.[0]?.translation_text ?? text;
  } catch (err) {
    logger.warn("Translation failed, proceeding untranslated", {
      srcLang,
      error: err.message,
    });
    return text;
  }
}

// ── Stage 3: Spam/Fraud Classification ───────────────────────────────────
// mshenoda/roberta-spam: LABEL_0 = ham (legitimate), LABEL_1 = spam/fraud
async function classifyFraud(englishText) {
  try {
    const data = await hfPost(
      'mshenoda/roberta-spam',
      englishText.slice(0, 512)
    );

    // Response shape: [[{label, score}, ...]] or [{label, score}, ...]
    const labels = Array.isArray(data?.[0]) ? data[0] : Array.isArray(data) ? data : [];

    // LABEL_1 = spam/fraud, LABEL_0 = ham
    const spamEntry = labels.find(l => l?.label === 'LABEL_1');
    const hamEntry  = labels.find(l => l?.label === 'LABEL_0');
    const spamScore = spamEntry?.score ?? 0;
    const hamScore  = hamEntry?.score  ?? 0;

    logger.debug('Spam classification (roberta-spam)', { spamScore, hamScore });

    return {
      isFraud:   spamScore > 0.6,
      mlScore:   spamScore,
      spamScore: spamScore,
      legitScore: hamScore,
    };
  } catch (err) {
    logger.warn('Fraud classification failed', { error: err.message });
    return { isFraud: false, mlScore: 0, spamScore: 0, legitScore: 0 };
  }
}

// ── Stage 4: NER ──────────────────────────────────────────────────────────
async function extractEntities(englishText) {
  let nerEntities = [];

  try {
    const data = await hfPost("dslim/bert-base-NER", englishText.slice(0, 512));
    if (Array.isArray(data)) nerEntities = data;
  } catch (err) {
    logger.warn("NER extraction failed", { error: err.message });
  }

  RE_UPI.lastIndex = 0;
  RE_AMOUNT.lastIndex = 0;
  RE_URL.lastIndex = 0;
  RE_PHONE.lastIndex = 0;

  return {
    upiIds: [...(englishText.match(RE_UPI) ?? [])],
    amounts: [...(englishText.match(RE_AMOUNT) ?? [])],
    urls: [...(englishText.match(RE_URL) ?? [])],
    phones: [...(englishText.match(RE_PHONE) ?? [])],
    bankNames: nerEntities
      .filter((e) => (e.entity_group || e.entity) === "ORG")
      .map((e) => e.word),
    names: nerEntities
      .filter((e) => (e.entity_group || e.entity) === "PER")
      .map((e) => e.word),
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
  const patternScore = Math.min(
    matchedPatterns.reduce((s, p) => s + p.weight, 0),
    100,
  );

  const entityRisk =
    (entities.urls.some((u) => /\.xyz|\.tk|\.ml|\.top|\.ga|\.cf/.test(u))
      ? 20
      : 0) +
    (entities.upiIds.length > 0 ? 5 : 0) +
    (entities.phones.length > 0 ? 5 : 0);

  // Weights: ML model 35%, pattern matching 50%, entity signals 15%.
  // Spam-likelihood discount lowers false positives for promotional messages.
  const baseRaw = mlScore * 100 * 0.35 + patternScore * 0.5 + entityRisk * 0.15;
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

function buildExplanation(classification, flags, riskScore) {
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
    explanation: buildExplanation(
      risk.classification,
      risk.flags,
      risk.riskScore,
    ),
    entities,
    hfLatencyMs,
  };
}

module.exports = { runPipeline };
