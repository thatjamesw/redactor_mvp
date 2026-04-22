function luhnOk(value) {
  const digits = (value || "").replace(/\D/g, "");
  if (!digits) return false;
  let sum = 0;
  let doubleDigit = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

const EMAIL_STRICT = /\b[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b/g;
const EMAIL_LOOSE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
const IPV4_CIDR = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\/(?:[0-9]|[12][0-9]|3[0-2])\b/g;
const IPV6 = /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi;
const API_KEY = /\bsk-[A-Za-z0-9]{8,}\b/g;
const AWS_AKID = /\bAKIA[0-9A-Z]{16}\b/g;
const JWT = /\beyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\b/g;
const GENERIC_SECRET = /\b[A-Za-z0-9_\-]{24,}\b/g;
const CREDIT_CARD = /\b(?:\d[ -]*?){13,19}\b/g;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/g;
const US_TIN = /\b9\d{2}-?(?:7\d|8[0-8]|9[0-2])-\d{4}\b/g;
const MAC_ADDRESS = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
const VIN = /\b[A-HJ-NPR-Z0-9]{17}\b/g;
const PASSPORT_GENERIC = /\b[A-Z0-9]{6,9}\b/g;
const MRZ_PASSPORT_NUMBER = /\b[A-Z][0-9]{6,8}\b/g;
const MRZ_LINE = /\bP<[A-Z<]{10,}|\b[A-Z0-9<]{20,}\b/g;
const DRIVERS_LICENSE_GENERIC = /\b[A-Z]{1,2}\d{6,8}\b/g;
const PHONE = /\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}\b/g;
const ADDRESS_SUFFIX =
  "(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Parkway|Pkwy|Katu|Tie|Polku|Kuja|Vagen|V\\.|Gata|Strasse|Straße|Rue|Chemin|Via|Corso|Calle|Camino|Rua|Avenida|Avda)";
const STREET_ADDRESS_NUMBER_FIRST = new RegExp(`\\b\\d{1,6}[A-Za-z]?(?:[-/]\\d+)?\\s+[A-Za-z0-9.'\\- ]+\\s${ADDRESS_SUFFIX}(?:\\s+\\d+[A-Za-z]?)?(?:\\s+[A-Za-z]\\s+\\d+)?\\b`, "gi");
const STREET_ADDRESS_NAME_FIRST_WITH_NUMBER = new RegExp(`\\b[A-Za-zÅÄÖåäö0-9.'\\-]+(?:\\s+[A-Za-zÅÄÖåäö0-9.'\\-]+)*\\s${ADDRESS_SUFFIX}\\s+\\d{1,6}[A-Za-z]?(?:\\s+[A-Za-z]\\s+\\d+)?(?:\\s+\\d+[A-Za-z]?)?\\b`, "gi");
const NAME_CONTEXT_PATTERN = /\b(?:name|customer|client|employee|user|contact|owner|recipient)\s*[:=-]\s*([A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+(?:\s+[A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+){1,3})/gi;
const ADDRESS_CONTEXT_PATTERN = new RegExp(`\\b(?:address|street|osoite|addr)\\s*[:=-]\\s*((?:\\d{1,6}[A-Za-z]?(?:[-/]\\d+)?\\s+[A-Za-z0-9.'\\- ]+\\s${ADDRESS_SUFFIX}|[A-Za-zÅÄÖåäö0-9.'\\-]+(?:\\s+[A-Za-zÅÄÖåäö0-9.'\\-]+)*\\s${ADDRESS_SUFFIX}\\s+\\d{1,6}[A-Za-z]?(?:\\s+[A-Za-z]\\s+\\d+)?(?:\\s+\\d+[A-Za-z]?)?))\\b`, "gi");

const NAME_KEY = /^(?:name|full name|full_name|first name|last name|contact|author)$/i;
const PLACE_KEY = /(?:^|[_\-. ])(?:city|town|location|country|region|address)$/i;
const ORG_KEY = /(?:^|[_\-. ])(?:company|organisation|organization|employer|business|tenant)$/i;
const PHONE_KEY = /(?:^|[_\-. ])(?:phone|telephone|mobile|cell|fax|contact number)$/i;
const EMAIL_KEY = /(?:^|[_\-. ])(?:email|email address|email_address|e-mail|mail)$/i;
const SSN_KEY = /(?:^|[_\-. ])(?:ssn|social security|social_security|tax id|tin|itin|ein)$/i;
const PASSPORT_KEY = /(?:^|[_\-. ])(?:passport|passport number|passport_no|passport_number)$/i;
const LICENSE_KEY = /(?:^|[_\-. ])(?:driver|drivers license|driver_license|license number|licence number)$/i;
const VIN_KEY = /(?:^|[_\-. ])(?:vin|vehicle identification|vehicle_id)$/i;
const MAC_KEY = /(?:^|[_\-. ])(?:mac|mac address|mac_address)$/i;

const PASSPORT_DISALLOWED = /^(?:true|false|null)$/i;
const VIN_DISALLOWED = /[IOQ]/;

function scanMatches(text, regex, label, baseConfidence, findings, context = {}) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(text)) !== null) {
    addFinding(findings, label, baseConfidence, match.index, match.index + match[0].length, match[0], ["pattern_match"], context);
  }
}

function categoryForLabel(label) {
  if (["API_KEY", "AWS_ACCESS_KEY", "JWT", "POTENTIAL_SECRET"].includes(label)) return "secrets";
  if (["IPV4", "IPV4_CIDR", "IPV6", "MAC_ADDRESS"].includes(label)) return "network";
  if (["CREDIT_CARD", "US_TAX_ID"].includes(label)) return "financial";
  if (["PERSON", "PLACE", "ORG", "STREET_ADDRESS", "FACE", "DOCUMENT_TEXT"].includes(label)) return "identity";
  if (["PHONE", "EMAIL", "SSN", "PASSPORT", "PASSPORT_ZONE", "DRIVERS_LICENSE", "VIN", "UUID"].includes(label)) return "pii";
  return "other";
}

function categoryEnabled(options, label) {
  const category = categoryForLabel(label);
  const enabled = options.enabledCategories || {};
  return enabled[category] !== false;
}

function addFinding(findings, label, confidence, start, end, original, reasoning, context) {
  findings.push({
    id: `f-${findings.length + 1}`,
    label,
    category: categoryForLabel(label),
    confidence,
    start,
    end,
    original,
    reasoning,
    context,
  });
}

export function scanTextValue(text, options = {}, context = {}) {
  const findings = [];
  const content = String(text ?? "");

  if (categoryEnabled(options, "EMAIL")) {
    const emailRegex = EMAIL_KEY.test(context.keyHint || "") ? EMAIL_LOOSE : (options.strictEmail ? EMAIL_STRICT : EMAIL_LOOSE);
    const emailConfidence = EMAIL_KEY.test(context.keyHint || "") ? 0.97 : (options.strictEmail ? 0.91 : 0.82);
    scanMatches(content, emailRegex, "EMAIL", emailConfidence, findings, context);
  }
  if (categoryEnabled(options, "API_KEY")) scanMatches(content, API_KEY, "API_KEY", 0.96, findings, context);
  if (categoryEnabled(options, "AWS_ACCESS_KEY")) scanMatches(content, AWS_AKID, "AWS_ACCESS_KEY", 0.95, findings, context);
  if (categoryEnabled(options, "JWT")) scanMatches(content, JWT, "JWT", 0.92, findings, context);
  if (categoryEnabled(options, "UUID")) scanMatches(content, UUID, "UUID", 0.87, findings, context);
  if (categoryEnabled(options, "IPV4_CIDR")) scanMatches(content, IPV4_CIDR, "IPV4_CIDR", 0.94, findings, context);
  if (categoryEnabled(options, "IPV4")) scanMatches(content, IPV4, "IPV4", 0.82, findings, context);
  if (categoryEnabled(options, "IPV6")) scanMatches(content, IPV6, "IPV6", 0.82, findings, context);
  if (categoryEnabled(options, "SSN")) scanMatches(content, SSN, "SSN", 0.95, findings, context);
  if (categoryEnabled(options, "US_TAX_ID")) scanMatches(content, US_TIN, "US_TAX_ID", 0.9, findings, context);
  if (categoryEnabled(options, "MAC_ADDRESS")) scanMatches(content, MAC_ADDRESS, "MAC_ADDRESS", 0.92, findings, context);
  if (categoryEnabled(options, "POTENTIAL_SECRET")) scanMatches(content, GENERIC_SECRET, "POTENTIAL_SECRET", 0.66, findings, context);
  if (categoryEnabled(options, "STREET_ADDRESS")) {
    scanMatches(content, STREET_ADDRESS_NUMBER_FIRST, "STREET_ADDRESS", 0.78, findings, context);
    scanMatches(content, STREET_ADDRESS_NAME_FIRST_WITH_NUMBER, "STREET_ADDRESS", 0.8, findings, context);
  }

  if (categoryEnabled(options, "PHONE")) {
    PHONE.lastIndex = 0;
    let phoneMatch;
    while ((phoneMatch = PHONE.exec(content)) !== null) {
      const digits = phoneMatch[0].replace(/\D/g, "");
      if (digits.length < 7 || digits.length > 15) continue;
      addFinding(findings, "PHONE", digits.length >= 10 ? 0.85 : 0.72, phoneMatch.index, phoneMatch.index + phoneMatch[0].length, phoneMatch[0], ["phone_pattern"], context);
    }
  }

  if (categoryEnabled(options, "PERSON")) {
    NAME_CONTEXT_PATTERN.lastIndex = 0;
    let nameMatch;
    while ((nameMatch = NAME_CONTEXT_PATTERN.exec(content)) !== null) {
      const original = nameMatch[1];
      const start = nameMatch.index + nameMatch[0].indexOf(original);
      addFinding(findings, "PERSON", 0.79, start, start + original.length, original, ["contextual_name_pattern"], context);
    }
  }

  if (categoryEnabled(options, "STREET_ADDRESS")) {
    ADDRESS_CONTEXT_PATTERN.lastIndex = 0;
    let addressMatch;
    while ((addressMatch = ADDRESS_CONTEXT_PATTERN.exec(content)) !== null) {
      const original = addressMatch[1];
      const start = addressMatch.index + addressMatch[0].indexOf(original);
      addFinding(findings, "STREET_ADDRESS", 0.82, start, start + original.length, original, ["contextual_address_pattern"], context);
    }
  }

  if (categoryEnabled(options, "VIN")) {
    VIN.lastIndex = 0;
    let vinMatch;
    while ((vinMatch = VIN.exec(content)) !== null) {
      if (VIN_DISALLOWED.test(vinMatch[0])) continue;
      addFinding(findings, "VIN", 0.9, vinMatch.index, vinMatch.index + vinMatch[0].length, vinMatch[0], ["vin_pattern"], context);
    }
  }

  if (categoryEnabled(options, "PASSPORT")) {
    PASSPORT_GENERIC.lastIndex = 0;
    let passportMatch;
    while ((passportMatch = PASSPORT_GENERIC.exec(content)) !== null) {
      const value = passportMatch[0];
      if (PASSPORT_DISALLOWED.test(value)) continue;
      const alphaCount = (value.match(/[A-Z]/g) || []).length;
      const digitCount = (value.match(/\d/g) || []).length;
      const hinted = PASSPORT_KEY.test(context.keyHint || "");
      const looksLikePassportNumber = alphaCount >= 1 && digitCount >= 5;
      if ((hinted && digitCount >= 4) || looksLikePassportNumber) {
        addFinding(findings, "PASSPORT", hinted ? 0.88 : 0.76, passportMatch.index, passportMatch.index + value.length, value, [hinted ? "field_hint:passport" : "passport_pattern"], context);
      }
    }

    MRZ_PASSPORT_NUMBER.lastIndex = 0;
    let mrzPassportMatch;
    while ((mrzPassportMatch = MRZ_PASSPORT_NUMBER.exec(content)) !== null) {
      const value = mrzPassportMatch[0];
      addFinding(findings, "PASSPORT", 0.86, mrzPassportMatch.index, mrzPassportMatch.index + value.length, value, ["mrz_passport_pattern"], context);
    }

    MRZ_LINE.lastIndex = 0;
    let mrzLineMatch;
    while ((mrzLineMatch = MRZ_LINE.exec(content)) !== null) {
      addFinding(findings, "PASSPORT", 0.9, mrzLineMatch.index, mrzLineMatch.index + mrzLineMatch[0].length, mrzLineMatch[0], ["mrz_line_pattern"], context);
    }
  }

  if (categoryEnabled(options, "DRIVERS_LICENSE")) {
    DRIVERS_LICENSE_GENERIC.lastIndex = 0;
    let licenseMatch;
    while ((licenseMatch = DRIVERS_LICENSE_GENERIC.exec(content)) !== null) {
      if (!LICENSE_KEY.test(context.keyHint || "")) continue;
      addFinding(findings, "DRIVERS_LICENSE", 0.84, licenseMatch.index, licenseMatch.index + licenseMatch[0].length, licenseMatch[0], ["field_hint:drivers_license"], context);
    }
  }

  if (categoryEnabled(options, "CREDIT_CARD")) {
    CREDIT_CARD.lastIndex = 0;
    let ccMatch;
    while ((ccMatch = CREDIT_CARD.exec(content)) !== null) {
      addFinding(findings, "CREDIT_CARD", luhnOk(ccMatch[0]) ? 0.9 : 0.58, ccMatch.index, ccMatch.index + ccMatch[0].length, ccMatch[0], [luhnOk(ccMatch[0]) ? "luhn_pass" : "luhn_soft_match"], context);
    }
  }

  if (options.detectNames && context.keyHint) {
    const trimmed = content.trim();
    if (trimmed) {
      if (categoryEnabled(options, "PERSON") && NAME_KEY.test(context.keyHint) && /^[A-Za-z][A-Za-z ,.'-]{1,60}$/.test(trimmed)) {
        addFinding(findings, "PERSON", 0.84, 0, content.length, content, ["field_hint:name"], context);
      } else if (categoryEnabled(options, "EMAIL") && EMAIL_KEY.test(context.keyHint) && /^[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$/.test(trimmed)) {
        addFinding(findings, "EMAIL", 0.99, 0, content.length, content, ["field_hint:email"], context);
      } else if (categoryEnabled(options, "PLACE") && PLACE_KEY.test(context.keyHint) && /^[A-Za-z][A-Za-z ,.'-]{1,60}$/.test(trimmed)) {
        addFinding(findings, "PLACE", 0.75, 0, content.length, content, ["field_hint:place"], context);
      } else if (categoryEnabled(options, "ORG") && ORG_KEY.test(context.keyHint) && /^[A-Za-z0-9][A-Za-z0-9 &.,'-]{2,80}$/.test(trimmed)) {
        addFinding(findings, "ORG", 0.72, 0, content.length, content, ["field_hint:org"], context);
      } else if (categoryEnabled(options, "PHONE") && PHONE_KEY.test(context.keyHint) && /^[+\d(][\d\s().-]{6,}$/.test(trimmed)) {
        addFinding(findings, "PHONE", 0.84, 0, content.length, content, ["field_hint:phone"], context);
      } else if (categoryEnabled(options, "US_TAX_ID") && SSN_KEY.test(context.keyHint) && /^[A-Z0-9-]{8,15}$/.test(trimmed)) {
        addFinding(findings, "US_TAX_ID", 0.84, 0, content.length, content, ["field_hint:tax_id"], context);
      } else if (categoryEnabled(options, "PASSPORT") && PASSPORT_KEY.test(context.keyHint) && /^[A-Z0-9-]{6,12}$/.test(trimmed)) {
        addFinding(findings, "PASSPORT", 0.86, 0, content.length, content, ["field_hint:passport"], context);
      } else if (categoryEnabled(options, "DRIVERS_LICENSE") && LICENSE_KEY.test(context.keyHint) && /^[A-Z0-9-]{6,16}$/.test(trimmed)) {
        addFinding(findings, "DRIVERS_LICENSE", 0.82, 0, content.length, content, ["field_hint:drivers_license"], context);
      } else if (categoryEnabled(options, "VIN") && VIN_KEY.test(context.keyHint) && /^[A-HJ-NPR-Z0-9]{17}$/.test(trimmed)) {
        addFinding(findings, "VIN", 0.9, 0, content.length, content, ["field_hint:vin"], context);
      } else if (categoryEnabled(options, "MAC_ADDRESS") && MAC_KEY.test(context.keyHint) && /^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(trimmed)) {
        addFinding(findings, "MAC_ADDRESS", 0.92, 0, content.length, content, ["field_hint:mac"], context);
      } else if (categoryEnabled(options, "STREET_ADDRESS") && PLACE_KEY.test(context.keyHint) && /\d/.test(trimmed) && /[A-Za-z]/.test(trimmed)) {
        addFinding(findings, "STREET_ADDRESS", 0.74, 0, content.length, content, ["field_hint:address"], context);
      }
    }
  }

  findings.sort((left, right) => left.start - right.start || right.end - left.end);
  return findings.filter((item, index) => {
    const previous = findings[index - 1];
    return !previous || previous.start !== item.start || previous.end !== item.end || previous.label !== item.label;
  });
}
