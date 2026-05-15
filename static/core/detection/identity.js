import { editDistanceWithin, extractIdentitySeeds, identityTokens } from "../utils.js";
import { semanticEvidence } from "./evidence.js";
import { addFinding, categoryEnabled } from "./shared.js";

const LABELLED_VALUE_PATTERN = /\b[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}0-9 _./'-]{1,40}\s*[:=-]\s*([\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]+(?:[ \t]+[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]+){1,3})/giu;

const CONTACT_SEGMENT_NAME = /^[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}(?:\s+[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}){1,2}$/u;
const CONTACT_SEGMENT_PLACE = /^[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}(?:\s+[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}){0,2}$/u;
const EMAIL_LOOSE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b/g;
const IDENTITY_CANDIDATE = /\b[\p{Script=Latin}\p{M}0-9@$][\p{Script=Latin}\p{M}0-9@$.'\u2019-]{1,}(?:\s+[\p{Script=Latin}\p{M}0-9@$][\p{Script=Latin}\p{M}0-9@$.'\u2019-]{1,}){0,2}\b/gu;
const STANDALONE_NAME_LINE = /^[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}(?:\s+[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M}.'\u2019-]{1,}){1,2}$/u;
const NON_NAME_LINE_HINTS = /^(?:project manager|manager|owner|service owner|customer primary|customer secondary|incident response|runbook|rollback|support team|security team|engineering team)$/i;
const NON_NAME_TOKENS = new Set([
  "and", "or", "the", "for", "with", "from", "into", "onto", "over", "under",
  "project", "manager", "service", "owner", "customer", "primary", "secondary",
  "incident", "response", "rollback", "support", "security", "engineering", "team",
  "test", "sample", "internal", "external", "local", "browser",
]);
const COUNTRY_NAMES = new Set(`
afghanistan,albania,algeria,andorra,angola,argentina,armenia,australia,austria,azerbaijan,bahamas,bahrain,bangladesh,belarus,belgium,belize,bolivia,bosnia and herzegovina,botswana,brazil,bulgaria,cambodia,cameroon,canada,chile,china,colombia,costa rica,croatia,cyprus,czech republic,denmark,dominican republic,ecuador,egypt,el salvador,estonia,ethiopia,finland,france,georgia,germany,ghana,greece,guatemala,honduras,hong kong,hungary,iceland,india,indonesia,iran,iraq,ireland,israel,italy,jamaica,japan,jordan,kazakhstan,kenya,kuwait,latvia,lebanon,lithuania,luxembourg,malaysia,mexico,moldova,mongolia,morocco,netherlands,new zealand,nigeria,norway,pakistan,panama,peru,philippines,poland,portugal,qatar,romania,russia,saudi arabia,serbia,singapore,slovakia,slovenia,south africa,south korea,spain,sri lanka,sweden,switzerland,taiwan,thailand,tunisia,turkey,ukraine,united arab emirates,united kingdom,uk,united states,usa,uruguay,venezuela,vietnam
`.trim().split(","));

function addContextualNameFindings(content, findings, context) {
  LABELLED_VALUE_PATTERN.lastIndex = 0;
  let nameMatch;
  while ((nameMatch = LABELLED_VALUE_PATTERN.exec(content)) !== null) {
    const original = nameMatch[1];
    const labelHint = nameMatch[0].slice(0, nameMatch[0].indexOf(original)).replace(/[:=-]\s*$/, "").trim();
    if (!semanticEvidence({ ...context, keyHint: labelHint }, "PERSON").matched) continue;
    const start = nameMatch.index + nameMatch[0].indexOf(original);
    addFinding(findings, "PERSON", 0.73, start, start + original.length, original, ["labelled_identity_pattern"], context);
  }
}

function addFieldHintIdentityFindings(content, options, findings, context) {
  if (!options.detectNames || !context.keyHint) return;
  const trimmed = content.trim();
  if (!trimmed) return;
  const nameEvidence = semanticEvidence(context, "PERSON");
  const placeEvidence = semanticEvidence(context, "PLACE");
  const orgEvidence = semanticEvidence(context, "ORG");

  if (categoryEnabled(options, "PERSON") && nameEvidence.matched && /^[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M} ,.'\u2019-]{1,60}$/u.test(trimmed)) {
    addFinding(findings, "PERSON", Math.min(0.9, 0.72 + nameEvidence.score), 0, content.length, content, ["field_hint:name"], context);
  } else if (categoryEnabled(options, "PLACE") && placeEvidence.matched && /^[\p{Script=Latin}\p{M}][\p{Script=Latin}\p{M} ,.'\u2019-]{1,60}$/u.test(trimmed)) {
    addFinding(findings, "PLACE", Math.min(0.84, 0.66 + placeEvidence.score), 0, content.length, content, ["field_hint:place"], context);
  } else if (categoryEnabled(options, "ORG") && orgEvidence.matched && /^[\p{Script=Latin}\p{M}0-9][\p{Script=Latin}\p{M}0-9 &.,'\u2019-]{2,80}$/u.test(trimmed)) {
    addFinding(findings, "ORG", Math.min(0.84, 0.64 + orgEvidence.score), 0, content.length, content, ["field_hint:org"], context);
  }
}

function addContactLineIdentityFindings(content, findings, context) {
  const lines = content.split(/\r?\n/);
  let offset = 0;
  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    if (!line.includes(",")) continue;
    const parts = line.split(",").map((segment) => segment.trim()).filter(Boolean);
    if (parts.length < 2 || parts.length > 6) continue;
    const emailIndex = parts.findIndex((segment) => EMAIL_LOOSE.test(segment));
    EMAIL_LOOSE.lastIndex = 0;
    if (emailIndex === -1) continue;

    const countryIndex = parts.findIndex((segment, index) => index > emailIndex && COUNTRY_NAMES.has(segment.toLowerCase()));
    const cityIndex = countryIndex > emailIndex + 1 && CONTACT_SEGMENT_PLACE.test(parts[countryIndex - 1]) ? countryIndex - 1 : -1;

    let searchFrom = 0;
    parts.forEach((segment, index) => {
      const matchOffset = line.toLowerCase().indexOf(segment.toLowerCase(), searchFrom);
      if (matchOffset === -1) return;
      const start = lineStart + matchOffset;
      const end = start + segment.length;
      searchFrom = matchOffset + segment.length;

      if (index < emailIndex && CONTACT_SEGMENT_NAME.test(segment)) {
        const confidence = parts.length === 2 ? 0.78 : 0.74;
        addFinding(findings, "PERSON", confidence, start, end, segment, ["contact_line_name"], context);
        return;
      }
      if (index > emailIndex && (index === countryIndex || index === cityIndex) && CONTACT_SEGMENT_PLACE.test(segment)) {
        addFinding(findings, "PLACE", 0.72, start, end, segment, ["contact_line_place"], context);
      }
    });
  }
}

function addStandaloneNameLineFindings(content, findings, context) {
  const lines = content.split(/\r?\n/);
  let offset = 0;
  const candidates = [];
  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    const trimmed = line.trim();
    if (!trimmed || trimmed.includes(",") || trimmed.includes("@") || /\d/.test(trimmed)) continue;
    if (!STANDALONE_NAME_LINE.test(trimmed)) continue;
    if (NON_NAME_LINE_HINTS.test(trimmed)) continue;

    const tokens = trimmed.toLowerCase().split(/\s+/);
    if (tokens.some((token) => NON_NAME_TOKENS.has(token))) continue;
    if (COUNTRY_NAMES.has(trimmed.toLowerCase())) continue;

    const startOffset = line.indexOf(trimmed);
    const start = lineStart + Math.max(0, startOffset);
    candidates.push({ start, end: start + trimmed.length, original: trimmed });
  }

  const nameListConfidence = candidates.length >= 2 ? 0.84 : 0.63;
  for (const candidate of candidates) {
    const properCased = candidate.original
      .split(/\s+/)
      .every((token) => /^[\p{Lu}][\p{Ll}\p{M}.'\u2019-]+$/u.test(token));
    const confidence = Math.max(nameListConfidence, properCased ? 0.82 : 0.63);
    addFinding(findings, "PERSON", confidence, candidate.start, candidate.end, candidate.original, ["standalone_name_line"], context);
  }
}

function sameIdentityTokens(seedTokens, candidateTokens) {
  if (seedTokens.length !== candidateTokens.length || !seedTokens.length) return false;
  return seedTokens.every((seed, index) => {
    const candidate = candidateTokens[index];
    if (seed === candidate) return true;
    if (seed.length < 4 || candidate.length < 4) return false;
    return editDistanceWithin(seed, candidate, 1);
  });
}

function propagateIdentitySeeds(content, findings, context, externalSeeds = []) {
  const localSeeds = extractIdentitySeeds(findings);
  const seeds = [...localSeeds, ...externalSeeds]
    .filter((seed, index, list) => list.findIndex((other) => other.label === seed.label && other.tokens.join(" ") === seed.tokens.join(" ")) === index);

  if (!seeds.length) return;

  IDENTITY_CANDIDATE.lastIndex = 0;
  let match;
  while ((match = IDENTITY_CANDIDATE.exec(content)) !== null) {
    const original = match[0];
    const normalizedTokens = identityTokens(original);
    if (!normalizedTokens.length) continue;
    for (const seed of seeds) {
      if (!sameIdentityTokens(seed.tokens, normalizedTokens)) continue;
      const alreadyCovered = findings.some((item) => item.label === seed.label && item.start === match.index && item.end === match.index + original.length);
      if (alreadyCovered) break;
      addFinding(findings, seed.label, 0.68, match.index, match.index + original.length, original, ["identity_seed_match"], context);
      break;
    }
  }
}

export function scanIdentityFindings(content, options = {}, context = {}, findings = []) {
  if (categoryEnabled(options, "PERSON")) {
    addContextualNameFindings(content, findings, context);
  }

  addFieldHintIdentityFindings(content, options, findings, context);

  if (options.detectNames && (categoryEnabled(options, "PERSON") || categoryEnabled(options, "PLACE"))) {
    addContactLineIdentityFindings(content, findings, context);
    if (categoryEnabled(options, "PERSON")) addStandaloneNameLineFindings(content, findings, context);
    propagateIdentitySeeds(content, findings, context, options.identitySeeds || []);
  }

  return findings;
}
