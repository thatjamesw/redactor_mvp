import { editDistanceWithin, extractIdentitySeeds, identityTokens } from "../utils.js";
import { addFinding, categoryEnabled, contextHasSemanticHint } from "./shared.js";

const NAME_CONTEXT_PATTERN = /\b(?:name|customer|client|employee|user|contact|owner|recipient|nimi|henkilo|henkilö|yhteyshenkilo|yhteyshenkilö|forfattare|författare)\s*[:=-]\s*([A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+(?:[ \t]+[A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+){1,3})/gi;
const NAME_HINTS = ["name", "full name", "first name", "last name", "contact", "author", "nimi", "etunimi", "sukunimi", "yhteyshenkilo", "yhteyshenkilö", "forfattare", "författare"];
const PLACE_HINTS = ["city", "town", "location", "country", "region", "address", "osoite", "kaupunki", "paikkakunta", "maa", "land", "stad"];
const ORG_HINTS = ["company", "organisation", "organization", "employer", "business", "tenant", "yritys", "organisaatio", "bolag"];

const CONTACT_SEGMENT_NAME = /^[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö.'-]{1,}(?:\s+[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö.'-]{1,}){1,2}$/;
const CONTACT_SEGMENT_PLACE = /^[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö.'-]{1,}(?:\s+[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö.'-]{1,}){0,2}$/;
const EMAIL_LOOSE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b/g;
const IDENTITY_CANDIDATE = /\b[A-Za-zÅÄÖåäö0-9@$][A-Za-zÅÄÖåäö0-9@$.'-]{1,}(?:\s+[A-Za-zÅÄÖåäö0-9@$][A-Za-zÅÄÖåäö0-9@$.'-]{1,}){0,2}\b/g;
const COUNTRY_NAMES = new Set(`
afghanistan,albania,algeria,andorra,angola,argentina,armenia,australia,austria,azerbaijan,bahamas,bahrain,bangladesh,belarus,belgium,belize,bolivia,bosnia and herzegovina,botswana,brazil,bulgaria,cambodia,cameroon,canada,chile,china,colombia,costa rica,croatia,cyprus,czech republic,denmark,dominican republic,ecuador,egypt,el salvador,estonia,ethiopia,finland,france,georgia,germany,ghana,greece,guatemala,honduras,hong kong,hungary,iceland,india,indonesia,iran,iraq,ireland,israel,italy,jamaica,japan,jordan,kazakhstan,kenya,kuwait,latvia,lebanon,lithuania,luxembourg,malaysia,mexico,moldova,mongolia,morocco,netherlands,new zealand,nigeria,norway,pakistan,panama,peru,philippines,poland,portugal,qatar,romania,russia,saudi arabia,serbia,singapore,slovakia,slovenia,south africa,south korea,spain,sri lanka,sweden,switzerland,taiwan,thailand,tunisia,turkey,ukraine,united arab emirates,united kingdom,uk,united states,usa,uruguay,venezuela,vietnam
`.trim().split(","));

function addContextualNameFindings(content, findings, context) {
  NAME_CONTEXT_PATTERN.lastIndex = 0;
  let nameMatch;
  while ((nameMatch = NAME_CONTEXT_PATTERN.exec(content)) !== null) {
    const original = nameMatch[1];
    const start = nameMatch.index + nameMatch[0].indexOf(original);
    addFinding(findings, "PERSON", 0.79, start, start + original.length, original, ["contextual_name_pattern"], context);
  }
}

function addFieldHintIdentityFindings(content, options, findings, context) {
  if (!options.detectNames || !context.keyHint) return;
  const trimmed = content.trim();
  if (!trimmed) return;
  const nameContext = contextHasSemanticHint(context, NAME_HINTS);
  const placeContext = contextHasSemanticHint(context, PLACE_HINTS);
  const orgContext = contextHasSemanticHint(context, ORG_HINTS);

  if (categoryEnabled(options, "PERSON") && nameContext && /^[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö ,.'-]{1,60}$/.test(trimmed)) {
    addFinding(findings, "PERSON", 0.84, 0, content.length, content, ["field_hint:name"], context);
  } else if (categoryEnabled(options, "PLACE") && placeContext && /^[A-Za-zÅÄÖåäö][A-Za-zÅÄÖåäö ,.'-]{1,60}$/.test(trimmed)) {
    addFinding(findings, "PLACE", 0.75, 0, content.length, content, ["field_hint:place"], context);
  } else if (categoryEnabled(options, "ORG") && orgContext && /^[A-Za-zÅÄÖåäö0-9][A-Za-zÅÄÖåäö0-9 &.,'-]{2,80}$/.test(trimmed)) {
    addFinding(findings, "ORG", 0.72, 0, content.length, content, ["field_hint:org"], context);
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
    if (parts.length < 3 || parts.length > 6) continue;
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
        addFinding(findings, "PERSON", 0.74, start, end, segment, ["contact_line_name"], context);
        return;
      }
      if (index > emailIndex && (index === countryIndex || index === cityIndex) && CONTACT_SEGMENT_PLACE.test(segment)) {
        addFinding(findings, "PLACE", 0.72, start, end, segment, ["contact_line_place"], context);
      }
    });
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
    propagateIdentitySeeds(content, findings, context, options.identitySeeds || []);
  }

  return findings;
}
