import { scanTextValue } from "./detectors.js";
import { dedupeFindings, extractIdentitySeeds } from "./utils.js";

export function scanValueCollectionWithIdentitySeeds(values, options = {}) {
  const findings = [];

  for (const { value, context } of values) {
    findings.push(...scanTextValue(value, options, context));
  }

  const identitySeeds = extractIdentitySeeds(findings);
  if (identitySeeds.length) {
    for (const { value, context } of values) {
      findings.push(...scanTextValue(value, { ...options, identitySeeds }, context));
    }
  }

  return dedupeFindings(findings);
}
