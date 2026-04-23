import { dedupeFindings } from "./utils.js";
import { scanIdentityFindings } from "./detection/identity.js";
import { scanStructuredFindings } from "./detection/structured.js";

export function scanTextValue(text, options = {}, context = {}) {
  const content = String(text ?? "");
  const findings = [];

  scanStructuredFindings(content, options, context, findings);
  scanIdentityFindings(content, options, context, findings);

  findings.sort((left, right) => left.start - right.start || right.end - left.end);
  return dedupeFindings(findings);
}
