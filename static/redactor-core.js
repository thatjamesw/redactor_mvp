export { scanTextValue } from "./core/detectors.js";
export { replacementFor, applyTextReplacements } from "./core/replacements.js";
export { prepareDocument, scanDocument, redactDocument } from "./core/document.js";

export function findingsForDisplay(scanResult, query = "") {
  const search = query.trim().toLowerCase();
  return scanResult.findings.filter((item) => {
    if (!search) return true;
    const haystack = [item.label, item.original, item.context?.previewPath, ...(item.reasoning || [])].join(" ").toLowerCase();
    return haystack.includes(search);
  });
}
