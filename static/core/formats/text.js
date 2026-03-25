import { applyTextReplacements } from "../replacements.js";
import { annotateFindings, detectLineEnding, summarise } from "../utils.js";
import { scanTextValue } from "../detectors.js";

export function prepareTextDocument(text, name = "pasted.txt") {
  return {
    kind: "text",
    name,
    content: text,
    lineEnding: detectLineEnding(text),
    trailingNewline: /\r?\n$/.test(text),
    formatInfo: {
      label: "Text",
      guarantee: "Whitespace and line breaks are preserved except where matched values are replaced.",
    },
  };
}

export function scanTextDocument(document, options = {}) {
  const findings = annotateFindings(scanTextValue(document.content, options, { kind: document.kind }));
  return { document, findings, summary: summarise(findings), preview: document.content, formatInfo: document.formatInfo };
}

export function redactTextDocument(scanResult, selectedIds, mode) {
  return {
    text: applyTextReplacements(scanResult.document.content, scanResult.findings, new Set(selectedIds), mode),
    fileName: scanResult.document.name,
    formatInfo: scanResult.formatInfo,
  };
}

