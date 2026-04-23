import { prepareDelimitedDocument, redactDelimitedDocument, scanDelimitedDocument } from "./formats/delimited.js";
import { prepareDocxDocument, redactDocxDocument, scanDocxDocument } from "./formats/docx.js";
import { prepareImageDocument, redactImageDocument, scanImageDocument } from "./formats/image.js";
import { prepareJsonDocument, redactJsonDocument, scanJsonDocument } from "./formats/json.js";
import { preparePdfDocument, redactPdfDocument, scanPdfDocument } from "./formats/pdf.js";
import { prepareTextDocument, redactTextDocument, scanTextDocument } from "./formats/text.js";
import { prepareXlsxDocument, redactXlsxDocument, scanXlsxDocument } from "./formats/xlsx.js";
import { prepareYamlDocument, redactYamlDocument, scanYamlDocument } from "./formats/yaml.js";

function splitDelimitedRow(line, separator) {
  const cells = [];
  let cell = "";
  let inQuotes = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];
    if (char === '"') {
      if (inQuotes && next === '"') {
        cell += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (!inQuotes && char === separator) {
      cells.push(cell);
      cell = "";
      continue;
    }
    cell += char;
  }
  cells.push(cell);
  return cells;
}

function nonEmptyLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function assessDelimited(text, separator) {
  const label = separator === "\t" ? "tsv" : "csv";
  const lines = nonEmptyLines(text);
  if (lines.length < 2) return { kind: label, confidence: "none", score: 0 };

  const widths = lines.map((line) => splitDelimitedRow(line, separator).length);
  const firstWidth = widths[0];
  if (firstWidth < 2) return { kind: label, confidence: "none", score: 0 };
  if (widths.some((width) => width !== firstWidth)) return { kind: label, confidence: "none", score: 0 };

  const rows = lines.map((line) => splitDelimitedRow(line, separator).map((cell) => cell.trim()));
  const rowCount = rows.length;
  const columnCount = firstWidth;
  const header = rows[0];

  let score = 0;
  if (rowCount >= 3) score += 2;
  else score += 1;
  if (columnCount >= 3) score += 1;
  if (lines.every((line) => line.includes(separator))) score += 1;
  if (lines.some((line) => line.includes('"'))) score += 1;

  const semanticHeader = header.every((cell) => /[A-Za-zÅÄÖåäö]/.test(cell))
    && new Set(header.map((cell) => cell.toLowerCase())).size === header.length;
  if (semanticHeader) score += 1;

  const filledCells = rows.flat().filter((cell) => cell !== "").length;
  const fillRate = filledCells / Math.max(1, rowCount * columnCount);
  if (fillRate >= 0.7) score += 1;

  return {
    kind: label,
    confidence: score >= 5 ? "high" : (score >= 3 ? "ambiguous" : "none"),
    score,
  };
}

function assessYaml(text) {
  const lines = nonEmptyLines(text);
  if (lines.length < 2) return { kind: "yaml", confidence: "none", score: 0 };
  const keyedLines = lines.filter((line) => /^\s*["'A-Za-z0-9_-]+\s*:\s*\S+/.test(line));
  if (keyedLines.length < 2) return { kind: "yaml", confidence: "none", score: 0 };
  const listLike = lines.filter((line) => /^\s*-\s+\S+/.test(line)).length;
  const score = keyedLines.length >= 3 ? 4 + (listLike > 0 ? 1 : 0) : 3;
  return {
    kind: "yaml",
    confidence: score >= 4 ? "high" : "ambiguous",
    score,
  };
}

function looksLikeMarkdown(text) {
  if (!/\n/.test(text)) return false;
  if (/^\s{0,3}#{1,6}\s+\S/m.test(text)) return true;
  if (/^\|.+\|\s*$/m.test(text) && /^\|?\s*:?-{2,}:?(?:\s*\|\s*:?-{2,}:?)+\s*\|?\s*$/m.test(text)) return true;
  if (/^\s*[-*+]\s+\S/m.test(text)) return true;
  if (/^\s*\d+\.\s+\S/m.test(text)) return true;
  if (/^\s*```/m.test(text)) return true;
  return false;
}

function annotateDetection(document, detection) {
  document.autoDetection = detection;
  return document;
}

function prepareAlternateDocument(rawText, candidate) {
  if (candidate.kind === "csv") return annotateDetection(prepareDelimitedDocument(rawText, ",", "pasted.csv"), candidate);
  if (candidate.kind === "tsv") return annotateDetection(prepareDelimitedDocument(rawText, "\t", "pasted.tsv"), candidate);
  if (candidate.kind === "yaml") return annotateDetection(prepareYamlDocument(rawText, "pasted.yaml"), candidate);
  return null;
}

function scanConcreteDocument(document, options = {}) {
  if (document.kind === "text") return scanTextDocument(document, options);
  if (document.kind === "yaml") return scanYamlDocument(document, options);
  if (document.kind === "table") return scanDelimitedDocument(document, options);
  if (document.kind === "json") return scanJsonDocument(document, options);
  if (document.kind === "docx") return scanDocxDocument(document, options);
  if (document.kind === "image") return scanImageDocument(document, options);
  if (document.kind === "pdf") return scanPdfDocument(document, options);
  if (document.kind === "xlsx") return scanXlsxDocument(document, options);
  return { document, findings: [], summary: { total: 0, high: 0, medium: 0 }, preview: "", formatInfo: document.formatInfo };
}

export async function prepareDocument({ textInput, fileName, fileMeta }) {
  if (fileMeta?.kind === "image") return prepareImageDocument(fileMeta);
  if (fileMeta?.kind === "docx") return prepareDocxDocument(fileMeta);
  if (fileMeta?.kind === "pdf") return preparePdfDocument(fileMeta);
  if (fileMeta?.kind === "xlsx") return prepareXlsxDocument(fileMeta);
  const rawText = textInput ?? "";
  const lower = (fileName || "").toLowerCase();
  if (lower.endsWith(".docx")) throw new Error("Use the file uploader for DOCX documents.");
  if (lower.endsWith(".pdf")) throw new Error("Use the file uploader for PDF documents.");
  if (lower.endsWith(".xlsx")) throw new Error("Use the file uploader for Excel workbooks.");
  if (lower.endsWith(".xls")) throw new Error("Legacy .xls is intentionally unsupported in the secure browser parser. Convert it to .xlsx first.");
  if (lower.endsWith(".json")) return prepareJsonDocument(rawText, fileName);
  if (lower.endsWith(".csv")) return prepareDelimitedDocument(rawText, ",", fileName);
  if (lower.endsWith(".tsv")) return prepareDelimitedDocument(rawText, "\t", fileName);
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return prepareYamlDocument(rawText, fileName);

  if (!fileName) {
    const trimmed = rawText.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        JSON.parse(trimmed);
        return annotateDetection(prepareJsonDocument(rawText, "pasted.json"), {
          kind: "json",
          confidence: "high",
          source: "auto",
        });
      } catch (error) {
        void error;
      }
    }

    const markdown = looksLikeMarkdown(rawText);
    const candidates = [];
    if (!markdown) {
      const yaml = assessYaml(rawText);
      if (yaml.confidence !== "none") candidates.push(yaml);

      const tsv = assessDelimited(rawText, "\t");
      if (tsv.confidence !== "none") candidates.push(tsv);

      const csv = assessDelimited(rawText, ",");
      if (csv.confidence !== "none") candidates.push(csv);
    }

    const highConfidence = candidates.filter((candidate) => candidate.confidence === "high");
    if (highConfidence.length === 1) {
      return prepareAlternateDocument(rawText, highConfidence[0]);
    }

    const textDocument = annotateDetection(prepareTextDocument(rawText, "pasted.txt"), {
      kind: "text",
      confidence: candidates.length ? "preferred" : "default",
      source: "auto",
      alternatives: candidates.map((candidate) => ({ kind: candidate.kind, confidence: candidate.confidence })),
    });
    textDocument.alternateDocuments = candidates
      .map((candidate) => prepareAlternateDocument(rawText, candidate))
      .filter(Boolean);
    return textDocument;
  }

  return prepareTextDocument(rawText, fileName || "pasted.txt");
}

export async function scanDocument(document, options = {}) {
  if (document.kind === "text" && document.alternateDocuments?.length) {
    const primary = scanTextDocument(document, options);
    const alternates = document.alternateDocuments.map((candidate) => scanConcreteDocument(candidate, options));
    const bestAlternate = alternates
      .slice()
      .sort((left, right) => {
        if (right.summary.total !== left.summary.total) return right.summary.total - left.summary.total;
        const rightHighConfidence = right.document.autoDetection?.confidence === "high" ? 1 : 0;
        const leftHighConfidence = left.document.autoDetection?.confidence === "high" ? 1 : 0;
        return rightHighConfidence - leftHighConfidence;
      })[0];

    const alternateIsClearlyBetter = bestAlternate
      && bestAlternate.summary.total > 0
      && (
        primary.summary.total === 0
        || bestAlternate.summary.total >= primary.summary.total + 2
        || (bestAlternate.summary.total > primary.summary.total && primary.summary.total <= 1)
      );

    if (alternateIsClearlyBetter) {
      return {
        ...bestAlternate,
        autoDetection: {
          source: "fallback",
          preferredKind: document.kind,
          selectedKind: bestAlternate.document.kind,
        },
      };
    }
    return primary;
  }

  return scanConcreteDocument(document, options);
}

export async function redactDocument(scanResult, selectedIds, mode = "redact") {
  if (scanResult.document.kind === "text") return redactTextDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "yaml") return redactYamlDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "table") return redactDelimitedDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "json") return redactJsonDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "docx") return redactDocxDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "image") return redactImageDocument(scanResult, selectedIds);
  if (scanResult.document.kind === "pdf") return redactPdfDocument(scanResult, selectedIds, mode);
  if (scanResult.document.kind === "xlsx") return redactXlsxDocument(scanResult, selectedIds, mode);
  return { text: "", fileName: scanResult.document.name || "redacted.txt", formatInfo: scanResult.formatInfo };
}
