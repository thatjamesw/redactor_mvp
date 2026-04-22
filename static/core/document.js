import { prepareDelimitedDocument, redactDelimitedDocument, scanDelimitedDocument } from "./formats/delimited.js";
import { prepareDocxDocument, redactDocxDocument, scanDocxDocument } from "./formats/docx.js";
import { prepareImageDocument, redactImageDocument, scanImageDocument } from "./formats/image.js";
import { prepareJsonDocument, redactJsonDocument, scanJsonDocument } from "./formats/json.js";
import { preparePdfDocument, redactPdfDocument, scanPdfDocument } from "./formats/pdf.js";
import { prepareTextDocument, redactTextDocument, scanTextDocument } from "./formats/text.js";
import { prepareXlsxDocument, redactXlsxDocument, scanXlsxDocument } from "./formats/xlsx.js";
import { prepareYamlDocument, redactYamlDocument, scanYamlDocument } from "./formats/yaml.js";

function looksLikeYaml(text) {
  return /^[\s\S]*:\s[\s\S]*$/m.test(text) && /\n/.test(text);
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
        return prepareJsonDocument(rawText, "pasted.json");
      } catch (error) {
        void error;
      }
    }
    if (!looksLikeMarkdown(rawText) && looksLikeYaml(rawText)) return prepareYamlDocument(rawText, "pasted.yaml");
    if (/\t/.test(rawText) && /\n/.test(rawText)) return prepareDelimitedDocument(rawText, "\t", "pasted.tsv");
    if (/,[^\n]+/.test(rawText) && /\n/.test(rawText)) return prepareDelimitedDocument(rawText, ",", "pasted.csv");
  }

  return prepareTextDocument(rawText, fileName || "pasted.txt");
}

export async function scanDocument(document, options = {}) {
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
