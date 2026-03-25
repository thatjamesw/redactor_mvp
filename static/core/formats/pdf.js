import { applyTextReplacements } from "../replacements.js";
import { annotateFindings, summarise } from "../utils.js";
import { scanTextValue } from "../detectors.js";

const PDF_SCRIPT_URL = new URL("../../vendor/pdfjs/pdf.min.mjs", import.meta.url);
const PDF_WORKER_URL = new URL("../../vendor/pdfjs/pdf.worker.min.mjs", import.meta.url);
const PDF_STANDARD_FONT_URL = new URL("../../vendor/pdfjs/standard_fonts/", import.meta.url);

let pdfPromise = null;

function cloneArrayBuffer(buffer) {
  return buffer.slice(0);
}

async function ensurePdfJs() {
  if (pdfPromise) return pdfPromise;
  pdfPromise = (async () => {
    const browser = typeof document !== "undefined";
    const imported = browser
      ? await import(PDF_SCRIPT_URL.href)
      : await import("pdfjs-dist/legacy/build/pdf.mjs");
    const pdfjs = imported.default || imported;
    if (browser && pdfjs.GlobalWorkerOptions) pdfjs.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL.href;
    return pdfjs;
  })();
  return pdfPromise;
}

function normalisePageLines(items) {
  const rows = [];
  for (const item of items) {
    const value = String(item.str || "").trim();
    if (!value) continue;
    const y = Math.round((item.transform?.[5] || 0) * 10) / 10;
    const x = item.transform?.[4] || 0;
    let row = rows.find((entry) => Math.abs(entry.y - y) < 3);
    if (!row) {
      row = { y, items: [] };
      rows.push(row);
    }
    row.items.push({ x, value });
  }
  return rows
    .sort((left, right) => right.y - left.y)
    .map((row) => row.items.sort((left, right) => left.x - right.x).map((item) => item.value).join(" ").replace(/\s+/g, " ").trim())
    .filter(Boolean);
}

function joinPages(pages) {
  return pages.map((page) => `[Page ${page.pageNumber}]\n${page.text}`.trim()).join("\n\n");
}

export async function preparePdfDocument(fileState) {
  const pdfjs = await ensurePdfJs();
  const bytes = new Uint8Array(cloneArrayBuffer(fileState.arrayBuffer));
  const loadingTask = pdfjs.getDocument({
    data: bytes,
    useWorkerFetch: false,
    isEvalSupported: false,
    disableWorker: typeof document === "undefined",
    standardFontDataUrl: typeof document === "undefined"
      ? new URL("../../vendor/pdfjs/standard_fonts/", import.meta.url).pathname
      : PDF_STANDARD_FONT_URL.href,
  });
  const pdf = await loadingTask.promise;
  const pages = [];
  for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
    const page = await pdf.getPage(pageNumber);
    const textContent = await page.getTextContent();
    const lines = normalisePageLines(textContent.items || []);
    pages.push({
      pageNumber,
      text: lines.join("\n"),
    });
  }
  return {
    kind: "pdf",
    name: fileState.name || "document.pdf",
    pages,
    extractedText: joinPages(pages),
    formatInfo: {
      label: "PDF (text extraction)",
      guarantee: "Text is extracted locally page by page. Output is safe redacted text export, not a visually rebuilt PDF.",
    },
  };
}

export function scanPdfDocument(document, options = {}) {
  const findings = [];
  document.pages.forEach((page) => {
    findings.push(...scanTextValue(page.text, options, {
      kind: "pdf",
      pageNumber: page.pageNumber,
      previewPath: `Page ${page.pageNumber}`,
    }));
  });
  const annotated = annotateFindings(findings);
  return {
    document,
    findings: annotated,
    summary: summarise(annotated),
    preview: document.extractedText,
    formatInfo: document.formatInfo,
  };
}

export function redactPdfDocument(scanResult, selectedIds, mode) {
  const selected = new Set(selectedIds);
  const pages = scanResult.document.pages.map((page) => {
    const matches = scanResult.findings.filter((finding) => selected.has(finding.id) && finding.context?.pageNumber === page.pageNumber);
    return {
      ...page,
      text: applyTextReplacements(page.text, matches, selected, mode),
    };
  });
  return {
    text: joinPages(pages),
    fileName: scanResult.document.name.replace(/\.pdf$/i, "") + "-redacted.txt",
    formatInfo: scanResult.formatInfo,
  };
}
