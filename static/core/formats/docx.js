import { applyTextReplacements } from "../replacements.js";
import { annotateFindings, summarise } from "../utils.js";
import { scanTextValue } from "../detectors.js";

const MAMMOTH_SCRIPT_PATH = "./static/vendor/mammoth/mammoth.browser.min.js";

let mammothPromise = null;

async function ensureMammoth() {
  if (mammothPromise) return mammothPromise;
  mammothPromise = (async () => {
    if (typeof document === "undefined") {
      const imported = await import("mammoth");
      return imported.default || imported;
    }
    if (globalThis.mammoth?.extractRawText) return globalThis.mammoth;

    const prior = document.querySelector(`script[data-vendor-bundle="mammoth"]`);
    if (prior) {
      await new Promise((resolve) => {
        if (globalThis.mammoth?.extractRawText) resolve();
        else prior.addEventListener("load", () => resolve(), { once: true });
        prior.addEventListener("error", () => resolve(), { once: true });
      });
    } else {
      await new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = MAMMOTH_SCRIPT_PATH;
        script.async = true;
        script.dataset.vendorBundle = "mammoth";
        script.onload = () => resolve();
        script.onerror = () => reject(new Error("Local Mammoth bundle not found at static/vendor/mammoth/mammoth.browser.min.js."));
        document.head.appendChild(script);
      });
    }

    if (!globalThis.mammoth?.extractRawText) throw new Error("Local Mammoth bundle is missing or incomplete.");
    return globalThis.mammoth;
  })();
  return mammothPromise;
}

function cloneArrayBuffer(buffer) {
  return buffer.slice(0);
}

export async function prepareDocxDocument(fileState) {
  const mammoth = await ensureMammoth();
  const { value, messages } = await mammoth.extractRawText({ arrayBuffer: cloneArrayBuffer(fileState.arrayBuffer) });
  const content = String(value || "").replace(/\r\n/g, "\n").trim();
  return {
    kind: "docx",
    name: fileState.name || "document.docx",
    content,
    messages: messages || [],
    formatInfo: {
      label: "DOCX (text extraction)",
      guarantee: "Document text is extracted locally and exported as cleaned text. Original DOCX layout and styling are not rewritten yet.",
    },
  };
}

export function scanDocxDocument(document, options = {}) {
  const findings = annotateFindings(scanTextValue(document.content, options, { kind: "docx", previewPath: document.name }));
  return {
    document,
    findings,
    summary: summarise(findings),
    preview: document.content,
    formatInfo: document.formatInfo,
  };
}

export function redactDocxDocument(scanResult, selectedIds, mode) {
  return {
    text: applyTextReplacements(scanResult.document.content, scanResult.findings, new Set(selectedIds), mode),
    fileName: scanResult.document.name.replace(/\.docx$/i, "") + "-redacted.txt",
    formatInfo: scanResult.formatInfo,
  };
}
