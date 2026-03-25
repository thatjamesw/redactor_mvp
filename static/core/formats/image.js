import { scanTextValue } from "../detectors.js";
import { summarise } from "../utils.js";

const TESSERACT_SCRIPT_PATH = "./static/vendor/tesseract/tesseract.min.js";
const TESSERACT_WORKER_PATH = "./static/vendor/tesseract/worker.min.js";
const TESSERACT_CORE_PATH = "./static/vendor/tesseract/core";
const TESSERACT_LANG_PATH = "./static/vendor/tesseract/lang";

let workerPromise = null;
let activeWorker = null;

async function ensureTesseract() {
  const existing = globalThis.Tesseract;
  if (existing && typeof existing.recognize === "function") return existing;

  const prior = document.querySelector(`script[data-ocr-bundle="tesseract"]`);
  if (prior) {
    await new Promise((resolve) => {
      if (globalThis.Tesseract) resolve();
      else prior.addEventListener("load", () => resolve(), { once: true });
      prior.addEventListener("error", () => resolve(), { once: true });
    });
  } else {
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = TESSERACT_SCRIPT_PATH;
      script.async = true;
      script.dataset.ocrBundle = "tesseract";
      script.onload = () => resolve();
      script.onerror = () => reject(new Error("Local OCR bundle not found at static/vendor/tesseract/tesseract.min.js."));
      document.head.appendChild(script);
    });
  }

  const loaded = globalThis.Tesseract;
  if (!loaded || typeof loaded.recognize !== "function") {
    throw new Error("Local OCR bundle is missing or incomplete. Add the vendored Tesseract browser files under static/vendor/tesseract.");
  }
  return loaded;
}

async function ensureWorker() {
  if (workerPromise) return workerPromise;

  workerPromise = (async () => {
    const Tesseract = await ensureTesseract();
    if (typeof Tesseract.createWorker !== "function") {
      throw new Error("Local OCR bundle loaded, but createWorker is unavailable.");
    }
    const worker = await Tesseract.createWorker("eng", 1, {
      workerPath: TESSERACT_WORKER_PATH,
      corePath: TESSERACT_CORE_PATH,
      langPath: TESSERACT_LANG_PATH,
      workerBlobURL: false,
      gzip: true,
      cacheMethod: "none",
      logger: () => {},
    });
    await worker.setParameters({
      preserve_interword_spaces: "1",
      user_defined_dpi: "300",
    });
    activeWorker = worker;
    return worker;
  })().catch((error) => {
    workerPromise = null;
    activeWorker = null;
    throw error;
  });

  return workerPromise;
}

export async function shutdownImageWorker() {
  if (!activeWorker) return;
  await activeWorker.terminate();
  activeWorker = null;
  workerPromise = null;
}

function loadImage(dataUrl) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Could not load the image for OCR."));
    image.src = dataUrl;
  });
}

function unionBox(boxes) {
  return boxes.reduce(
    (acc, box) => ({
      x0: Math.min(acc.x0, box.x0),
      y0: Math.min(acc.y0, box.y0),
      x1: Math.max(acc.x1, box.x1),
      y1: Math.max(acc.y1, box.y1),
    }),
    { x0: Number.POSITIVE_INFINITY, y0: Number.POSITIVE_INFINITY, x1: 0, y1: 0 }
  );
}

function lineGroups(words) {
  const map = new Map();
  words.forEach((word, index) => {
    const key = `${word.block_num ?? 0}:${word.par_num ?? 0}:${word.line_num ?? 0}`;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push({ ...word, index });
  });
  return [...map.values()].map((group) => group.sort((left, right) => (left.word_num ?? left.index) - (right.word_num ?? right.index)));
}

function buildCandidates(group) {
  const candidates = [];
  for (let start = 0; start < group.length; start += 1) {
    let text = "";
    const positions = [];
    for (let end = start; end < Math.min(group.length, start + 6); end += 1) {
      const prefix = text ? " " : "";
      const from = text.length + prefix.length;
      text += `${prefix}${group[end].text}`;
      positions.push({ from, to: from + group[end].text.length, word: group[end] });
      candidates.push({ text, positions: [...positions], words: group.slice(start, end + 1) });
    }
  }
  return candidates;
}

function imageFindingsFromCandidates(candidates, options, lineIndex) {
  const findings = [];
  for (const candidate of candidates) {
    const matches = scanTextValue(candidate.text, options, { kind: "image", previewPath: `ocr.line_${lineIndex + 1}` });
    for (const match of matches) {
      const overlapping = candidate.positions.filter((position) => !(match.end <= position.from || match.start >= position.to));
      if (!overlapping.length) continue;
      const box = unionBox(overlapping.map((position) => position.word.bbox));
      findings.push({
        label: match.label,
        category: match.category,
        confidence: match.confidence,
        start: match.start,
        end: match.end,
        original: candidate.text.slice(match.start, match.end),
        reasoning: [...match.reasoning, "ocr_bbox_map"],
        context: {
          ...match.context,
          previewPath: `ocr.line_${lineIndex + 1}`,
          bbox: box,
        },
      });
    }
  }
  const deduped = new Map();
  for (const finding of findings) {
    const box = finding.context.bbox;
    const key = `${finding.label}:${finding.original}:${box.x0}:${box.y0}:${box.x1}:${box.y1}`;
    if (!deduped.has(key) || deduped.get(key).confidence < finding.confidence) deduped.set(key, finding);
  }
  return [...deduped.values()];
}

export function prepareImageDocument(fileState) {
  return {
    kind: "image",
    name: fileState.name || "pasted-image.png",
    mimeType: fileState.mimeType || "image/png",
    dataUrl: fileState.dataUrl,
    width: fileState.width,
    height: fileState.height,
    formatInfo: {
      label: "Image",
      guarantee: "OCR runs locally in the browser. Export uses black-box redaction over detected regions rather than text replacement.",
    },
  };
}

export async function scanImageDocument(document, options = {}) {
  const worker = await ensureWorker();
  const result = await worker.recognize(document.dataUrl);
  const words = (result.data.words || []).filter((word) => {
    const text = String(word.text || "").trim();
    const confidence = Number(word.confidence ?? word.conf ?? 0);
    return text && confidence >= 35 && word.bbox;
  });
  const lines = lineGroups(words);
  const findings = [];
  lines.forEach((group, lineIndex) => {
    findings.push(...imageFindingsFromCandidates(buildCandidates(group), options, lineIndex));
  });
  const annotated = findings.map((finding, index) => ({
    ...finding,
    id: `f-${String(index + 1).padStart(4, "0")}`,
    replacement: "[REDACTED]",
  }));
  const preview = lines.map((group) => group.map((word) => word.text).join(" ")).join("\n");
  return { document, findings: annotated, summary: summarise(annotated), preview, formatInfo: document.formatInfo };
}

export async function redactImageDocument(scanResult, selectedIds) {
  const image = await loadImage(scanResult.document.dataUrl);
  const canvas = document.createElement("canvas");
  canvas.width = image.width;
  canvas.height = image.height;
  const context = canvas.getContext("2d");
  context.drawImage(image, 0, 0);

  const selected = new Set(selectedIds);
  for (const finding of scanResult.findings) {
    if (!selected.has(finding.id)) continue;
    const box = finding.context?.bbox;
    if (!box) continue;
    context.fillStyle = "#000";
    context.fillRect(box.x0, box.y0, Math.max(8, box.x1 - box.x0), Math.max(8, box.y1 - box.y0));
  }

  return {
    text: "Redacted image ready. Use the preview or export the file.",
    imageDataUrl: canvas.toDataURL("image/png"),
    fileName: scanResult.document.name.replace(/\.[^.]+$/, "") + "-redacted.png",
    formatInfo: scanResult.formatInfo,
    isImage: true,
    copyable: false,
  };
}
