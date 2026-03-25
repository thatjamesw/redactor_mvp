import { benchmarkCorpus } from "./core/benchmark-data.js";
import { shutdownImageWorker } from "./core/formats/image.js";
import { findingsForDisplay, prepareDocument, redactDocument, scanDocument, scanTextValue } from "./redactor-core.js";

const fileInput = document.querySelector("#file-input");
const textInput = document.querySelector("#text-input");
const presetSelect = document.querySelector("#preset-select");
const modeSelect = document.querySelector("#mode-select");
const confidenceSelect = document.querySelector("#confidence-select");
const imageModeSelect = document.querySelector("#image-mode-select");
const filterSearch = document.querySelector("#filter-search");
const strictEmail = document.querySelector("#strict-email");
const detectNames = document.querySelector("#detect-names");
const detectFaces = document.querySelector("#detect-faces");
const categoryToggles = [...document.querySelectorAll(".category-toggle")];
const findingsEl = document.querySelector("#findings");
const reviewEmpty = document.querySelector("#review-empty");
const outputEl = document.querySelector("#output");
const inputStatus = document.querySelector("#input-status");
const outputStatus = document.querySelector("#output-status");
const outputRisk = document.querySelector("#output-risk");
const benchmarkStatus = document.querySelector("#benchmark-status");
const benchmarkResults = document.querySelector("#benchmark-results");
const benchmarkBreakdown = document.querySelector("#benchmark-breakdown");
const benchmarkTotal = document.querySelector("#benchmark-total");
const benchmarkHit = document.querySelector("#benchmark-hit");
const benchmarkRate = document.querySelector("#benchmark-rate");
const fileSummary = document.querySelector("#file-summary");
const formatNote = document.querySelector("#format-note");
const outputNote = document.querySelector("#output-note");
const copyButton = document.querySelector("#copy-button");
const downloadButton = document.querySelector("#download-button");
const stickySafeCopyButton = document.querySelector("#sticky-safe-copy");
const stickyCopyButton = document.querySelector("#sticky-copy-button");
const stickyDownloadButton = document.querySelector("#sticky-download-button");
const stickySelection = document.querySelector("#sticky-selection");
const stickySummary = document.querySelector("#sticky-summary");
const metricTotal = document.querySelector("#metric-total");
const metricHigh = document.querySelector("#metric-high");
const metricMedium = document.querySelector("#metric-medium");
const metricAuto = document.querySelector("#metric-auto");
const metricCurrent = document.querySelector("#metric-current");
const metricLeft = document.querySelector("#metric-left");
const selectionNote = document.querySelector("#selection-note");
const imageTools = document.querySelector("#image-tools");
const manualBoxButton = document.querySelector("#manual-box-button");
const clearManualBoxesButton = document.querySelector("#clear-manual-boxes-button");

let fileState = null;
let scanState = null;
let outputState = null;
let selectionState = new Set();
let recommendedSelectionState = new Set();
let manualDrawMode = false;
let manualBoxDraft = null;
let manualBoxCounter = 0;

const presets = {
  llm_safe: {
    strictEmail: true,
    detectNames: true,
    detectFaces: true,
    imageMode: "standard",
    confidence: "high",
    categories: { pii: true, identity: true, financial: true, network: true, secrets: true },
  },
  paranoid: {
    strictEmail: true,
    detectNames: true,
    detectFaces: true,
    imageMode: "document_safe",
    confidence: "medium",
    categories: { pii: true, identity: true, financial: true, network: true, secrets: true },
  },
  balanced: {
    strictEmail: true,
    detectNames: true,
    detectFaces: true,
    imageMode: "standard",
    confidence: "medium",
    categories: { pii: true, identity: true, financial: true, network: true, secrets: true },
  },
  secrets_only: {
    strictEmail: true,
    detectNames: false,
    detectFaces: false,
    imageMode: "standard",
    confidence: "high",
    categories: { pii: false, identity: false, financial: false, network: true, secrets: true },
  },
  structured_pii: {
    strictEmail: true,
    detectNames: true,
    detectFaces: true,
    imageMode: "document_safe",
    confidence: "medium",
    categories: { pii: true, identity: true, financial: true, network: false, secrets: false },
  },
};

function setStatus(element, message, type = "") {
  element.textContent = message;
  element.className = `status ${type}`.trim();
}

function escapeHtml(text) {
  return String(text ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function renderSummary(summary = { total: 0, high: 0, medium: 0 }) {
  metricTotal.textContent = String(summary.total || 0);
  metricHigh.textContent = String(summary.high || 0);
  metricMedium.textContent = String(summary.medium || 0);
}

function setsEqual(left, right) {
  if (left.size !== right.size) return false;
  for (const item of left) if (!right.has(item)) return false;
  return true;
}

function renderSelectionTrust() {
  const autoCount = recommendedSelectionState.size;
  const currentCount = selectionState.size;
  const total = scanState?.findings?.length || 0;
  const leftCount = Math.max(0, total - currentCount);
  metricAuto.textContent = String(autoCount);
  metricCurrent.textContent = String(currentCount);
  metricLeft.textContent = String(leftCount);

  if (!scanState) {
    selectionNote.textContent = "High-confidence findings will be auto-selected after a scan.";
    outputRisk.textContent = "Run a scan to see whether anything is still outside the current output.";
    outputRisk.className = "risk-banner";
    return;
  }
  const thresholdLabel = confidenceSelect.value === "medium" ? "high and medium confidence" : "high confidence";
  if (setsEqual(selectionState, recommendedSelectionState)) {
    selectionNote.textContent = `Auto-selection is using ${thresholdLabel}. ${leftCount} finding${leftCount === 1 ? "" : "s"} remain outside the current output.`;
  } else {
    const added = [...selectionState].filter((id) => !recommendedSelectionState.has(id)).length;
    const removed = [...recommendedSelectionState].filter((id) => !selectionState.has(id)).length;
    selectionNote.textContent = `You adjusted the default selection: ${added} added, ${removed} removed. Current output reflects ${currentCount} selected finding${currentCount === 1 ? "" : "s"}.`;
  }
  if (leftCount > 0) {
    outputRisk.textContent = `${leftCount} finding${leftCount === 1 ? "" : "s"} remain outside the current output. Review before copying or exporting if you want the safest possible result.`;
    outputRisk.className = "risk-banner warn";
  } else {
    outputRisk.textContent = "All current findings are included in the output. Copy or export is in a good state.";
    outputRisk.className = "risk-banner safe";
  }
}

function refreshActions() {
  const hasOutput = Boolean((outputState?.text || "").trim());
  const downloadable = Boolean((outputState?.text || "").trim() || outputState?.imageDataUrl);
  const copyable = hasOutput && outputState?.copyable !== false && !outputState?.isImage;
  copyButton.disabled = !copyable;
  downloadButton.disabled = !downloadable;
  stickyCopyButton.disabled = !copyable;
  stickyDownloadButton.disabled = !downloadable;
  stickySelection.textContent = `${selectionState.size} selected`;
  stickySummary.textContent = downloadable
    ? "Current output is ready to copy or export."
    : (scanState ? "Adjust findings and output will update automatically." : "Run a scan to generate safe output.");
}

function manualFindings() {
  return (scanState?.findings || []).filter((finding) => finding.reasoning?.includes("manual_redaction_box"));
}

function syncImageToolState() {
  const isImage = Boolean(scanState?.document?.kind === "image" && outputState?.isImage);
  imageTools.classList.toggle("hidden", !isImage);
  manualBoxButton.disabled = !isImage;
  clearManualBoxesButton.disabled = !isImage || manualFindings().length === 0;
  manualBoxButton.textContent = manualDrawMode ? "Drawing boxes…" : "Draw blackout boxes";
}

function renderFormatNote(formatInfo, target) {
  target.textContent = formatInfo ? `${formatInfo.label}: ${formatInfo.guarantee}` : "";
}

function mimeTypeForFile(name = "") {
  const lower = name.toLowerCase();
  if (lower.endsWith(".json")) return "application/json;charset=utf-8";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "application/yaml;charset=utf-8";
  if (lower.endsWith(".csv")) return "text/csv;charset=utf-8";
  if (lower.endsWith(".tsv")) return "text/tab-separated-values;charset=utf-8";
  if (lower.endsWith(".xlsx")) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  if (lower.endsWith(".xls")) return "application/vnd.ms-excel";
  return "text/plain;charset=utf-8";
}

function autoSelectThreshold() {
  return confidenceSelect.value === "medium" ? 0.55 : 0.8;
}

function currentEnabledCategories() {
  return Object.fromEntries(categoryToggles.map((toggle) => [toggle.dataset.category, toggle.checked]));
}

function applyPreset(name) {
  const preset = presets[name];
  if (!preset) return;
  strictEmail.checked = preset.strictEmail;
  detectNames.checked = preset.detectNames;
  detectFaces.checked = preset.detectFaces;
  imageModeSelect.value = preset.imageMode;
  confidenceSelect.value = preset.confidence;
  categoryToggles.forEach((toggle) => {
    toggle.checked = preset.categories[toggle.dataset.category] !== false;
  });
}

function currentOptions() {
  return {
    strictEmail: strictEmail.checked,
    detectNames: detectNames.checked,
    detectFaces: detectFaces.checked,
    aggressiveImageDocs: imageModeSelect.value === "document_safe",
    imageMode: imageModeSelect.value,
    enabledCategories: currentEnabledCategories(),
  };
}

async function currentDocument() {
  const sourceText = fileState?.kind === "text" ? fileState.text : textInput.value;
  const fileName = fileState ? fileState.name : undefined;
  return prepareDocument({ textInput: sourceText, fileName, fileMeta: fileState });
}

async function readInputFile(file) {
  const lowerName = (file.name || "").toLowerCase();
  if ((file.type || "").startsWith("image/")) {
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("Could not read the image file."));
      reader.readAsDataURL(file);
    });
    const dimensions = await new Promise((resolve, reject) => {
      const image = new Image();
      image.onload = () => resolve({ width: image.naturalWidth, height: image.naturalHeight });
      image.onerror = () => reject(new Error("Could not load the image preview."));
      image.src = dataUrl;
    });
    return { kind: "image", name: file.name, dataUrl, mimeType: file.type, size: file.size, ...dimensions };
  }
  if (lowerName.endsWith(".xlsx") || lowerName.endsWith(".xls")) {
    const arrayBuffer = await file.arrayBuffer();
    return { kind: "xlsx", name: file.name, arrayBuffer, size: file.size };
  }
  const text = await file.text();
  return { kind: "text", name: file.name, text, size: file.size };
}

function selectedIds() {
  return [...selectionState];
}

function renderImageOverlay() {
  const overlay = outputEl.querySelector(".output-overlay");
  const image = outputEl.querySelector("img");
  if (!(overlay instanceof HTMLElement) || !(image instanceof HTMLImageElement) || scanState?.document?.kind !== "image") return;
  overlay.innerHTML = "";
  overlay.classList.toggle("drawing", manualDrawMode);

  const naturalWidth = scanState.document.width || image.naturalWidth || 1;
  const naturalHeight = scanState.document.height || image.naturalHeight || 1;
  const displayWidth = image.clientWidth || image.width || 1;
  const displayHeight = image.clientHeight || image.height || 1;

  for (const finding of manualFindings()) {
    const box = finding.context?.bbox;
    if (!box) continue;
    const element = document.createElement("div");
    element.className = "manual-box";
    element.style.left = `${(box.x0 / naturalWidth) * displayWidth}px`;
    element.style.top = `${(box.y0 / naturalHeight) * displayHeight}px`;
    element.style.width = `${((box.x1 - box.x0) / naturalWidth) * displayWidth}px`;
    element.style.height = `${((box.y1 - box.y0) / naturalHeight) * displayHeight}px`;
    overlay.appendChild(element);
  }

  if (manualBoxDraft) {
    const element = document.createElement("div");
    element.className = "manual-box live";
    element.style.left = `${manualBoxDraft.left}px`;
    element.style.top = `${manualBoxDraft.top}px`;
    element.style.width = `${manualBoxDraft.width}px`;
    element.style.height = `${manualBoxDraft.height}px`;
    overlay.appendChild(element);
  }
}

function addManualRedactionBox(box) {
  if (!scanState || scanState.document.kind !== "image") return;
  manualBoxCounter += 1;
  const finding = {
    id: `f-manual-${manualBoxCounter}`,
    label: "MANUAL_AREA",
    category: "identity",
    confidence: 1,
    start: 0,
    end: 0,
    original: "Manual blackout box",
    reasoning: ["manual_redaction_box"],
    context: {
      kind: "image",
      previewPath: `manual.box_${manualBoxCounter}`,
      bbox: box,
    },
    replacement: "[REDACTED]",
  };
  scanState.findings.push(finding);
  scanState.summary = {
    total: scanState.findings.length,
    high: scanState.findings.filter((item) => item.confidence >= 0.8).length,
    medium: scanState.findings.filter((item) => item.confidence < 0.8).length,
  };
  selectionState.add(finding.id);
  recommendedSelectionState.add(finding.id);
  renderFindings();
  renderSelectionTrust();
  syncImageToolState();
  refreshOutputFromSelection("Added a manual blackout box.").catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
}

function clearManualRedactionBoxes() {
  if (!scanState) return;
  const manualIds = new Set(manualFindings().map((finding) => finding.id));
  if (!manualIds.size) return;
  scanState.findings = scanState.findings.filter((finding) => !manualIds.has(finding.id));
  selectionState = new Set([...selectionState].filter((id) => !manualIds.has(id)));
  recommendedSelectionState = new Set([...recommendedSelectionState].filter((id) => !manualIds.has(id)));
  scanState.summary = {
    total: scanState.findings.length,
    high: scanState.findings.filter((item) => item.confidence >= 0.8).length,
    medium: scanState.findings.filter((item) => item.confidence < 0.8).length,
  };
  manualBoxDraft = null;
  renderFindings();
  renderSelectionTrust();
  syncImageToolState();
  refreshOutputFromSelection("Cleared manual blackout boxes.").catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
}

function renderFindings() {
  findingsEl.innerHTML = "";
  if (!scanState) {
    renderSummary();
    renderSelectionTrust();
    reviewEmpty.classList.remove("hidden");
    return;
  }
  const filtered = findingsForDisplay(scanState, filterSearch.value);
  renderSummary(scanState.summary);
  reviewEmpty.classList.toggle("hidden", filtered.length > 0);

  for (const finding of filtered) {
    const confidenceClass = finding.confidence >= 0.8 ? "high" : "medium";
    const wasRecommended = recommendedSelectionState.has(finding.id);
    const isSelected = selectionState.has(finding.id);
    const selectionLabel = isSelected
      ? (wasRecommended ? "Auto-selected" : "Manually selected")
      : (wasRecommended ? "Skipped manually" : "Not auto-selected");
    const wrapper = document.createElement("article");
    wrapper.className = "finding";
    wrapper.innerHTML = `
      <div class="finding-top">
        <label class="toggle"><input class="finding-select" type="checkbox" value="${finding.id}" ${isSelected ? "checked" : ""} /> Select</label>
        <span class="badge ${confidenceClass}">${finding.label}</span>
        <span class="badge ${finding.category || "pii"}">${finding.category || "other"}</span>
        <span class="badge ${confidenceClass}">${finding.confidence.toFixed(2)}</span>
        <span class="badge trust">${selectionLabel}</span>
      </div>
      <code>${escapeHtml(finding.original)}</code>
      <div class="meta">${escapeHtml(finding.context?.previewPath || finding.context?.kind || "text")} • ${escapeHtml((finding.reasoning || []).join(", ") || "matched rule")}</div>
    `;
    findingsEl.appendChild(wrapper);
  }
}

function updateSelectionFromThreshold() {
  if (!scanState) return;
  const threshold = autoSelectThreshold();
  recommendedSelectionState = new Set(scanState.findings.filter((item) => item.confidence >= threshold).map((item) => item.id));
  selectionState = new Set(recommendedSelectionState);
  renderFindings();
  renderSelectionTrust();
}

function setOutput(result) {
  outputState = result;
  if (result.isImage && result.imageDataUrl) {
    outputEl.innerHTML = `<div class="output-canvas"><img src="${result.imageDataUrl}" alt="Redacted output preview" /><div class="output-overlay"></div></div>`;
  } else {
    outputEl.textContent = result.text;
  }
  renderFormatNote(result.formatInfo, outputNote);
  refreshActions();
  renderSelectionTrust();
  syncImageToolState();
  renderImageOverlay();
}

async function refreshOutputFromSelection(statusMessage = "") {
  if (!scanState) return null;
  const result = await redactDocument(scanState, selectedIds(), modeSelect.value);
  setOutput(result);
  if (statusMessage) setStatus(outputStatus, statusMessage, "success");
  return result;
}

async function runScan() {
  const documentModel = await currentDocument();
  manualDrawMode = false;
  manualBoxDraft = null;
  if (documentModel.kind === "image") {
    setStatus(inputStatus, "Running OCR locally in your browser. The first image can take a little while.", "warn");
  }
  scanState = await scanDocument(documentModel, currentOptions());
  updateSelectionFromThreshold();
  renderFormatNote(scanState.formatInfo, formatNote);
  await refreshOutputFromSelection();
  setStatus(inputStatus, `Scan complete. ${scanState.summary.total} findings detected locally in your browser.`, "success");
  setStatus(outputStatus, "Review the findings or copy the current output right away.", "");
}

function applySelected() {
  if (!scanState) {
    setStatus(outputStatus, "Run a scan first so there is something to apply.", "warn");
    return null;
  }
  return refreshOutputFromSelection(`Applied ${selectedIds().length} selected findings.`);
}

async function copyOutput(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus(outputStatus, successMessage, "success");
  } catch (error) {
    setStatus(outputStatus, `Copy failed: ${error.message}`, "error");
  }
}

function runBenchmark() {
  const options = currentOptions();
  const results = benchmarkCorpus.map((testCase) => {
    const findings = scanTextValue(testCase.text, options, { keyHint: testCase.keyHint || "", previewPath: "benchmark" });
    const matched = findings.some((finding) => finding.label === testCase.label);
    return { ...testCase, matched, findings };
  });
  const hitCount = results.filter((item) => item.matched).length;
  benchmarkTotal.textContent = String(results.length);
  benchmarkHit.textContent = String(hitCount);
  benchmarkRate.textContent = `${Math.round((hitCount / Math.max(1, results.length)) * 100)}%`;
  const byCategory = new Map();
  for (const item of results) {
    if (!byCategory.has(item.category)) byCategory.set(item.category, { total: 0, hit: 0 });
    const bucket = byCategory.get(item.category);
    bucket.total += 1;
    if (item.matched) bucket.hit += 1;
  }
  benchmarkBreakdown.textContent = [...byCategory.entries()]
    .map(([category, stats]) => `${category}: ${stats.hit}/${stats.total}`)
    .join(" • ");
  benchmarkResults.classList.remove("empty");
  benchmarkResults.innerHTML = results.map((item) => `${item.matched ? "PASS" : "MISS"}  ${item.label.padEnd(16, " ")}  ${item.text}`).join("\n");
  setStatus(benchmarkStatus, `${hitCount} of ${results.length} benchmark samples matched with the current detector settings.`, hitCount === results.length ? "success" : "warn");
}

document.querySelector("#scan-button").addEventListener("click", async () => {
  try {
    await runScan();
  } catch (error) {
    setStatus(inputStatus, `Scan failed: ${error.message}`, "error");
  }
});

document.querySelector("#apply-button").addEventListener("click", async () => {
  try {
    await applySelected();
  } catch (error) {
    setStatus(outputStatus, `Apply failed: ${error.message}`, "error");
  }
});

document.querySelector("#safe-copy-button").addEventListener("click", async () => {
  try {
    await runScan();
    const result = await refreshOutputFromSelection();
    if (result?.copyable !== false && result?.text) {
      await copyOutput(result.text, "LLM-safe output copied to your clipboard.");
    } else {
      setStatus(outputStatus, "Image redaction ready. Use export to save the black-boxed image.", "success");
    }
  } catch (error) {
    setStatus(outputStatus, `LLM-safe copy failed: ${error.message}`, "error");
  }
});
stickySafeCopyButton.addEventListener("click", async () => {
  try {
    await runScan();
    const result = await refreshOutputFromSelection();
    if (result?.copyable !== false && result?.text) {
      await copyOutput(result.text, "LLM-safe output copied to your clipboard.");
    } else {
      setStatus(outputStatus, "Image redaction ready. Use export to save the black-boxed image.", "success");
    }
  } catch (error) {
    setStatus(outputStatus, `LLM-safe copy failed: ${error.message}`, "error");
  }
});

document.querySelector("#copy-button").addEventListener("click", async () => {
  if (!outputState?.text) return;
  const hasResidualRisk = Boolean(scanState && scanState.findings.length > selectionState.size);
  await copyOutput(outputState.text, hasResidualRisk ? "Output copied. Some findings still remain outside the current output." : "Output copied to your clipboard.");
});
stickyCopyButton.addEventListener("click", async () => {
  if (!outputState?.text) return;
  const hasResidualRisk = Boolean(scanState && scanState.findings.length > selectionState.size);
  await copyOutput(outputState.text, hasResidualRisk ? "Output copied. Some findings still remain outside the current output." : "Output copied to your clipboard.");
});

document.querySelector("#download-button").addEventListener("click", () => {
  if (!outputState) return;
  const downloadName = outputState.fileName?.startsWith("redacted_") ? outputState.fileName : `redacted_${outputState.fileName || "output.txt"}`;
  const link = document.createElement("a");
  let objectUrl = "";
  if (outputState.isImage && outputState.imageDataUrl) {
    link.href = outputState.imageDataUrl;
  } else if (outputState.binaryData) {
    const blob = new Blob([outputState.binaryData], { type: outputState.blobType || mimeTypeForFile(downloadName) });
    objectUrl = URL.createObjectURL(blob);
    link.href = objectUrl;
  } else {
    const blob = new Blob([outputState.text], { type: mimeTypeForFile(downloadName) });
    objectUrl = URL.createObjectURL(blob);
    link.href = objectUrl;
  }
  link.download = downloadName;
  link.click();
  if (objectUrl) URL.revokeObjectURL(objectUrl);
  setStatus(outputStatus, scanState && scanState.findings.length > selectionState.size ? "File downloaded, but some findings remain outside the current output." : "Redacted file downloaded locally.", scanState && scanState.findings.length > selectionState.size ? "warn" : "success");
});
stickyDownloadButton.addEventListener("click", () => {
  if (!outputState) return;
  document.querySelector("#download-button").click();
});

document.querySelector("#benchmark-button").addEventListener("click", runBenchmark);

document.querySelector("#clear-button").addEventListener("click", async () => {
  fileInput.value = "";
  textInput.value = "";
  filterSearch.value = "";
  fileState = null;
  scanState = null;
  outputState = null;
  selectionState = new Set();
  recommendedSelectionState = new Set();
  manualDrawMode = false;
  manualBoxDraft = null;
  findingsEl.innerHTML = "";
  outputEl.innerHTML = "";
  fileSummary.textContent = "No file selected.";
  formatNote.textContent = "Format guarantees will appear here after the app recognises your input.";
  outputNote.textContent = "Output formatting notes will appear here once content has been processed.";
  benchmarkResults.textContent = "Benchmark results will appear here.";
  benchmarkResults.classList.add("empty");
  benchmarkBreakdown.textContent = "Category breakdown will appear here after running the benchmark.";
  benchmarkTotal.textContent = "0";
  benchmarkHit.textContent = "0";
  benchmarkRate.textContent = "0%";
  renderSummary();
  renderSelectionTrust();
  reviewEmpty.classList.remove("hidden");
  refreshActions();
  await shutdownImageWorker();
  setStatus(inputStatus, "Cleared the current session.", "");
  setStatus(outputStatus, "", "");
  setStatus(benchmarkStatus, "", "");
  syncImageToolState();
});

document.querySelector("#select-all-button").addEventListener("click", () => {
  selectionState = new Set((scanState?.findings || []).map((item) => item.id));
  renderFindings();
  renderSelectionTrust();
  refreshOutputFromSelection().catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
});

document.querySelector("#select-none-button").addEventListener("click", () => {
  selectionState = new Set();
  renderFindings();
  renderSelectionTrust();
  refreshOutputFromSelection().catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
});

presetSelect.addEventListener("change", () => {
  applyPreset(presetSelect.value);
  if (scanState) {
    runScan().catch((error) => setStatus(inputStatus, `Preset update failed: ${error.message}`, "error"));
  }
});

confidenceSelect.addEventListener("change", () => {
  updateSelectionFromThreshold();
  refreshOutputFromSelection().catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
});
modeSelect.addEventListener("change", () => {
  if (scanState) refreshOutputFromSelection().catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
});
strictEmail.addEventListener("change", () => {
  if (scanState) runScan().catch((error) => setStatus(inputStatus, `Detector update failed: ${error.message}`, "error"));
});
detectNames.addEventListener("change", () => {
  if (scanState) runScan().catch((error) => setStatus(inputStatus, `Detector update failed: ${error.message}`, "error"));
});
detectFaces.addEventListener("change", () => {
  if (scanState) runScan().catch((error) => setStatus(inputStatus, `Image update failed: ${error.message}`, "error"));
});
imageModeSelect.addEventListener("change", () => {
  if (scanState) runScan().catch((error) => setStatus(inputStatus, `Image update failed: ${error.message}`, "error"));
});
categoryToggles.forEach((toggle) => {
  toggle.addEventListener("change", () => {
    if (scanState) runScan().catch((error) => setStatus(inputStatus, `Category update failed: ${error.message}`, "error"));
  });
});
filterSearch.addEventListener("input", renderFindings);
findingsEl.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.classList.contains("finding-select")) return;
  if (target.checked) selectionState.add(target.value);
  else selectionState.delete(target.value);
  renderSelectionTrust();
  refreshOutputFromSelection().catch((error) => setStatus(outputStatus, `Refresh failed: ${error.message}`, "error"));
});

fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  if (!file) {
    fileState = null;
    fileSummary.textContent = "No file selected.";
    return;
  }
  try {
    fileState = await readInputFile(file);
    manualDrawMode = false;
    manualBoxDraft = null;
    fileSummary.textContent = `${fileState.name} loaded locally (${Math.round(fileState.size / 1024) || 1} KB). Pasted text is ignored while a file is selected.`;
    renderFormatNote((await currentDocument()).formatInfo, formatNote);
    setStatus(inputStatus, "File loaded locally. Click LLM-safe copy for the fastest workflow.", "success");
  } catch (error) {
    fileState = null;
    setStatus(inputStatus, `Could not read file: ${error.message}`, "error");
  }
});

document.addEventListener("paste", async (event) => {
  const items = [...(event.clipboardData?.items || [])];
  const imageItem = items.find((item) => item.type.startsWith("image/"));
  if (!imageItem) return;
  const file = imageItem.getAsFile();
  if (!file) return;
  event.preventDefault();
  try {
    fileState = await readInputFile(file);
    manualDrawMode = false;
    manualBoxDraft = null;
    fileSummary.textContent = `${fileState.name} pasted from clipboard. OCR will run locally in the browser.`;
    renderFormatNote((await currentDocument()).formatInfo, formatNote);
    setStatus(inputStatus, "Image pasted from clipboard. Click scan or LLM-safe copy to process it.", "success");
  } catch (error) {
    setStatus(inputStatus, `Could not read pasted image: ${error.message}`, "error");
  }
});

textInput.addEventListener("input", () => {
  if (fileState) return;
  currentDocument().then((documentModel) => {
    renderFormatNote(documentModel.formatInfo, formatNote);
  }).catch(() => {
    formatNote.textContent = "Format recognition will appear here once the input parses cleanly.";
  });
});

manualBoxButton.addEventListener("click", () => {
  if (!scanState || scanState.document.kind !== "image") return;
  manualDrawMode = !manualDrawMode;
  manualBoxDraft = null;
  syncImageToolState();
  renderImageOverlay();
  setStatus(outputStatus, manualDrawMode ? "Drag on the image to add blackout boxes." : "Manual blackout mode turned off.", manualDrawMode ? "warn" : "");
});

clearManualBoxesButton.addEventListener("click", () => {
  clearManualRedactionBoxes();
});

outputEl.addEventListener("pointerdown", (event) => {
  if (!manualDrawMode || !scanState || scanState.document.kind !== "image") return;
  const overlay = outputEl.querySelector(".output-overlay");
  if (!(overlay instanceof HTMLElement)) return;
  const rect = overlay.getBoundingClientRect();
  manualBoxDraft = {
    startX: Math.min(Math.max(event.clientX - rect.left, 0), rect.width),
    startY: Math.min(Math.max(event.clientY - rect.top, 0), rect.height),
    left: Math.min(Math.max(event.clientX - rect.left, 0), rect.width),
    top: Math.min(Math.max(event.clientY - rect.top, 0), rect.height),
    width: 0,
    height: 0,
  };
  renderImageOverlay();
});

outputEl.addEventListener("pointermove", (event) => {
  if (!manualDrawMode || !manualBoxDraft) return;
  const overlay = outputEl.querySelector(".output-overlay");
  if (!(overlay instanceof HTMLElement)) return;
  const rect = overlay.getBoundingClientRect();
  const currentX = Math.min(Math.max(event.clientX - rect.left, 0), rect.width);
  const currentY = Math.min(Math.max(event.clientY - rect.top, 0), rect.height);
  manualBoxDraft.left = Math.min(manualBoxDraft.startX, currentX);
  manualBoxDraft.top = Math.min(manualBoxDraft.startY, currentY);
  manualBoxDraft.width = Math.abs(currentX - manualBoxDraft.startX);
  manualBoxDraft.height = Math.abs(currentY - manualBoxDraft.startY);
  renderImageOverlay();
});

outputEl.addEventListener("pointerup", () => {
  if (!manualDrawMode || !manualBoxDraft || !scanState || scanState.document.kind !== "image") return;
  const overlay = outputEl.querySelector(".output-overlay");
  const image = outputEl.querySelector("img");
  if (!(overlay instanceof HTMLElement) || !(image instanceof HTMLImageElement)) return;
  const rect = overlay.getBoundingClientRect();
  const naturalWidth = scanState.document.width || image.naturalWidth || 1;
  const naturalHeight = scanState.document.height || image.naturalHeight || 1;
  if (manualBoxDraft.width >= 12 && manualBoxDraft.height >= 12) {
    addManualRedactionBox({
      x0: (manualBoxDraft.left / rect.width) * naturalWidth,
      y0: (manualBoxDraft.top / rect.height) * naturalHeight,
      x1: ((manualBoxDraft.left + manualBoxDraft.width) / rect.width) * naturalWidth,
      y1: ((manualBoxDraft.top + manualBoxDraft.height) / rect.height) * naturalHeight,
    });
  }
  manualBoxDraft = null;
  renderImageOverlay();
});

refreshActions();
applyPreset(presetSelect.value);
renderSelectionTrust();
syncImageToolState();
window.addEventListener("beforeunload", () => {
  shutdownImageWorker().catch(() => {});
});
