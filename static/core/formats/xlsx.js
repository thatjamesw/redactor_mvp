import { scanTextValue } from "../detectors.js";
import { replacementFor } from "../replacements.js";
import { annotateFindings, descendingReplacementOrder, summarise } from "../utils.js";

const XLSX_SCRIPT_PATH = "./static/vendor/xlsx/xlsx.full.min.js";

async function ensureXlsx() {
  const existing = globalThis.XLSX;
  if (existing && typeof existing.read === "function") return existing;

  const prior = document.querySelector(`script[data-vendor-bundle="xlsx"]`);
  if (prior) {
    await new Promise((resolve) => {
      if (globalThis.XLSX) resolve();
      else prior.addEventListener("load", () => resolve(), { once: true });
      prior.addEventListener("error", () => resolve(), { once: true });
    });
  } else {
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = XLSX_SCRIPT_PATH;
      script.async = true;
      script.dataset.vendorBundle = "xlsx";
      script.onload = () => resolve();
      script.onerror = () => reject(new Error("Local XLSX bundle not found at static/vendor/xlsx/xlsx.full.min.js."));
      document.head.appendChild(script);
    });
  }

  const loaded = globalThis.XLSX;
  if (!loaded || typeof loaded.read !== "function") {
    throw new Error("Local XLSX bundle is missing or incomplete.");
  }
  return loaded;
}

function extFromName(name = "") {
  return name.toLowerCase().split(".").pop() || "xlsx";
}

export async function prepareXlsxDocument(fileState) {
  const XLSX = await ensureXlsx();
  const workbook = XLSX.read(fileState.arrayBuffer, { type: "array", cellDates: false, raw: false });
  const sheets = workbook.SheetNames.map((name) => {
    const matrix = XLSX.utils.sheet_to_json(workbook.Sheets[name], { header: 1, raw: false, defval: "" });
    const [headers = [], ...rows] = matrix;
    return {
      name,
      headers: headers.map((value, index) => String(value || `column_${index + 1}`)),
      rows: rows.map((row) => headers.map((_, index) => String(row[index] ?? ""))),
    };
  });
  return {
    kind: "xlsx",
    name: fileState.name || "workbook.xlsx",
    ext: extFromName(fileState.name),
    workbook,
    sheets,
    formatInfo: {
      label: "Excel workbook",
      guarantee: "Sheet names, row and column shape, and workbook structure are preserved. Formulas and formatting are not deeply rewritten yet.",
    },
  };
}

export function scanXlsxDocument(document, options = {}) {
  const findings = [];
  document.sheets.forEach((sheet, sheetIndex) => {
    sheet.rows.forEach((row, rowIndex) => {
      row.forEach((cell, columnIndex) => {
        const header = sheet.headers[columnIndex] || `column_${columnIndex + 1}`;
        findings.push(...scanTextValue(cell, options, {
          kind: "xlsx",
          sheetIndex,
          rowIndex,
          columnIndex,
          keyHint: header,
          previewPath: `${sheet.name}!row ${rowIndex + 1}.${header}`,
        }));
      });
    });
  });
  const annotated = annotateFindings(findings);
  const previewLines = document.sheets.slice(0, 2).flatMap((sheet) => {
    const rows = [sheet.headers, ...sheet.rows].slice(0, 6);
    return [`[${sheet.name}]`, ...rows.map((row) => row.join("\t"))];
  });
  return {
    document,
    findings: annotated,
    summary: summarise(annotated),
    preview: previewLines.join("\n"),
    formatInfo: document.formatInfo,
  };
}

export async function redactXlsxDocument(scanResult, selectedIds, mode) {
  const XLSX = await ensureXlsx();
  const selected = new Set(selectedIds);
  const cache = new Map();

  scanResult.document.sheets.forEach((sheet) => {
    sheet.rows = sheet.rows.map((row) => [...row]);
  });

  const grouped = new Map();
  for (const finding of scanResult.findings) {
    if (!selected.has(finding.id)) continue;
    const key = `${finding.context.sheetIndex}:${finding.context.rowIndex}:${finding.context.columnIndex}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(finding);
  }

  for (const [key, matches] of grouped.entries()) {
    const [sheetIndex, rowIndex, columnIndex] = key.split(":").map(Number);
    let output = scanResult.document.sheets[sheetIndex].rows[rowIndex][columnIndex] ?? "";
    for (const finding of [...matches].sort(descendingReplacementOrder)) {
      const original = output.slice(finding.start, finding.end);
      const replacement = replacementFor(finding.label, original, mode, cache);
      output = `${output.slice(0, finding.start)}${replacement}${output.slice(finding.end)}`;
    }
    scanResult.document.sheets[sheetIndex].rows[rowIndex][columnIndex] = output;
  }

  const workbook = XLSX.utils.book_new();
  scanResult.document.sheets.forEach((sheet) => {
    const matrix = [sheet.headers, ...sheet.rows];
    const worksheet = XLSX.utils.aoa_to_sheet(matrix);
    XLSX.utils.book_append_sheet(workbook, worksheet, sheet.name);
  });

  const binaryData = XLSX.write(workbook, { type: "array", bookType: scanResult.document.ext === "xls" ? "xls" : "xlsx" });
  const previewLines = scanResult.document.sheets.slice(0, 2).flatMap((sheet) => {
    const rows = [sheet.headers, ...sheet.rows].slice(0, 6);
    return [`[${sheet.name}]`, ...rows.map((row) => row.join("\t"))];
  });

  return {
    text: previewLines.join("\n"),
    binaryData,
    blobType: scanResult.document.ext === "xls" ? "application/vnd.ms-excel" : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    fileName: scanResult.document.name.replace(/\.(xlsx|xls)$/i, "") + "-redacted." + scanResult.document.ext,
    formatInfo: scanResult.formatInfo,
    copyable: false,
  };
}
