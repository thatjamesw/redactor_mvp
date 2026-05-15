import { collapseOverlappingReplacements, replacementFor } from "../replacements.js";
import { scanValueCollectionWithIdentitySeeds } from "../scan-helpers.js";
import { annotateFindings, descendingReplacementOrder, detectLineEnding, summarise, withTrailingNewline } from "../utils.js";

function escapeCsvCell(value, separator) {
  const text = value == null ? "" : String(value);
  if (text.includes('"') || text.includes("\n") || text.includes("\r") || text.includes(separator)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function parseDelimited(text, separator) {
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
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
      row.push(cell);
      cell = "";
      continue;
    }
    if (!inQuotes && (char === "\n" || char === "\r")) {
      if (char === "\r" && next === "\n") index += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      continue;
    }
    cell += char;
  }
  row.push(cell);
  if (row.length > 1 || row[0] !== "" || rows.length === 0) rows.push(row);
  return rows;
}

export function serialiseDelimited(headers, rows, separator, lineEnding, trailingNewline) {
  const body = [headers, ...rows].map((row) => row.map((cell) => escapeCsvCell(cell, separator)).join(separator)).join(lineEnding);
  return withTrailingNewline(body, lineEnding, trailingNewline);
}

export function prepareDelimitedDocument(text, separator, name) {
  const rows = parseDelimited(text, separator).filter((row) => !(row.length === 1 && row[0] === ""));
  const [headerRow = [], ...dataRows] = rows;
  return {
    kind: "table",
    name,
    separator,
    headers: headerRow,
    rows: dataRows.map((row) => headerRow.map((_, index) => row[index] ?? "")),
    lineEnding: detectLineEnding(text),
    trailingNewline: /\r?\n$/.test(text),
    formatInfo: {
      label: separator === "\t" ? "TSV" : "CSV",
      guarantee: "Row and column shape are preserved. Field quoting may be normalized during export.",
    },
  };
}

export function scanDelimitedDocument(document, options = {}) {
  const cells = [];
  document.rows.forEach((row, rowIndex) => {
    row.forEach((cell, columnIndex) => {
      const header = document.headers[columnIndex] || `column_${columnIndex + 1}`;
      const context = { kind: "table", rowIndex, columnIndex, keyHint: header, previewPath: `row ${rowIndex + 1}.${header}` };
      cells.push({ value: cell, context });
    });
  });
  const findings = scanValueCollectionWithIdentitySeeds(cells, options);
  const annotated = annotateFindings(findings);
  return {
    document,
    findings: annotated,
    summary: summarise(annotated),
    preview: serialiseDelimited(document.headers, document.rows, document.separator, document.lineEnding, document.trailingNewline),
    formatInfo: document.formatInfo,
  };
}

export function redactDelimitedDocument(scanResult, selectedIds, mode) {
  const selected = new Set(selectedIds);
  const cache = new Map();
  const rows = scanResult.document.rows.map((row) => [...row]);
  const grouped = new Map();
  for (const finding of scanResult.findings) {
    if (!selected.has(finding.id)) continue;
    const key = `${finding.context.rowIndex}:${finding.context.columnIndex}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(finding);
  }
  for (const [key, matches] of grouped.entries()) {
    const [rowIndex, columnIndex] = key.split(":").map(Number);
    let output = rows[rowIndex][columnIndex] ?? "";
    for (const finding of collapseOverlappingReplacements(matches, output, mode).sort(descendingReplacementOrder)) {
      const original = output.slice(finding.start, finding.end);
      const replacement = replacementFor(finding.label, original, mode, cache);
      output = `${output.slice(0, finding.start)}${replacement}${output.slice(finding.end)}`;
    }
    rows[rowIndex][columnIndex] = output;
  }
  return {
    text: serialiseDelimited(scanResult.document.headers, rows, scanResult.document.separator, scanResult.document.lineEnding, scanResult.document.trailingNewline),
    fileName: scanResult.document.name,
    formatInfo: scanResult.formatInfo,
  };
}
