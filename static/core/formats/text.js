import { applyTextReplacements } from "../replacements.js";
import { annotateFindings, ascendingFindingOrder, dedupeFindings, detectLineEnding, extractIdentitySeeds, summarise } from "../utils.js";
import { scanTextValue } from "../detectors.js";

const markdownModule = typeof document === "undefined"
  ? await import("mdast-util-from-markdown")
  : await import("../../vendor/markdown/markdown-parser.bundle.mjs");
const markdownTableModule = typeof document === "undefined"
  ? await import("mdast-util-gfm-table")
  : markdownModule;
const micromarkTableModule = typeof document === "undefined"
  ? await import("micromark-extension-gfm-table")
  : markdownModule;

const { fromMarkdown } = markdownModule;
const { gfmTableFromMarkdown } = markdownTableModule;
const { gfmTable } = micromarkTableModule;

function nodePlainText(node) {
  if (!node) return "";
  if (node.type === "text" || node.type === "inlineCode") return node.value || "";
  if (!Array.isArray(node.children)) return "";
  return node.children.map((child) => nodePlainText(child)).join("");
}

function firstTextualDescendant(node) {
  if (!node) return null;
  if ((node.type === "text" || node.type === "inlineCode") && node.position) return node;
  if (!Array.isArray(node.children)) return null;
  for (const child of node.children) {
    const match = firstTextualDescendant(child);
    if (match) return match;
  }
  return null;
}

function lastTextualDescendant(node) {
  if (!node) return null;
  if ((node.type === "text" || node.type === "inlineCode") && node.position) return node;
  if (!Array.isArray(node.children)) return null;
  for (let index = node.children.length - 1; index >= 0; index -= 1) {
    const match = lastTextualDescendant(node.children[index]);
    if (match) return match;
  }
  return null;
}

function cellValueWithOffsets(source, cell) {
  const text = nodePlainText(cell).trim();
  if (!text) return null;

  const first = firstTextualDescendant(cell);
  const last = lastTextualDescendant(cell);
  const fallbackStart = cell.position?.start?.offset ?? 0;
  const fallbackEnd = cell.position?.end?.offset ?? fallbackStart;
  const start = first?.position?.start?.offset ?? fallbackStart;
  const end = last?.position?.end?.offset ?? fallbackEnd;

  return {
    text,
    start,
    end: Math.max(start, end),
    original: source.slice(start, end),
  };
}

function collapseNestedFindings(findings) {
  return findings
    .slice()
    .sort((left, right) => left.start - right.start || right.end - left.end || right.confidence - left.confidence)
    .filter((candidate, index, ordered) => !ordered.some((other, otherIndex) => {
      if (otherIndex === index) return false;
      if (other.label !== candidate.label) return false;
      if (other.start > candidate.start || other.end < candidate.end) return false;
      if (other.start === candidate.start && other.end === candidate.end) return other.confidence > candidate.confidence;
      return true;
    }));
}

function collapseDuplicateRanges(findings) {
  const bestByRange = new Map();
  for (const finding of findings) {
    const key = `${finding.start}:${finding.end}`;
    const current = bestByRange.get(key);
    if (!current || finding.confidence > current.confidence || (finding.confidence === current.confidence && finding.label < current.label)) {
      bestByRange.set(key, finding);
    }
  }
  return [...bestByRange.values()];
}

function finalizeTextFindings(findings) {
  return collapseNestedFindings(dedupeFindings(collapseDuplicateRanges(findings))).sort(ascendingFindingOrder);
}

function visitNodes(node, onNode) {
  if (!node || typeof node !== "object") return;
  onNode(node);
  if (!Array.isArray(node.children)) return;
  node.children.forEach((child) => visitNodes(child, onNode));
}

function markdownTableFindings(source, options, kind) {
  const findings = [];
  const cells = [];
  const tree = fromMarkdown(source, {
    extensions: [gfmTable()],
    mdastExtensions: [gfmTableFromMarkdown()],
  });

  visitNodes(tree, (node) => {
    if (node.type !== "table") return;
    const [headerRow, ...dataRows] = node.children || [];
    if (!headerRow?.children?.length || !dataRows.length) return;

    const headers = headerRow.children.map((cell, columnIndex) => cellValueWithOffsets(source, cell)?.text || `column_${columnIndex + 1}`);
    dataRows.forEach((row, rowIndex) => {
      row.children?.forEach((cell, columnIndex) => {
        const cellData = cellValueWithOffsets(source, cell);
        if (!cellData) return;

        const header = headers[columnIndex] || `column_${columnIndex + 1}`;
        const cellFindings = collapseNestedFindings(scanTextValue(cellData.text, options, {
          kind,
          keyHint: header,
          previewPath: `row ${rowIndex + 1}.${header}`,
          rowIndex,
          columnIndex,
        }));

        for (const finding of cellFindings) {
          findings.push({
            ...finding,
            start: cellData.start + finding.start,
            end: cellData.start + finding.end,
            original: cellData.original.slice(finding.start, finding.end) || finding.original,
          });
        }
        cells.push({ cellData, header, rowIndex, columnIndex });
      });
    });
  });

  const identitySeeds = extractIdentitySeeds(findings);
  if (identitySeeds.length) {
    cells.forEach(({ cellData, header, rowIndex, columnIndex }) => {
      const cellFindings = collapseNestedFindings(scanTextValue(cellData.text, { ...options, identitySeeds }, {
        kind,
        keyHint: header,
        previewPath: `row ${rowIndex + 1}.${header}`,
        rowIndex,
        columnIndex,
      }));
      for (const finding of cellFindings) {
        findings.push({
          ...finding,
          start: cellData.start + finding.start,
          end: cellData.start + finding.end,
          original: cellData.original.slice(finding.start, finding.end) || finding.original,
        });
      }
    });
  }

  return findings;
}

function headerlessPipeRowFindings(source, options, kind) {
  const findings = [];
  const lines = source.split(/\r?\n/);
  let offset = 0;

  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;

    if ((line.match(/\|/g) || []).length < 6) continue;
    if (/^\s*\|?\s*:?-{2,}:?/.test(line)) continue;

    const cells = line.split("|").map((cell) => cell.trim());
    if (cells.length < 5) continue;

    const cellMeta = [];
    let searchFrom = 0;
    for (const rawCell of cells) {
      if (!rawCell) continue;
      const index = line.indexOf(rawCell, searchFrom);
      if (index === -1) continue;
      cellMeta.push({
        text: rawCell,
        start: lineStart + index,
      });
      searchFrom = index + rawCell.length;
    }

    const hasEmail = cellMeta.some((cell) => /^[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$/.test(cell.text));
    const hasPhone = cellMeta.some((cell) => /^[+\d(][\d\s().-]{6,}$/.test(cell.text));
    if (!hasEmail && !hasPhone) continue;

    for (const cell of cellMeta) {
      if (!/^[A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+(?:\s+[A-ZÅÄÖ][A-Za-zÅÄÖåäö.'-]+){1,3}$/.test(cell.text)) continue;
      if (/^(?:CTO|IT|CEO|CFO|COO|Project Manager|Manager|Owner|Service Owner|Customer primary|Customer secondary)$/i.test(cell.text)) continue;
      findings.push({
        id: `f-h-${findings.length + 1}`,
        label: "PERSON",
        category: "identity",
        confidence: 0.8,
        start: cell.start,
        end: cell.start + cell.text.length,
        original: cell.text,
        reasoning: ["pipe_row_person_context"],
        context: {
          kind,
          previewPath: "pipe_row",
        },
      });
    }
  }

  return findings;
}

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
  const findings = finalizeTextFindings([
    ...scanTextValue(document.content, options, { kind: document.kind }),
    ...headerlessPipeRowFindings(document.content, options, document.kind),
    ...markdownTableFindings(document.content, options, document.kind),
  ]);
  const deduped = findings.filter((item, index) => {
    const previous = findings[index - 1];
    return !previous || previous.start !== item.start || previous.end !== item.end || previous.label !== item.label;
  });
  const annotated = annotateFindings(deduped);
  return { document, findings: annotated, summary: summarise(annotated), preview: document.content, formatInfo: document.formatInfo };
}

export function redactTextDocument(scanResult, selectedIds, mode) {
  return {
    text: applyTextReplacements(scanResult.document.content, scanResult.findings, new Set(selectedIds), mode),
    fileName: scanResult.document.name,
    formatInfo: scanResult.formatInfo,
  };
}
