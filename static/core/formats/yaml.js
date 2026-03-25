import { scanTextValue } from "../detectors.js";
import { replacementFor } from "../replacements.js";
import { annotateFindings, descendingReplacementOrder, detectLineEnding, summarise, withTrailingNewline } from "../utils.js";

function splitYamlComment(value) {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    const previous = value[index - 1];
    if (char === "'" && !inDouble) inSingle = !inSingle;
    if (char === '"' && !inSingle && previous !== "\\") inDouble = !inDouble;
    if (char === "#" && !inSingle && !inDouble) {
      const previousChar = value[index - 1];
      if (index === 0 || /\s/.test(previousChar)) return { value: value.slice(0, index), comment: value.slice(index) };
    }
  }
  return { value, comment: "" };
}

export function prepareYamlDocument(text, name) {
  const lineEnding = detectLineEnding(text);
  const trailingNewline = /\r?\n$/.test(text);
  const lines = text.split(/\r\n|\n|\r/);
  const segments = [];
  let blockIndent = null;

  lines.forEach((line, lineIndex) => {
    const indent = line.match(/^\s*/)?.[0].length ?? 0;
    if (blockIndent !== null) {
      if (line.trim() === "" || indent > blockIndent) return;
      blockIndent = null;
    }
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;

    const dashMatch = line.match(/^(\s*-\s+)(.*)$/);
    const keyValueMatch = line.match(/^(\s*[^#][^:]*:\s*)(.*)$/);
    let prefix = "";
    let rawValue = "";
    let keyHint = "";
    let valueOffset = 0;

    if (dashMatch) {
      prefix = dashMatch[1];
      rawValue = dashMatch[2];
      valueOffset = prefix.length;
    } else if (keyValueMatch) {
      prefix = keyValueMatch[1];
      rawValue = keyValueMatch[2];
      keyHint = prefix.replace(/:\s*$/, "").trim().replace(/^['"]|['"]$/g, "");
      valueOffset = prefix.length;
    } else {
      return;
    }

    const { value: valuePart, comment } = splitYamlComment(rawValue);
    const trimmedValue = valuePart.trim();
    if (!trimmedValue) return;
    if (/^[|>][-+0-9]*$/.test(trimmedValue)) {
      blockIndent = indent;
      return;
    }

    const leadingSpace = valuePart.length - valuePart.trimStart().length;
    const trailingSpace = valuePart.length - valuePart.trimEnd().length;
    const unquotedStart = valueOffset + leadingSpace;
    const unquotedEnd = line.length - comment.length - trailingSpace;

    let value = valuePart.trim();
    let start = unquotedStart;
    let end = unquotedEnd;
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
      start += 1;
      end -= 1;
    }

    segments.push({
      segmentIndex: segments.length,
      lineIndex,
      start,
      end,
      value,
      keyHint,
      previewPath: keyHint ? `yaml.${keyHint}` : `yaml.line_${lineIndex + 1}`,
    });
  });

  return {
    kind: "yaml",
    name,
    text,
    lines,
    lineEnding,
    trailingNewline,
    segments,
    formatInfo: {
      label: "YAML",
      guarantee: "Shape and surrounding formatting are preserved for standard inline YAML scalars. Block scalars and advanced YAML features are left unchanged.",
    },
  };
}

export function scanYamlDocument(document, options = {}) {
  const findings = [];
  for (const segment of document.segments) {
    findings.push(...scanTextValue(segment.value, options, { kind: "yaml", segmentIndex: segment.segmentIndex, keyHint: segment.keyHint, previewPath: segment.previewPath }));
  }
  const annotated = annotateFindings(findings);
  return { document, findings: annotated, summary: summarise(annotated), preview: document.text, formatInfo: document.formatInfo };
}

export function redactYamlDocument(scanResult, selectedIds, mode) {
  const selected = new Set(selectedIds);
  const cache = new Map();
  const lines = [...scanResult.document.lines];
  const grouped = new Map();
  for (const finding of scanResult.findings) {
    if (!selected.has(finding.id)) continue;
    const key = String(finding.context.segmentIndex);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(finding);
  }

  for (const [key, matches] of grouped.entries()) {
    const segment = scanResult.document.segments[Number(key)];
    let output = lines[segment.lineIndex].slice(segment.start, segment.end);
    for (const finding of [...matches].sort(descendingReplacementOrder)) {
      const original = output.slice(finding.start, finding.end);
      const replacement = replacementFor(finding.label, original, mode, cache);
      output = `${output.slice(0, finding.start)}${replacement}${output.slice(finding.end)}`;
    }
    lines[segment.lineIndex] = `${lines[segment.lineIndex].slice(0, segment.start)}${output}${lines[segment.lineIndex].slice(segment.end)}`;
  }

  return {
    text: withTrailingNewline(lines.join(scanResult.document.lineEnding), scanResult.document.lineEnding, scanResult.document.trailingNewline),
    fileName: scanResult.document.name,
    formatInfo: scanResult.formatInfo,
  };
}
