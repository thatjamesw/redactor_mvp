import { collapseOverlappingReplacements, replacementFor } from "../replacements.js";
import { scanValueCollectionWithIdentitySeeds } from "../scan-helpers.js";
import { annotateFindings, descendingReplacementOrder, detectLineEnding, summarise } from "../utils.js";

function parseJsonString(text, startIndex) {
  let index = startIndex + 1;
  let value = "";
  while (index < text.length) {
    const char = text[index];
    if (char === '"') return { value, end: index + 1 };
    if (char === "\\") {
      const next = text[index + 1];
      if (next === "u") {
        const hex = text.slice(index + 2, index + 6);
        value += String.fromCharCode(Number.parseInt(hex, 16));
        index += 6;
        continue;
      }
      const escapes = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      value += escapes[next] ?? next;
      index += 2;
      continue;
    }
    value += char;
    index += 1;
  }
  throw new Error("Unterminated JSON string");
}

function parseJsonWithLocations(text) {
  let index = 0;
  const locations = [];

  function skipWhitespace() {
    while (index < text.length && /\s/.test(text[index])) index += 1;
  }

  function parseValue(path = []) {
    skipWhitespace();
    const char = text[index];
    if (char === "{") return parseObject(path);
    if (char === "[") return parseArray(path);
    if (char === '"') {
      const start = index;
      const parsed = parseJsonString(text, index);
      index = parsed.end;
      locations.push({ path, value: parsed.value, start, end: index });
      return parsed.value;
    }
    if (char === "-" || /\d/.test(char)) return parseNumber();
    if (text.startsWith("true", index)) {
      index += 4;
      return true;
    }
    if (text.startsWith("false", index)) {
      index += 5;
      return false;
    }
    if (text.startsWith("null", index)) {
      index += 4;
      return null;
    }
    throw new Error(`Unexpected token at ${index}`);
  }

  function parseObject(path) {
    const result = {};
    index += 1;
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return result;
    }
    while (index < text.length) {
      skipWhitespace();
      if (text[index] !== '"') throw new Error(`Expected object key at ${index}`);
      const key = parseJsonString(text, index);
      index = key.end;
      skipWhitespace();
      if (text[index] !== ":") throw new Error(`Expected ':' at ${index}`);
      index += 1;
      result[key.value] = parseValue([...path, key.value]);
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return result;
      }
      if (text[index] !== ",") throw new Error(`Expected ',' at ${index}`);
      index += 1;
    }
    throw new Error("Unterminated JSON object");
  }

  function parseArray(path) {
    const result = [];
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return result;
    }
    let itemIndex = 0;
    while (index < text.length) {
      result.push(parseValue([...path, String(itemIndex)]));
      itemIndex += 1;
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return result;
      }
      if (text[index] !== ",") throw new Error(`Expected ',' at ${index}`);
      index += 1;
    }
    throw new Error("Unterminated JSON array");
  }

  function parseNumber() {
    const start = index;
    while (index < text.length && /[-+0-9.eE]/.test(text[index])) index += 1;
    return Number(text.slice(start, index));
  }

  const value = parseValue([]);
  skipWhitespace();
  if (index !== text.length) throw new Error(`Unexpected trailing content at ${index}`);
  return { value, locations };
}

export function prepareJsonDocument(text, name) {
  const parsed = parseJsonWithLocations(text);
  return {
    kind: "json",
    name,
    source: text,
    value: parsed.value,
    locations: parsed.locations,
    lineEnding: detectLineEnding(text),
    trailingNewline: /\r?\n$/.test(text),
    formatInfo: {
      label: "JSON",
      guarantee: "JSON structure and surrounding whitespace are preserved while string scalar values are updated in place.",
    },
  };
}

export function scanJsonDocument(document, options = {}) {
  const locations = document.locations.map((location) => {
    const keyHint = location.path[location.path.length - 1] || "";
    return {
      value: location.value,
      context: { kind: "json", path: location.path, keyHint, previewPath: location.path.join(".") },
    };
  });
  const findings = scanValueCollectionWithIdentitySeeds(locations, options);
  const annotated = annotateFindings(findings);
  return { document, findings: annotated, summary: summarise(annotated), preview: document.source, formatInfo: document.formatInfo };
}

export function redactJsonDocument(scanResult, selectedIds, mode) {
  const selected = new Set(selectedIds);
  const cache = new Map();
  const grouped = new Map();
  for (const finding of scanResult.findings) {
    if (!selected.has(finding.id)) continue;
    const key = finding.context.path.join(">");
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(finding);
  }

  const replacements = [];
  for (const location of scanResult.document.locations) {
    const key = location.path.join(">");
    const matches = grouped.get(key) || [];
    if (!matches.length) continue;
    let output = location.value;
    for (const finding of collapseOverlappingReplacements(matches, output, mode).sort(descendingReplacementOrder)) {
      const original = output.slice(finding.start, finding.end);
      const replacement = replacementFor(finding.label, original, mode, cache);
      output = `${output.slice(0, finding.start)}${replacement}${output.slice(finding.end)}`;
    }
    replacements.push({ start: location.start, end: location.end, jsonValue: JSON.stringify(output) });
  }

  let text = scanResult.document.source;
  for (const replacement of replacements.sort(descendingReplacementOrder)) {
    text = `${text.slice(0, replacement.start)}${replacement.jsonValue}${text.slice(replacement.end)}`;
  }
  return { text, fileName: scanResult.document.name, formatInfo: scanResult.formatInfo };
}
