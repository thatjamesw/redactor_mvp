import { base36Token, descendingReplacementOrder, fnv1a } from "./utils.js";

export function replacementFor(label, original, mode, cache) {
  if (mode === "redact") return "[REDACTED]";
  const key = `${label}:${original}`;
  if (!cache.has(key)) {
    const seed = fnv1a(key);
    let value = "[REDACTED]";
    if (label === "EMAIL") value = `user+${base36Token(seed, 10)}@example.test`;
    else if (label === "IPV4") value = `198.51.100.${(seed % 253) + 1}`;
    else if (label === "IPV4_CIDR") value = `198.51.100.0/${Math.min(32, Math.max(8, Number(String(original).split("/")[1] || 24)))}`;
    else if (label === "IPV6") value = `2001:db8::${(seed % 65535).toString(16)}`;
    else if (label === "UUID") value = `${base36Token(seed, 8)}-${base36Token(seed + 1, 4)}-${base36Token(seed + 2, 4)}-${base36Token(seed + 3, 4)}-${base36Token(seed + 4, 12)}`.slice(0, 36);
    else if (label === "PERSON") value = `Person_${base36Token(seed, 8)}`;
    else if (label === "PLACE") value = `Place_${base36Token(seed, 6)}`;
    else if (label === "ORG") value = `Org_${base36Token(seed, 7)}`;
    else if (label === "CREDIT_CARD") value = `4111 1111 ${String((seed % 10000) + 1000).slice(0, 4)} ${String(((seed >>> 2) % 10000) + 1000).slice(0, 4)}`;
    else value = `redact-${base36Token(seed, 16)}`;
    cache.set(key, value);
  }
  return cache.get(key);
}

export function applyTextReplacements(text, findings, selectedIds, mode) {
  const selected = collapseOverlappingReplacements(
    findings.filter((item) => selectedIds.has(item.id)),
    text,
    mode
  ).sort(descendingReplacementOrder);
  let output = text;
  const cache = new Map();
  for (const item of selected) {
    const original = output.slice(item.start, item.end);
    const replacement = replacementFor(item.label, original, mode, cache);
    output = `${output.slice(0, item.start)}${replacement}${output.slice(item.end)}`;
  }
  return output;
}

export function collapseOverlappingReplacements(findings, text = "", mode = "redact") {
  const ordered = findings
    .filter((item) => Number.isFinite(item.start) && Number.isFinite(item.end) && item.end > item.start)
    .slice()
    .sort((left, right) => left.start - right.start || left.end - right.end || (right.confidence || 0) - (left.confidence || 0));
  const collapsed = [];

  for (const finding of ordered) {
    const current = collapsed[collapsed.length - 1];
    if (!current || finding.start >= current.end) {
      collapsed.push({ ...finding });
      continue;
    }

    const best = (finding.confidence || 0) > (current.confidence || 0) ? finding : current;
    current.start = Math.min(current.start, finding.start);
    current.end = Math.max(current.end, finding.end);
    current.label = best.label;
    current.confidence = Math.max(current.confidence || 0, finding.confidence || 0);
    current.reasoning = [...new Set([...(current.reasoning || []), ...(finding.reasoning || []), "overlap_collapsed"])];
    current.original = text.slice(current.start, current.end) || current.original;

    if (mode === "redact") current.label = "REDACTED";
  }

  return collapsed;
}
