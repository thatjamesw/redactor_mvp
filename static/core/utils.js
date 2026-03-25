export function fnv1a(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

export function base36Token(seed, length = 10) {
  let token = "";
  let current = seed >>> 0;
  while (token.length < length) {
    current = (current * 1664525 + 1013904223) >>> 0;
    token += current.toString(36);
  }
  return token.slice(0, length);
}

export function detectLineEnding(text) {
  if (text.includes("\r\n")) return "\r\n";
  if (text.includes("\r")) return "\r";
  return "\n";
}

export function withTrailingNewline(text, lineEnding, trailingNewline) {
  return trailingNewline ? `${text}${lineEnding}` : text;
}

export function summarise(findings) {
  return {
    total: findings.length,
    high: findings.filter((item) => item.confidence >= 0.8).length,
    medium: findings.filter((item) => item.confidence < 0.8).length,
  };
}

export function annotateFindings(findings) {
  return findings.map((item, index) => ({
    ...item,
    id: `f-${String(index + 1).padStart(4, "0")}`,
    replacement: "[REDACTED]",
  }));
}

export function descendingReplacementOrder(left, right) {
  return right.start - left.start || right.end - left.end;
}
