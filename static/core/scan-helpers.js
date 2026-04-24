import { scanTextValue } from "./detectors.js";
import { valueShapeLabels } from "./detection/evidence.js";
import { dedupeFindings, extractIdentitySeeds } from "./utils.js";

const PRECISE_PROFILE_LABELS = new Set([
  "EMAIL",
  "PHONE",
  "CREDIT_CARD",
  "IPV4",
  "IPV4_CIDR",
  "IPV6",
  "MAC_ADDRESS",
  "VIN",
  "STREET_ADDRESS",
  "POTENTIAL_SECRET",
]);

function profileGroupKey(context = {}) {
  if (context.kind === "table" && Number.isInteger(context.columnIndex)) return `table:${context.columnIndex}`;
  if (Number.isInteger(context.tableIndex) && Number.isInteger(context.columnIndex)) return `table:${context.kind || "text"}:${context.tableIndex}:${context.columnIndex}`;
  if (context.kind === "xlsx" && Number.isInteger(context.sheetIndex) && Number.isInteger(context.columnIndex)) {
    return `xlsx:${context.sheetIndex}:${context.columnIndex}`;
  }
  if (context.kind === "json" && Array.isArray(context.path) && context.path.length > 1) {
    return `json:${context.path.slice(0, -1).join(">")}`;
  }
  return "";
}

function enrichValuesWithProfiles(values) {
  const groups = new Map();
  const analysed = values.map((item) => ({
    ...item,
    shapeLabels: valueShapeLabels(item.value),
    groupKey: profileGroupKey(item.context),
  }));

  for (const item of analysed) {
    if (!item.groupKey || !String(item.value ?? "").trim()) continue;
    if (!groups.has(item.groupKey)) groups.set(item.groupKey, []);
    groups.get(item.groupKey).push(item);
  }

  const hintsByGroup = new Map();
  for (const [key, items] of groups.entries()) {
    const counts = new Map();
    for (const item of items) {
      for (const label of new Set(item.shapeLabels)) {
        counts.set(label, (counts.get(label) || 0) + 1);
      }
    }

    const hints = [];
    for (const [label, count] of counts.entries()) {
      const ratio = count / items.length;
      if (PRECISE_PROFILE_LABELS.has(label) && count >= 1) {
        hints.push(label);
      } else if (count >= 2 && ratio >= 0.6) {
        hints.push(label);
      }
    }
    if (hints.length) hintsByGroup.set(key, hints);
  }

  return analysed.map(({ groupKey, shapeLabels, ...item }) => {
    const profileHints = [...new Set([...(item.context?.profileHints || []), ...(hintsByGroup.get(groupKey) || [])])];
    if (!profileHints.length) return item;
    return { ...item, context: { ...item.context, profileHints } };
  });
}

export function scanValueCollectionWithIdentitySeeds(values, options = {}) {
  const profiledValues = enrichValuesWithProfiles(values);
  const findings = [];

  for (const { value, context } of profiledValues) {
    findings.push(...scanTextValue(value, options, context));
  }

  const identitySeeds = extractIdentitySeeds(findings);
  if (identitySeeds.length) {
    for (const { value, context } of profiledValues) {
      findings.push(...scanTextValue(value, { ...options, identitySeeds }, context));
    }
  }

  return dedupeFindings(findings);
}
