import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { prepareDocument, redactDocument, scanDocument } from "../static/redactor-core.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const casesPath = path.join(repoRoot, "tests", "regression-cases.json");
const cases = JSON.parse(fs.readFileSync(casesPath, "utf8"));

function optionsFor(testCase) {
  return {
    strictEmail: testCase.options?.strictEmail ?? true,
    detectNames: testCase.options?.detectNames ?? true,
    detectFaces: false,
    aggressiveImageDocs: false,
    imageMode: "standard",
    enabledCategories: testCase.options?.enabledCategories ?? {
      pii: true,
      identity: true,
      financial: true,
      network: true,
      secrets: true,
    },
  };
}

async function runCase(testCase) {
  const document = await prepareDocument({
    textInput: testCase.input,
    fileName: testCase.fileName,
    fileMeta: null,
  });
  const scan = await scanDocument(document, optionsFor(testCase));
  const threshold = testCase.threshold === "medium" ? 0.55 : 0.8;
  const selected = scan.findings.filter((finding) => finding.confidence >= threshold).map((finding) => finding.id);
  const redacted = await redactDocument(scan, selected, testCase.mode || "redact");
  const output = redacted.text || "";

  const failures = [];
  for (const present of testCase.expectPresent || []) {
    if (!output.includes(present)) failures.push(`missing expected text: ${present}`);
  }
  for (const absent of testCase.expectAbsent || []) {
    if (output.includes(absent)) failures.push(`unexpected residual text: ${absent}`);
  }
  if (typeof testCase.minFindings === "number" && scan.summary.total < testCase.minFindings) {
    failures.push(`expected at least ${testCase.minFindings} findings, got ${scan.summary.total}`);
  }

  return { name: testCase.name, failures };
}

const results = [];
for (const testCase of cases) {
  // eslint-disable-next-line no-await-in-loop
  results.push(await runCase(testCase));
}

const failed = results.filter((result) => result.failures.length > 0);
for (const result of results) {
  const status = result.failures.length ? "FAIL" : "PASS";
  console.log(`${status} ${result.name}`);
  for (const failure of result.failures) console.log(`  - ${failure}`);
}

if (failed.length) {
  console.error(`\n${failed.length} regression case(s) failed.`);
  process.exit(1);
}

console.log(`\nAll ${results.length} regression cases passed.`);
