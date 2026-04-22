import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const vendorRoot = path.join(repoRoot, "static", "vendor", "markdown");
const entryPoint = path.join(__dirname, "vendor-markdown-parser-entry.mjs");
const outFile = path.join(vendorRoot, "markdown-parser.bundle.mjs");

mkdirSync(vendorRoot, { recursive: true });

await build({
  entryPoints: [entryPoint],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2020",
  outfile: outFile,
  logLevel: "info",
});

console.log(`Bundled ${path.relative(repoRoot, outFile)}`);
