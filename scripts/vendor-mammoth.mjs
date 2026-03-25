import { cpSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const vendorRoot = path.join(repoRoot, "static", "vendor", "mammoth");

const copies = [
  {
    from: path.join(repoRoot, "node_modules", "mammoth", "mammoth.browser.min.js"),
    to: path.join(vendorRoot, "mammoth.browser.min.js"),
  },
];

mkdirSync(vendorRoot, { recursive: true });

for (const entry of copies) {
  if (!existsSync(entry.from)) {
    throw new Error(`Missing Mammoth asset: ${path.relative(repoRoot, entry.from)}`);
  }
  cpSync(entry.from, entry.to);
  console.log(`Copied ${path.relative(repoRoot, entry.to)}`);
}

console.log("Local Mammoth assets are ready under static/vendor/mammoth.");
