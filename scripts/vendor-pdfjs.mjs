import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const vendorRoot = path.join(repoRoot, "static", "vendor", "pdfjs");

const copies = [
  {
    from: path.join(repoRoot, "node_modules", "pdfjs-dist", "build", "pdf.min.mjs"),
    to: path.join(vendorRoot, "pdf.min.mjs"),
  },
  {
    from: path.join(repoRoot, "node_modules", "pdfjs-dist", "build", "pdf.worker.min.mjs"),
    to: path.join(vendorRoot, "pdf.worker.min.mjs"),
  },
];

mkdirSync(vendorRoot, { recursive: true });
rmSync(path.join(vendorRoot, "standard_fonts"), { recursive: true, force: true });

for (const entry of copies) {
  if (!existsSync(entry.from)) {
    throw new Error(`Missing PDF.js asset: ${path.relative(repoRoot, entry.from)}`);
  }
  cpSync(entry.from, entry.to);
  console.log(`Copied ${path.relative(repoRoot, entry.to)}`);
}

const standardFontsFrom = path.join(repoRoot, "node_modules", "pdfjs-dist", "standard_fonts");
const standardFontsTo = path.join(vendorRoot, "standard_fonts");
if (!existsSync(standardFontsFrom)) {
  throw new Error(`Missing PDF.js standard fonts: ${path.relative(repoRoot, standardFontsFrom)}`);
}
cpSync(standardFontsFrom, standardFontsTo, { recursive: true });
console.log(`Copied ${path.relative(repoRoot, standardFontsTo)}`);

console.log("Local PDF.js assets are ready under static/vendor/pdfjs.");
