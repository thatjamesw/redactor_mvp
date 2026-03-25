# Redactor MVP

Browser-based redaction tool for cleaning sensitive data before sharing it with LLMs or other external systems.

## What It Does

- Scans pasted text or uploaded text-based files locally in the browser
- Flags likely PII and secrets such as emails, phone numbers, SSNs, tax IDs, passport-like IDs, driver's-license-like IDs, IPs, MAC addresses, VINs, street addresses, UUIDs, API keys, JWTs, and credit card numbers
- Lets you review findings before applying them
- Supports both `redact` and `pseudonymise` output modes
- Includes a one-click `LLM-safe copy` workflow
- Lets you copy the cleaned result or export it as a file
- Includes a built-in benchmark view so you can track detector coverage over time
- Includes workflow presets for `LLM-safe`, `Balanced`, `Secrets only`, and `Structured PII`

## Security Posture

- No backend processing
- No analytics, telemetry, or remote logging
- No browser storage used for your pasted data
- Strict client-side Content Security Policy via meta tag
- Referrer disabled
- Browser permissions locked down via `Permissions-Policy`
- No third-party runtime scripts
- OCR worker, core, and English language data served locally from this repo
- OCR traineddata cache disabled to avoid persisting language assets or OCR state in IndexedDB

This means the default GitHub Pages deployment is designed to avoid outbound network requests during both text and OCR workflows.

## Dependency Updates

The repository now includes:

- `package.json` for managed OCR dependency tracking
- `.github/dependabot.yml` for weekly updates to both npm dependencies and GitHub Actions

For OCR specifically, Dependabot can keep both `tesseract.js` and `@tesseract.js-data/eng` current. That is much safer and more maintainable than hardcoding a third-party CDN script in the page.

## Supported Inputs

The static build currently supports:

- pasted text
- `.txt`
- `.csv`
- `.tsv`
- `.json`
- `.yaml`
- `.yml`
- `.png`, `.jpg`, `.jpeg`, `.webp`, and other browser-readable images via local OCR

## Format Guarantees

- `Text`: whitespace and line breaks are preserved except where matched values are replaced
- `JSON`: structure and surrounding whitespace are preserved while string scalar values are updated in place
- `CSV` / `TSV`: row and column shape are preserved, though field quoting may be normalized on export
- `YAML`: inline scalar values are updated while surrounding formatting is preserved for standard mappings and lists; advanced YAML features such as complex tags, anchors, and block scalar bodies are intentionally left untouched

## Current Gaps

These are not yet part of the static browser build:

- PDF parsing
- DOCX parsing
- Excel support
- exact byte-for-byte formatting preservation for every structured format

## Local OCR Assets

OCR is now bundled locally for a security-first static deployment. The app loads only from:

- [static/vendor/tesseract/tesseract.min.js](/Users/jameswright/dev/_mvp/redactor_mvp/static/vendor/tesseract/tesseract.min.js)
- [static/vendor/tesseract/worker.min.js](/Users/jameswright/dev/_mvp/redactor_mvp/static/vendor/tesseract/worker.min.js)
- [static/vendor/tesseract/core](/Users/jameswright/dev/_mvp/redactor_mvp/static/vendor/tesseract/core)
- [static/vendor/tesseract/lang](/Users/jameswright/dev/_mvp/redactor_mvp/static/vendor/tesseract/lang)

The vendored files are generated from npm dependencies with:

```bash
npm install
npm run vendor:ocr
```

That script copies the browser runtime, worker, WebAssembly core files, and `eng.traineddata.gz` from managed dependencies into the static site directory.

Current OCR scope:

- English language OCR only
- black-box image redaction export
- no OCR blob worker URLs
- no IndexedDB OCR cache writes

## GitHub Pages

This repo is set up to deploy as a static site with GitHub Pages via GitHub Actions.

Once Pages is enabled for the repository, pushes to `main` will publish the app automatically.

The Pages workflow installs locked npm dependencies and regenerates the local OCR bundle before uploading the site artifact, so Dependabot updates flow through deployment cleanly.

## Local Development

Because this is now a static app, the easiest way to test it locally is with a simple static server:

```bash
cd /Users/jameswright/dev/_mvp/redactor_mvp
python3 -m http.server 4173
```

Then open:

```text
http://localhost:4173
```

Using a local server is more reliable than opening `index.html` directly from `file://`, because the app uses ES modules.
