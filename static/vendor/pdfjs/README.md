Local PDF parsing assets live here so PDF support works without any CDN or backend.

Generated files:

- `static/vendor/pdfjs/pdf.min.mjs`
- `static/vendor/pdfjs/pdf.worker.min.mjs`
- `static/vendor/pdfjs/standard_fonts/*`

Refresh these files after dependency updates with:

```bash
npm install
npm run vendor:browser-deps
```

Why this folder exists:

- the app intentionally avoids third-party runtime script loads
- PDF text extraction stays local in the browser
- GitHub Pages can serve the parser and worker as normal static assets
