Local Excel workbook parsing assets live here so `.xlsx` support works without any CDN or backend.

Generated files:

- `static/vendor/exceljs/exceljs.min.js`

Refresh these files after dependency updates with:

```bash
npm install
npm run vendor:browser-deps
```

Why this folder exists:

- the app intentionally avoids third-party runtime script loads
- workbook parsing and export stay local in the browser
- GitHub Pages can serve the parser as a normal static asset
