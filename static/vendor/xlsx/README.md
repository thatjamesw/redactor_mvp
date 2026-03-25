Local XLSX parsing assets live here so spreadsheet support works without any CDN or backend.

Generated files:

- `static/vendor/xlsx/xlsx.full.min.js`

Refresh these files after dependency updates with:

```bash
npm install
npm run vendor:browser-deps
```

Why this folder exists:

- the app intentionally avoids third-party runtime script loads
- spreadsheet parsing stays local in the browser
- GitHub Pages can serve the workbook parser as a normal static asset
