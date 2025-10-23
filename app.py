from flask import Flask, request, jsonify, send_from_directory, url_for
from pathlib import Path
import os, io, time, json, base64, re
import pandas as pd
import yaml

from redactor import (
    scan_text, apply_replacements_from_findings,
    promote_shapes_to_registry, reload_registry
)

app = Flask(__name__)

# ---- Export dir (local, configurable) ----
EXPORT_DIR = Path(os.getenv("EXPORT_DIR", Path(app.root_path) / "exports"))
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# =====================================================================
# Helpers (added for table-safe preview/export)
# =====================================================================

def _guess_sep(filename: str) -> str:
    """Return the delimiter for CSV/TSV based on filename."""
    return "\t" if filename.lower().endswith(".tsv") else ","

def _read_tabular(filename: str, raw: bytes) -> pd.DataFrame:
    """Read CSV/TSV/XLSX into a DataFrame with strings (no NA coercion)."""
    fname = filename.lower()
    if fname.endswith((".xlsx", ".xls")):
        bio = io.BytesIO(raw)
        # For redact/preview we only work on the first sheet
        return pd.read_excel(bio, dtype=str, keep_default_na=False)
    else:
        sep = _guess_sep(filename)
        from io import StringIO
        text = raw.decode("utf-8", errors="ignore")
        return pd.read_csv(StringIO(text), sep=sep, dtype=str, keep_default_na=False)

def _preview_from_dataframe(df: pd.DataFrame, limit: int = 100) -> str:
    """Stable line-by-line preview built from a redacted DataFrame."""
    lines = []
    n = min(len(df), limit)
    for i in range(n):
        for col in df.columns:
            val = df.iloc[i][col]
            sval = "" if pd.isna(val) else str(val).replace("\r\n", "\n").replace("\r", "\n")
            lines.append(f"row {i+1}.{col}: {sval}")
    return "\n".join(lines)

# -------- OCR cleanup helpers --------

def _clean_ocr_text(raw_text: str) -> str:
    """Heuristically clean OCR text to reduce gibberish lines.

    - Normalize whitespace
    - Remove control chars
    - Drop lines with too few letters or too many non-alnum symbols
    - Limit repeated punctuation
    """
    if not isinstance(raw_text, str):
        return ""
    text = raw_text.replace("\r", "\n")
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        # Remove control characters
        s = ''.join(ch for ch in s if (32 <= ord(ch) <= 126) or ch in "\t ")
        s = s.strip()
        if not s:
            continue
        alpha = sum(c.isalpha() for c in s)
        total = len(s)
        if alpha < 2:
            continue
        non_alnum = sum(not c.isalnum() and c not in " -_.,:/@()'\"#&+" for c in s)
        if total and non_alnum / total > 0.5:
            continue
        # Collapse long runs of punctuation
        s = re.sub(r"([\-_.,:/])\1{3,}", r"\1\1\1", s)
        lines.append(s)
    return "\n".join(lines)

# -------- NEW: selection-by-text helpers (avoid span offsets on tables) --------

def _compute_replacement_for_finding(f: dict, mode: str, ip_mode: str) -> str:
    """Return mode-aware replacement for a single finding's original text.

    Uses apply_replacements_from_findings to honour mode/pseudo rules.
    """
    orig = f.get("original")
    if not isinstance(orig, str) or not orig:
        return None
    try:
        # Adjust span to the substring we are replacing (0..len(orig))
        mini = dict(f)
        mini["start"] = 0
        mini["end"] = len(orig)
        mini["original"] = orig
        replaced = apply_replacements_from_findings(
            orig,
            [mini],
            selected_ids=[mini.get("id")],
            mode=mode,
            ip_mode=ip_mode,
        )
        return replaced
    except Exception:
        return None


def _build_selected_pairs(findings_payload: dict, selected_ids: list, mode: str, ip_mode: str):
    """Build (original, replacement) pairs from the selected findings, mode-aware."""
    pairs = []
    if not findings_payload:
        return pairs
    sel = set(selected_ids or [])
    for f in findings_payload.get("findings", []):
        if f.get("id") in sel:
            orig = f.get("original")
            # Prefer mode-aware replacement; fallback to provided replacement
            repl = _compute_replacement_for_finding(f, mode, ip_mode) or f.get("replacement") or "[REDACTED]"
            if isinstance(orig, str) and orig:
                pairs.append((orig, repl))
    # Longest originals first to minimise partial-overlap cascades
    pairs.sort(key=lambda t: len(t[0]), reverse=True)
    # De-dupe by original, keep the first (longest) replacement
    seen = set()
    out = []
    for o, r in pairs:
        if o not in seen:
            seen.add(o)
            out.append((o, r))
    return out

def _apply_pairs_to_text(s: str, pairs: list):
    """Apply (original -> replacement) pairs via literal substitution."""
    if not isinstance(s, str) or not s:
        return s
    for orig, repl in pairs:
        s = s.replace(orig, repl)
    return s

def _df_apply_selected_by_text(df: pd.DataFrame, findings_payload: dict, selected_ids: list, mode: str, ip_mode: str) -> pd.DataFrame:
    """Apply selected findings to each cell by exact text match (no spans)."""
    pairs = _build_selected_pairs(findings_payload, selected_ids, mode, ip_mode)
    if not pairs:
        return df.copy()
    return df.applymap(lambda v: _apply_pairs_to_text("" if pd.isna(v) else str(v), pairs))

# ---- NEW: pragmatic name-column fallback (redact mode only) ----
NAME_COL_RE = re.compile(r'^(?:full[-_\s]?name|name)$', re.IGNORECASE)

def _force_name_redaction(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    """If a column is clearly a personal name column, force redact its cells in redact mode."""
    if mode != "redact":
        return df
    name_cols = [c for c in df.columns if NAME_COL_RE.match(str(c).strip())]
    if not name_cols:
        return df
    df2 = df.copy()
    for c in name_cols:
        df2[c] = df2[c].apply(lambda v: "[REDACTED]" if isinstance(v, str) and v.strip() else v)
    return df2

# Pragmatic location-column fallback (redact mode only)
LOCATION_COL_RE = re.compile(r'^(?:city|town|location|country|region)$', re.IGNORECASE)

def _force_location_redaction(df: pd.DataFrame, mode: str) -> pd.DataFrame:
    if mode != "redact":
        return df
    loc_cols = [c for c in df.columns if LOCATION_COL_RE.match(str(c).strip())]
    if not loc_cols:
        return df
    df2 = df.copy()
    for c in loc_cols:
        df2[c] = df2[c].apply(lambda v: "[REDACTED]" if isinstance(v, str) and v.strip() else v)
    return df2

# ---------- Routes ----------

@app.get("/")
def home():
    return send_from_directory(".", "index.html")

@app.get("/download/<path:filename>")
def download_file(filename):
    # serves files from ./exports as attachments
    return send_from_directory(EXPORT_DIR, filename, as_attachment=True)

@app.post("/scan")
def route_scan():
    # Flags FIRST (so we can pass b64_plain to canonicaliser)
    use_ner = request.form.get("use_ner") == "1"
    intl_ids = request.form.get("intl_ids") == "1"
    strict_email = request.form.get("strict_email") == "1"
    b64_plain = request.form.get("b64_plain") == "1"
    debug = request.form.get("debug") == "1"
    ignore_headers = request.form.get("ignore_headers") == "1"

    # Include low-confidence by default, but disable for noisy OCR sources
    include_low = True

    text, meta = _get_text_or_canonical_text(request, b64_plain=b64_plain)
    if text is None:
        return jsonify({"error": "No input provided"}), 400

    # Heuristic: for OCR/image/pdf sources with very short text, suppress low-confidence; otherwise allow
    src = meta.get("source")
    text_len = len(text or "")
    if src in ("image", "pdf") and text_len < 50:
        eff_include_low = False
    else:
        eff_include_low = include_low

    # If pasting plain text and user asked to ignore headers, drop first line
    if meta.get("source") == "text" and ignore_headers and "\n" in text:
        text = text.split("\n", 1)[1]

    result = scan_text(
        text,
        include_low=eff_include_low,
        use_ner=use_ner,
        intl_ids=intl_ids,
        strict_email=strict_email,
        debug=debug,
        exclude_spans=meta.get('exclude_spans'),
        label_hints=meta.get('label_hints')
    )
    result["meta"] = meta
    return jsonify(result)

@app.post("/redact")
def route_redact():
    # Flags FIRST
    quick = request.form.get("quick") == "1"
    mode = request.form.get("mode", "redact")
    ip_mode = request.form.get("ip_mode", "rfc5737")
    use_ner = request.form.get("use_ner") == "1"
    intl_ids = request.form.get("intl_ids") == "1"
    strict_email = request.form.get("strict_email") == "1"
    b64_plain = request.form.get("b64_plain") == "1"
    debug = request.form.get("debug") == "1"
    ignore_headers = request.form.get("ignore_headers") == "1"

    # ---------- Table-first handling to avoid CSV tokenisation errors ----------
    uploaded = request.files.get("file")
    filename = uploaded.filename if uploaded and uploaded.filename else None
    if filename and filename.lower().endswith((".csv", ".tsv", ".xlsx", ".xls")):
        raw = uploaded.read()
        df = _read_tabular(filename, raw)

        findings_json = request.form.get("findings_json", "")
        selected_ids = request.form.getlist("selected_ids")
        findings_payload = None
        if findings_json:
            try:
                findings_payload = json.loads(findings_json)
            except Exception:
                findings_payload = None

        if findings_payload and not quick and selected_ids:
            # Apply the user's exact selections per-cell by literal pairs (mode-aware)
            df_red = _df_apply_selected_by_text(df, findings_payload, selected_ids, mode, ip_mode)
        else:
            # Quick or no payload: per-cell quick pass using _redact_cell
            def cell(v):
                return _redact_cell(
                    str(v), quick=True, mode=mode, ip_mode=ip_mode, use_ner=use_ner,
                    intl_ids=intl_ids, strict_email=strict_email, debug=debug, b64_plain=b64_plain
                ) if isinstance(v, str) else v
            df_red = df.applymap(cell)

        # Ensure personal name/location columns are fully redacted in redact mode
        df_red = _force_name_redaction(df_red, mode)
        df_red = _force_location_redaction(df_red, mode)

        # Build preview and an exact CSV/TSV blob for export to use 1:1
        preview = _preview_from_dataframe(df_red, limit=100)
        sep = _guess_sep(filename)
        red_csv = df_red.to_csv(index=False, sep=sep)

        return jsonify({"redacted": preview, "redacted_csv": red_csv})

    # ---------- Fallback to original text/canonical flow ----------
    text = request.form.get("text_input")
    meta = {"source": "text"}
    if not text:
        text, meta = _get_text_or_canonical_text(request, b64_plain=b64_plain)
    if not text:
        return jsonify({"error": "No text provided"}), 400

    findings_json = request.form.get("findings_json", "")
    findings_payload = None
    if findings_json:
        try:
            findings_payload = json.loads(findings_json)
        except Exception:
            findings_payload = None

    if quick or not findings_payload:
        findings_payload = scan_text(
            text,
            include_low=True,
            use_ner=use_ner,
            intl_ids=intl_ids,
            strict_email=strict_email,
            debug=debug,
            exclude_spans=meta.get('exclude_spans'),
            label_hints=meta.get('label_hints')
        )

    selected_ids = request.form.getlist("selected_ids")
    if quick:
        selected_ids = [f["id"] for f in findings_payload["findings"] if f["confidence"] >= 0.80]
    elif not selected_ids:
        return jsonify({"redacted": text, "note": "No findings selected; original text returned."})

    redacted_text = apply_replacements_from_findings(
        text,
        findings_payload["findings"],
        selected_ids=selected_ids,
        mode=mode,
        ip_mode=ip_mode
    )

    accepted_tokens = []
    for f in findings_payload["findings"]:
        if f["id"] in selected_ids and f["label"] in ("PotentialSecret", "API_KEY"):
            accepted_tokens.append(f["original"])
    promoted = False
    if accepted_tokens:
        promoted = promote_shapes_to_registry(accepted_tokens)

    return jsonify({
        "redacted": redacted_text,
        "selected_ids": selected_ids,
        "applied": len(selected_ids),
        "mode": mode,
        "ip_mode": ip_mode,
        "promoted": promoted
    })


@app.post("/export")
def route_export():
    # Flags FIRST
    quick = request.form.get("quick") == "1"
    mode = request.form.get("mode", "redact")
    ip_mode = request.form.get("ip_mode", "rfc5737")
    use_ner = request.form.get("use_ner") == "1"
    intl_ids = request.form.get("intl_ids") == "1"
    strict_email = request.form.get("strict_email") == "1"
    b64_plain = request.form.get("b64_plain") == "1"
    debug = request.form.get("debug") == "1"

    uploaded = request.files.get("file")
    filename = uploaded.filename if uploaded and uploaded.filename else None

    findings_json = request.form.get("findings_json", "")
    selected_ids = request.form.getlist("selected_ids")
    findings_payload = json.loads(findings_json) if findings_json else None

    # Optional exact preview/CSV passthrough; guarantees preview == export
    red_blob = request.form.get("redacted_csv") or request.form.get("redacted_blob")

    ts = int(time.time())
    if filename:
        ext = filename.lower().rsplit(".", 1)[-1]
        allowed = ('json','csv','tsv','xlsx','xls','yaml','yml','jpg','jpeg','png','tif','tiff','pdf')
        outname = f"redacted_{ts}.{ext if ext in allowed else 'txt'}"
    else:
        outname = f"redacted_{ts}.txt"
    outpath = EXPORT_DIR / outname

    if filename:
        raw = uploaded.read()
        ext = filename.lower().rsplit(".", 1)[-1]
        if ext == "json":
            data = json.loads(raw.decode("utf-8", errors="ignore"))
            red = _redact_structure(
                data, quick, mode, ip_mode, use_ner,
                intl_ids, strict_email, debug, b64_plain=b64_plain
            )
            outpath.write_text(json.dumps(red, indent=2, ensure_ascii=False), encoding="utf-8")

        elif ext in ("yaml", "yml"):
            docs = list(yaml.safe_load_all(raw.decode("utf-8", errors="ignore")))
            red_docs = [
                _redact_yaml_document(
                    d, quick, mode, ip_mode, use_ner,
                    intl_ids, strict_email, debug, b64_plain=b64_plain
                )
                for d in docs
            ]
            with open(outpath, "w", encoding="utf-8") as f:
                yaml.safe_dump_all(red_docs, f, sort_keys=False)

        elif ext in ("xlsx", "xls"):
            if red_blob:
                df_red = pd.read_csv(io.StringIO(red_blob))
                df_red = _force_name_redaction(df_red, mode)
                df_red = _force_location_redaction(df_red, mode)
                with pd.ExcelWriter(outpath, engine="openpyxl") as writer:
                    df_red.to_excel(writer, index=False)
            elif findings_payload and not quick and selected_ids:
                bio = io.BytesIO(raw)
                xl = pd.ExcelFile(bio)
                with pd.ExcelWriter(outpath, engine="openpyxl") as writer:
                    for sheet in xl.sheet_names:
                        df = xl.parse(sheet_name=sheet, dtype=str, keep_default_na=False)
                        df_red = _df_apply_selected_by_text(df, findings_payload, selected_ids, mode, ip_mode)
                        df_red = _force_name_redaction(df_red, mode)
                        df_red = _force_location_redaction(df_red, mode)
                        df_red.to_excel(writer, index=False, sheet_name=sheet)
            else:
                bio = io.BytesIO(raw)
                xl = pd.ExcelFile(bio)
                with pd.ExcelWriter(outpath, engine="openpyxl") as writer:
                    for sheet in xl.sheet_names:
                        df = xl.parse(sheet_name=sheet, dtype=str, keep_default_na=False)
                        for c in df.columns:
                            df[c] = df[c].apply(
                                lambda v: _redact_cell(
                                    str(v), quick=True, mode=mode, ip_mode=ip_mode, use_ner=use_ner,
                                    intl_ids=intl_ids, strict_email=strict_email, debug=debug, b64_plain=b64_plain
                                )
                            )
                        df = _force_name_redaction(df, mode)
                        df = _force_location_redaction(df, mode)
                        df.to_excel(writer, index=False, sheet_name=sheet)

        elif ext in ("csv", "tsv"):
            sep = _guess_sep(filename)
            if red_blob:
                # When we got the preview blob, ensure name-column fallback is also honoured
                df_red = pd.read_csv(io.StringIO(red_blob), sep=sep, dtype=str, keep_default_na=False)
                df_red = _force_name_redaction(df_red, mode)
                df_red = _force_location_redaction(df_red, mode)
                df_red.to_csv(outpath, index=False, sep=sep)
            else:
                df = _read_tabular(filename, raw)
                if findings_payload and not quick and selected_ids:
                    df_red = _df_apply_selected_by_text(df, findings_payload, selected_ids, mode, ip_mode)
                else:
                    # quick/hardened per-cell path
                    for c in df.columns:
                        df[c] = df[c].apply(
                            lambda v: _redact_cell(
                                str(v), quick=True, mode=mode, ip_mode=ip_mode, use_ner=use_ner,
                                intl_ids=intl_ids, strict_email=strict_email, debug=debug, b64_plain=b64_plain
                            )
                        )
                    df_red = df
                df_red = _force_name_redaction(df_red, mode)
                df_red = _force_location_redaction(df_red, mode)
                df_red.to_csv(outpath, index=False, sep=sep)

        elif ext in ("jpg", "jpeg", "png", "tif", "tiff"):
            # Image export with optional face and MRZ strip redaction
            from PIL import Image
            import cv2
            import numpy as np
            try:
                import pytesseract
            except Exception:
                pytesseract = None

            pil_img = Image.open(io.BytesIO(raw)).convert("RGB")

            # Build selected originals set (tokens to redact on image)
            selected_set = set()
            if findings_payload:
                sel_ids = set(selected_ids or [])
                for f in findings_payload.get("findings", []):
                    if not sel_ids or f.get("id") in sel_ids:
                        o = f.get("original")
                        if isinstance(o, str) and o.strip():
                            selected_set.add(o.strip())

            # Flags: redact faces and MRZ strip
            rf = request.form.get("redact_faces")
            rm = request.form.get("redact_mrz")
            redact_faces = (rf == "1") if rf is not None else True
            redact_mrz   = (rm == "1") if rm is not None else True

            # Prepare images for OCR and drawing
            cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
            if pytesseract is not None and selected_set:
                try:
                    rgb_for_ocr = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
                    data = pytesseract.image_to_data(rgb_for_ocr, output_type=pytesseract.Output.DICT, config="--psm 6")
                    n = len(data.get("text", []))
                    for i in range(n):
                        txt = data["text"][i]
                        try:
                            conf_list = data.get("conf", [])
                            conf = float(conf_list[i]) if i < len(conf_list) else 0.0
                        except Exception:
                            conf = 0.0
                        if conf < 60:
                            continue
                        wtxt = (txt or "").strip()
                        if not wtxt:
                            continue
                        if any(wtxt == s or wtxt in s or s in wtxt for s in selected_set):
                            x, y, w, h = int(data["left"][i]), int(data["top"][i]), int(data["width"][i]), int(data["height"][i])
                            cv2.rectangle(cv_img, (x, y), (x + w, y + h), (0, 0, 0), thickness=-1)
                except Exception:
                    pass

            # Face detection (Haar cascade)
            if redact_faces:
                try:
                    gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
                    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
                    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
                    for (x, y, w, h) in faces:
                        cv2.rectangle(cv_img, (x, y), (x + w, y + h), (0, 0, 0), thickness=-1)
                except Exception:
                    pass

            # MRZ strip (bottom 30% default)
            if redact_mrz:
                try:
                    h, w = cv_img.shape[:2]
                    y0 = int(h * 0.70)
                    cv2.rectangle(cv_img, (0, y0), (w, h), (0, 0, 0), thickness=-1)
                except Exception:
                    pass

            # Encode as PNG always for reliability
            success, enc = cv2.imencode('.png', cv_img)
            if not success or enc is None or enc.size == 0:
                altname = f"redacted_{ts}.txt"
                (EXPORT_DIR / altname).write_text("", encoding="utf-8")
                return jsonify({"download": url_for("download_file", filename=altname)})
            outname = f"redacted_{ts}.png"
            outpath = EXPORT_DIR / outname
            with open(outpath, 'wb') as f:
                f.write(enc.tobytes())

            return jsonify({"download": url_for("download_file", filename=outname)})

        else:
            # treat as plain text file
            text = raw.decode("utf-8", errors="ignore")
            if red_blob:
                redacted_text = red_blob
            elif findings_payload and not quick:
                redacted_text = apply_replacements_from_findings(
                    text, findings_payload.get("findings", []),
                    selected_ids=selected_ids, mode=mode, ip_mode=ip_mode
                )
            else:
                res = scan_text(
                    text, include_low=not quick, use_ner=use_ner,
                    intl_ids=intl_ids, strict_email=strict_email, debug=debug
                )
                sel = [f["id"] for f in res["findings"]] if not quick else [
                    f["id"] for f in res["findings"] if f["confidence"] >= 0.80
                ]
                redacted_text = apply_replacements_from_findings(
                    text, res["findings"], selected_ids=sel,
                    mode=mode, ip_mode=ip_mode
                )
            outpath.write_text(redacted_text, encoding="utf-8")

        return jsonify({"download": url_for("download_file", filename=outname)})

    else:
        # text mode (no file uploaded)
        text = request.form.get("text_input", "")
        if not text.strip() and not red_blob:
            return jsonify({"error": "Provide a file to export or text_input for plain text"}), 400

        if red_blob:
            redacted_text = red_blob
        elif findings_payload and not quick:
            redacted_text = apply_replacements_from_findings(
                text, findings_payload.get("findings", []),
                selected_ids=selected_ids, mode=mode, ip_mode=ip_mode
            )
        else:
            res = scan_text(
                text, include_low=not quick, use_ner=use_ner,
                intl_ids=intl_ids, strict_email=strict_email, debug=debug
            )
            sel = [f["id"] for f in res["findings"]] if not quick else [
                f["id"] for f in res["findings"] if f["confidence"] >= 0.80
            ]
            redacted_text = apply_replacements_from_findings(
                text, res["findings"], selected_ids=sel,
                mode=mode, ip_mode=ip_mode
            )
        outpath.write_text(redacted_text, encoding="utf-8")
        return jsonify({"download": url_for("download_file", filename=outname)})


# ---------- Base64 utilities ----------
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\n\r]+$')

def _maybe_b64_process(s: str, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug):
    if not isinstance(s, str):
        return s
    st = s.strip()
    if len(st) < 8 or len(st) % 4 != 0 or not _BASE64_RE.match(st):
        return s
    try:
        raw = base64.b64decode(st, validate=False)
        txt = raw.decode('utf-8', errors='ignore')
    except Exception:
        return s
    if not txt or sum(32 <= ord(ch) <= 126 or ch in '\n\r\t' for ch in txt) / max(1, len(txt)) < 0.85:
        return s
    res = scan_text(txt, include_low=not quick, use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email, debug=debug)
    sel = [f["id"] for f in res["findings"]] if not quick else [f["id"] for f in res["findings"] if f["confidence"]>=0.80]
    red = apply_replacements_from_findings(txt, res["findings"], selected_ids=sel, mode=mode, ip_mode=ip_mode)
    try:
        return base64.b64encode(red.encode('utf-8')).decode('utf-8')
    except Exception:
        return s

# ---------- Structure redaction helpers ----------

def _redact_cell(val, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain: bool = False):
    if b64_plain:
        maybe = _maybe_b64_process(val, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug)
        if maybe is not val:
            return maybe
    res = scan_text(val, include_low=not quick, use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email, debug=debug)
    sel = [f["id"] for f in res["findings"]] if not quick else [f["id"] for f in res["findings"] if f["confidence"]>=0.80]
    return apply_replacements_from_findings(val, res["findings"], selected_ids=sel, mode=mode, ip_mode=ip_mode)

def _get_text_or_canonical_text(req, b64_plain: bool = False):
    uploaded = req.files.get("file")
    if uploaded and uploaded.filename:
        filename = uploaded.filename.lower()
        raw = uploaded.read()
        # JSON
        if filename.endswith(".json"):
            try:
                data = json.loads(raw.decode("utf-8", errors="ignore"))
                canon = _json_to_canonical_text(data, b64_plain=b64_plain)
                meta = {"source":"json"}
                meta.update(_build_spans_for_canonical(canon, "json"))
                return canon, meta
            except Exception:
                pass
        # YAML / YML
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            try:
                docs = list(yaml.safe_load_all(raw.decode("utf-8", errors="ignore")))
                lines = []
                for idx, d in enumerate(docs, start=1):
                    prefix = f"doc{idx}"
                    lines.extend(_structure_to_canonical_lines(d, [prefix], b64_plain=b64_plain))
                canon = "\n".join(lines)
                meta = {"source":"yaml"}
                meta.update(_build_spans_for_canonical(canon, "yaml"))
                return canon, meta
            except Exception:
                pass
        # CSV / TSV
        if filename.endswith(".csv") or filename.endswith(".tsv"):
            try:
                sep = "\t" if filename.endswith(".tsv") else ","
                from io import StringIO
                text = raw.decode("utf-8", errors="ignore")
                df = pd.read_csv(StringIO(text), sep=sep, dtype=str, keep_default_na=False)
                lines = []
                for idx, row in df.iterrows():
                    for col in df.columns:
                        val = row[col] if row[col] is not None else ""
                        lines.append(f"row {idx+1}.{col}: {val}")
                canon = "\n".join(lines)
                meta = {"source":"csv"}
                meta.update(_build_spans_for_canonical(canon, "csv"))
                return canon, meta
            except Exception:
                pass
        # Excel
        if filename.endswith(".xlsx") or filename.endswith(".xls"):
            try:
                import io
                bio = io.BytesIO(raw)
                xl = pd.ExcelFile(bio)
                lines = []
                for sheet in xl.sheet_names:
                    df = xl.parse(sheet_name=sheet, dtype=str, keep_default_na=False)
                    for idx, row in df.iterrows():
                        for col in df.columns:
                            val = row[col] if row[col] is not None else ""
                            lines.append(f"{sheet}.row {idx+1}.{col}: {val}")
                canon = "\n".join(lines)
                meta = {"source":"excel"}
                meta.update(_build_spans_for_canonical(canon, "excel"))
                return canon, meta
            except Exception:
                pass
        # DOCX
        if filename.endswith(".docx"):
            try:
                import io
                bio = io.BytesIO(raw)
                try:
                    from docx import Document
                except Exception:
                    Document = None
                if Document is not None:
                    doc = Document(bio)
                    lines = []
                    for p in doc.paragraphs:
                        text = (p.text or "").replace("\r\n", "\n").replace("\r", "\n")
                        if text:
                            lines.append(text)
                    for ti, table in enumerate(getattr(doc, "tables", [])):
                        for ri, row in enumerate(table.rows):
                            for ci, cell in enumerate(row.cells):
                                txt = (cell.text or "").replace("\r\n", "\n").replace("\r", "\n")
                                lines.append(f"table{ti}.r{ri+1}c{ci+1}: {txt}")
                    canon = "\n".join(lines)
                    meta = {"source": "docx"}
                    meta.update(_build_spans_for_canonical(canon, "docx"))
                    return canon, meta
            except Exception:
                pass
        # Images (JPG/PNG/TIFF)
        if filename.endswith((".jpg", ".jpeg", ".png", ".tif", ".tiff")):
            try:
                from PIL import Image
                import io
                import pytesseract
                img = Image.open(io.BytesIO(raw))
                # Basic preprocessing: convert to RGB then grayscale for OCR
                if img.mode not in ("L", "RGB"):
                    img = img.convert("RGB")
                gray = img.convert("L")
                # Light denoise: resize up to help OCR, threshold to reduce artifacts
                try:
                    scale = 2 if max(img.size) < 1500 else 1
                    if scale > 1:
                        gray = gray.resize((gray.width * scale, gray.height * scale))
                except Exception:
                    pass
                # Try multiple OCR configurations to improve recall
                ocr_texts = []
                for cfg in ["--psm 6 -l eng", "--oem 1 --psm 6 -l eng", "--psm 4 -l eng", "--psm 7 -l eng", "--psm 11 -l eng"]:
                    try:
                        ocr_texts.append(pytesseract.image_to_string(gray, config=cfg))
                    except Exception:
                        pass
                # If still short, try cropping bottom area (likely MRZ zone on passports)
                try:
                    if sum(len(t or "") for t in ocr_texts) < 60:
                        w, h = gray.width, gray.height
                        mrz_crop = gray.crop((0, int(h*0.60), w, h))
                        for cfg in ["--psm 6 -l eng", "--psm 7 -l eng"]:
                            try:
                                ocr_texts.append(pytesseract.image_to_string(mrz_crop, config=cfg))
                            except Exception:
                                pass
                except Exception:
                    pass
                text = "\n".join([t for t in ocr_texts if t])
                text = _clean_ocr_text((text or "").strip())
                meta = {"source": "image", "ocr_len": len(text), "ocr_sample": text[:200]}
                # Always return image source; do not fall back to raw binary
                return text, meta
            except Exception:
                # Return empty OCR text but keep image source
                return "", {"source": "image", "ocr_len": 0, "ocr_sample": ""}
        # PDF (text extraction; fallback to OCR)
        if filename.endswith(".pdf"):
            try:
                import io
                import fitz  # PyMuPDF
                from PIL import Image
                import pytesseract
                doc = fitz.open(stream=raw, filetype="pdf")
                lines = []
                for page_index in range(len(doc)):
                    page = doc.load_page(page_index)
                    txt = page.get_text("text") or ""
                    txt = txt.strip()
                    if not txt:
                        # OCR fallback for this page
                        pix = page.get_pixmap(dpi=300)
                        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                        gray = img.convert("L")
                        txt = (pytesseract.image_to_string(gray) or "").strip()
                    if txt:
                        for ln in txt.splitlines():
                            lines.append(f"page {page_index+1}: {ln}")
                canon = "\n".join(lines)
                if canon:
                    meta = {"source": "pdf"}
                    meta.update(_build_spans_for_canonical(canon, "pdf"))
                    return canon, meta
            except Exception:
                pass
        # MBOX (mailbox)
        if filename.endswith(".mbox"):
            try:
                import io
                import mailbox
                from email.header import decode_header, make_header
                bio = io.BytesIO(raw)
                # mailbox.mbox expects a file path; use mailbox.mboxMessage parsing per message
                # We'll split on b"\nFrom " separators which delimit messages in mbox
                blob = bio.getvalue()
                parts = blob.split(b"\nFrom ")
                lines = []
                for i, part in enumerate(parts):
                    if not part:
                        continue
                    chunk = (b"From " + part) if i > 0 else part
                    try:
                        msg = mailbox.mboxMessage(chunk)
                    except Exception:
                        continue
                    def dh(v):
                        try:
                            return str(make_header(decode_header(v))) if v else ""
                        except Exception:
                            return str(v or "")
                    headers = {
                        "From": dh(msg.get("From")),
                        "To": dh(msg.get("To")),
                        "Cc": dh(msg.get("Cc")),
                        "Date": dh(msg.get("Date")),
                        "Subject": dh(msg.get("Subject")),
                    }
                    for k, v in headers.items():
                        if v:
                            lines.append(f"msg{i+1}.{k}: {v}")
                    # Body (prefer plain text)
                    body_texts = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type() or ""
                            if ctype.startswith("text/plain"):
                                try:
                                    body_texts.append(part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore"))
                                except Exception:
                                    pass
                    else:
                        try:
                            body_texts.append(msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore"))
                        except Exception:
                            pass
                    body = "\n".join([b.strip() for b in body_texts if b and b.strip()])
                    for ln in body.splitlines():
                        if ln.strip():
                            lines.append(f"msg{i+1}.body: {ln}")
                canon = "\n".join(lines)
                if canon:
                    meta = {"source": "mbox"}
                    meta.update(_build_spans_for_canonical(canon, "mbox"))
                    return canon, meta
            except Exception:
                pass
        # ZIP (flat canonicalization of textual members)
        if filename.endswith(".zip"):
            try:
                import io
                import zipfile
                lines = []
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        name = info.filename
                        # Avoid huge files
                        if info.file_size > 10 * 1024 * 1024:
                            lines.append(f"zip:{name}: [SKIPPED LARGE FILE]")
                            continue
                        with zf.open(info, "r") as fh:
                            data = fh.read()
                        low = name.lower()
                        if low.endswith((".txt", ".csv", ".tsv", ".json", ".yaml", ".yml")):
                            try:
                                txt = data.decode("utf-8", errors="ignore")
                                for ln in txt.splitlines():
                                    lines.append(f"zip:{name}: {ln}")
                            except Exception:
                                lines.append(f"zip:{name}: [UNREADABLE AS TEXT]")
                        else:
                            lines.append(f"zip:{name}: [UNSUPPORTED FILE TYPE]")
                canon = "\n".join(lines)
                if canon:
                    meta = {"source": "zip"}
                    meta.update(_build_spans_for_canonical(canon, "zip"))
                    return canon, meta
            except Exception:
                pass
        # Fallback to raw text
        try:
            return raw.decode("utf-8", errors="ignore"), {"source":"text"}
        except Exception:
            return None, {"source":"text"}

    text = req.form.get("text_input")
    return (text if (text and text.strip()) else None, {"source":"text"})

def _json_to_canonical_text(obj, b64_plain: bool = False):
    lines = _structure_to_canonical_lines(obj, [], b64_plain=b64_plain)
    return "\n".join(lines)

def _structure_to_canonical_lines(obj, path, b64_plain: bool = False):
    def maybe_decode(v):
        if not b64_plain or not isinstance(v, str):
            return v
        try:
            raw = base64.b64decode(v)
            txt = raw.decode('utf-8', errors='ignore')
            if txt and sum(32 <= ord(ch) <= 126 or ch in '\n\r\t' for ch in txt) / max(1, len(txt)) >= 0.85:
                return txt
        except Exception:
            pass
        return v

    lines = []
    def walk(o, p):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, p + [str(k)])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, p + [str(i)])
        else:
            leaf = "" if o is None else maybe_decode(o)
            if p:
                lines.append("{}.{}: {}".format(p[0], ".".join(p[1:]), leaf))
            else:
                lines.append(str(leaf))
    walk(obj, path[:])
    return lines

def _build_spans_for_canonical(text, source):
    exclude_spans = []
    label_hints = []
    for m in re.finditer(r"^.*?:\s", text, flags=re.MULTILINE):
        ks, ke = m.start(), m.end()
        exclude_spans.append((ks, ke))  # protect keys
        keytxt = text[ks:ke].lower()

        line_end = text.find("\n", ke)
        if line_end == -1:
            line_end = len(text)
        vs, ve = ke, line_end
        value = text[vs:ve].strip()
        if not value:
            continue

        if re.search(r"\b(city|town|location|country|region)\b", keytxt):
            label_hints.append((vs, ve, "GPE", 0.60))
        if re.search(r"\b(name|full[-_\s]?name)\b", keytxt):
            label_hints.append((vs, ve, "PERSON", 0.58))
        if re.search(r"\b(company|company_name|org|organisation|organization|employer|managedcloud)\b", keytxt):
            label_hints.append((vs, ve, "ORG", 0.58))
        if re.search(r"\b(business_service|service_id|service-code)\b", keytxt):
            label_hints.append((vs, ve, "BUSINESS_ID", 0.75))
    return {"exclude_spans": exclude_spans, "label_hints": label_hints}

def _redact_structure(obj, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain: bool = False):
    if isinstance(obj, dict):
        return {k: _redact_structure(v, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_structure(v, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain) for v in obj]
    if isinstance(obj, str):
        if b64_plain:
            maybe = _maybe_b64_process(obj, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug)
            if maybe is not obj:
                return maybe
        res = scan_text(obj, include_low=not quick, use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email, debug=debug)
        sel = [f["id"] for f in res["findings"]] if not quick else [f["id"] for f in res["findings"] if f["confidence"]>=0.80]
        return apply_replacements_from_findings(obj, res["findings"], selected_ids=sel, mode=mode, ip_mode=ip_mode)
    return obj

def _redact_yaml_document(doc, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain: bool = False):
    if not isinstance(doc, dict):
        return _redact_structure(doc, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain)

    kind = (str(doc.get("kind", "")) or "").strip()

    if kind.lower() == "secret":
        if isinstance(doc.get("stringData"), dict):
            new_sd = {}
            for k, v in doc["stringData"].items():
                new_sd[k] = _redact_structure(v, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain)
            doc["stringData"] = new_sd

        if isinstance(doc.get("data"), dict):
            new_data = {}
            for k, v in doc["data"].items():
                try:
                    decoded = base64.b64decode(str(v)).decode("utf-8", errors="ignore")
                except Exception:
                    decoded = str(v)
                red = _redact_structure(decoded, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=False)
                try:
                    reenc = base64.b64encode(red.encode("utf-8")).decode("utf-8")
                except Exception:
                    reenc = v
                new_data[k] = reenc
            doc["data"] = new_data

        for k, v in list(doc.items()):
            if k in ("data", "stringData"):
                continue
            doc[k] = _redact_structure(v, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain)
        return doc

    return _redact_structure(doc, quick, mode, ip_mode, use_ner, intl_ids, strict_email, debug, b64_plain=b64_plain)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=True)


@app.post("/reload")
def route_reload():
    ok = reload_registry("detectors.yaml", "user_detectors.yaml")
    return jsonify({"reloaded": bool(ok)})
