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
# Helpers for stable table preview + selection-aligned export
# =====================================================================

def _guess_sep(filename: str) -> str:
    return "\t" if filename.lower().endswith(".tsv") else ","

def _read_tabular(filename: str, raw: bytes) -> pd.DataFrame:
    if filename.lower().endswith((".xlsx", ".xls")):
        bio = io.BytesIO(raw)
        return pd.read_excel(bio)
    else:
        sep = _guess_sep(filename)
        return pd.read_csv(io.BytesIO(raw), sep=sep)

def _preview_from_dataframe(df: pd.DataFrame, limit: int = 100) -> str:
    lines = []
    n = min(len(df), limit)
    for i in range(n):
        for col in df.columns:
            val = df.iloc[i][col]
            sval = "" if pd.isna(val) else str(val).replace("\r\n", "\n").replace("\r", "\n")
            lines.append(f"row {i+1}.{col}: {sval}")
    return "\n".join(lines)

def _redact_cell_quick(txt: str, *, mode: str, ip_mode: str,
                       use_ner: bool, intl_ids: bool, strict_email: bool) -> str:
    if not isinstance(txt, str) or not txt:
        return txt
    res = scan_text(txt, include_low=False, use_ner=use_ner,
                    intl_ids=intl_ids, strict_email=strict_email, debug=False)
    sel = [f["id"] for f in res.get("findings", []) if f.get("confidence", 1.0) >= 0.80]
    out = apply_replacements_from_findings(txt, res.get("findings", []),
                                           selected_ids=sel, mode=mode, ip_mode=ip_mode)
    # Harden EMAIL + IPv4
    email_re = re.compile(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    out = email_re.sub("[REDACTED]", out)
    out = ip_re.sub("[REDACTED]", out)
    return out

def _df_quick_redact(df: pd.DataFrame, *, mode: str, ip_mode: str,
                     use_ner: bool, intl_ids: bool, strict_email: bool) -> pd.DataFrame:
    def f(x):
        return _redact_cell_quick(x, mode=mode, ip_mode=ip_mode,
                                  use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email) \
               if isinstance(x, str) else x
    return df.applymap(f)

def _apply_selected_to_text(original_text: str, findings_payload: dict,
                            selected_ids: list, *, mode: str, ip_mode: str) -> str:
    findings = findings_payload.get("findings", [])
    return apply_replacements_from_findings(original_text, findings,
                                            selected_ids=selected_ids, mode=mode, ip_mode=ip_mode)

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
    include_low = request.form.get("include_low") == "1"

    text, meta = _get_text_or_canonical_text(request, b64_plain=b64_plain)
    if text is None:
        return jsonify({"error": "No input provided"}), 400

    result = scan_text(
        text,
        include_low=include_low,
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

    # --- Table-first handling (avoid mangling canonical lines) ---
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

        if findings_payload and not quick:
            # Apply exact selection to the CSV blob, then parse back and preview from DataFrame
            sep = _guess_sep(filename)
            orig_csv = df.to_csv(index=False, sep=sep)
            red_csv = _apply_selected_to_text(orig_csv, findings_payload, selected_ids, mode=mode, ip_mode=ip_mode)
            df_red = pd.read_csv(io.StringIO(red_csv), sep=sep)
        else:
            # Quick path: hi-confidence + harden EMAIL/IP
            df_red = _df_quick_redact(df, mode=mode, ip_mode=ip_mode,
                                      use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email)

        preview = _preview_from_dataframe(df_red, limit=100)
        # Also return a CSV string of the redacted table so Export can write it 1:1
        sep = _guess_sep(filename)
        red_csv = df_red.to_csv(index=False, sep=sep)
        return jsonify({"redacted": preview, "redacted_csv": red_csv})

    # --- Fallback to original text/canonical flow ---
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

    # Pass-through of exact redacted CSV produced by /redact (for tables)
    red_blob = request.form.get("redacted_csv") or request.form.get("redacted_blob")

    ts = int(time.time())
    if filename:
        ext = filename.lower().rsplit(".", 1)[-1]
        outname = f"redacted_{ts}.{ext if ext in ('json','csv','tsv','xlsx','xls','yaml','yml') else 'txt'}"
    else:
        outname = f"redacted_{ts}.txt"
    outpath = EXPORT_DIR / outname

    if filename:
        raw = uploaded.read()
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
            df = _read_tabular(filename, raw)
            if red_blob:
                df_red = pd.read_csv(io.StringIO(red_blob))
            elif findings_payload and not quick:
                orig_csv = df.to_csv(index=False)
                red_csv = _apply_selected_to_text(orig_csv, findings_payload, selected_ids, mode=mode, ip_mode=ip_mode)
                df_red = pd.read_csv(io.StringIO(red_csv))
            else:
                df_red = _df_quick_redact(df, mode=mode, ip_mode=ip_mode,
                                          use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email)
            with pd.ExcelWriter(outpath, engine="openpyxl") as writer:
                df_red.to_excel(writer, index=False)

        elif ext in ("csv", "tsv"):
            df = _read_tabular(filename, raw)
            sep = _guess_sep(filename)
            if red_blob:
                outpath.write_text(red_blob, encoding="utf-8")
            elif findings_payload and not quick:
                orig_csv = df.to_csv(index=False, sep=sep)
                red_csv = _apply_selected_to_text(orig_csv, findings_payload, selected_ids, mode=mode, ip_mode=ip_mode)
                outpath.write_text(red_csv, encoding="utf-8")
            else:
                df_red = _df_quick_redact(df, mode=mode, ip_mode=ip_mode,
                                          use_ner=use_ner, intl_ids=intl_ids, strict_email=strict_email)
                df_red.to_csv(outpath, index=False, sep=sep)

        else:
            # treat as plain text file
            text = raw.decode("utf-8", errors="ignore")
            if red_blob:
                redacted_text = red_blob
            elif findings_payload and not quick:
                redacted_text = _apply_selected_to_text(text, findings_payload, selected_ids, mode=mode, ip_mode=ip_mode)
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
            redacted_text = _apply_selected_to_text(text, findings_payload, selected_ids, mode=mode, ip_mode=ip_mode)
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
