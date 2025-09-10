
# --- Optional external validators ---
try:
    import phonenumbers
    HAS_PHONENUM = True
except Exception:
    HAS_PHONENUM = False

try:
    from stdnum.fi import hetu as fi_hetu
    from stdnum.fi import businessid as fi_businessid
    HAS_STDNUM_FI = True
except Exception:
    HAS_STDNUM_FI = False

import hmac, hashlib, os

_REDACTOR_SALT = os.environ.get("REDACTOR_SALT", "change-me").encode("utf-8")

def _stable_token(label: str, value: str, length: int = 22) -> str:
    digest = hmac.new(_REDACTOR_SALT, f"{label}|{value}".encode("utf-8"), hashlib.sha256).digest()
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    base = len(alphabet)
    acc = int.from_bytes(digest, "big")
    out = []
    while len(out) < length:
        out.append(alphabet[acc % base])
        acc //= base
    return "".join(out)

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in set(s):
        freq[ch] = s.count(ch)
    n = len(s)
    import math
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

import re
import logging
from typing import List, Tuple, Optional
from faker import Faker
import yaml
import random
import uuid

logger = logging.getLogger("redactor")
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

__all__ = [
    "scan_text",
    "apply_replacements_from_findings",
    "reload_registry",
    "promote_shapes_to_registry",
    "get_mask",
]

# ---------- NLP (spaCy) ----------
try:
    import spacy
    try:
        nlp = spacy.load("en_core_web_sm")
    except Exception:
        nlp = spacy.blank("en")
        if "sentencizer" not in nlp.pipe_names:
            nlp.add_pipe("sentencizer")
except Exception:
    nlp = None

# ---------- Faker ----------
fake = Faker()

# ---------- Optional international IDs ----------
try:
    from stdnum import iban as std_iban
    from stdnum import swiftbic as std_bic
    from stdnum import vat as std_vat
    HAS_STDNUM = True
except Exception:
    HAS_STDNUM = False

# ---------- Registry loading / compiling ----------
def load_registry(path: str = "detectors.yaml"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            reg = yaml.safe_load(f) or {}
    except Exception:
        reg = {}
    reg.setdefault("patterns", [])
    reg.setdefault("derived_shapes", [])
    reg.setdefault("context_hints", {})
    return reg

def _merge_registries(sys_reg: dict, user_reg: dict) -> dict:
    out = {"patterns": [], "derived_shapes": [], "context_hints": {}}
    out["patterns"] = (user_reg.get("patterns") or []) + (sys_reg.get("patterns") or [])
    out["derived_shapes"] = (user_reg.get("derived_shapes") or []) + (sys_reg.get("derived_shapes") or [])
    keys = set((sys_reg.get("context_hints") or {}).keys()) | set((user_reg.get("context_hints") or {}).keys())
    for k in keys:
        out["context_hints"][k] = []
        if k in (sys_reg.get("context_hints") or {}):
            out["context_hints"][k].extend(sys_reg["context_hints"][k] or [])
        if k in (user_reg.get("context_hints") or {}):
            out["context_hints"][k].extend(user_reg["context_hints"][k] or [])
    return out

def _atomic_write_yaml(path: str, data: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    os.replace(tmp, path)

def load_merged_registry(sys_path="detectors.yaml", user_path="user_detectors.yaml") -> dict:
    sys_reg = load_registry(sys_path)
    user_reg = load_registry(user_path)
    return _merge_registries(sys_reg, user_reg)

REGISTRY = load_merged_registry("detectors.yaml", "user_detectors.yaml")

def compile_context_hints(hints):
    out = {}
    for k, arr in (hints or {}).items():
        pats = []
        for x in arr or []:
            try:
                pats.append(re.compile(x, re.I))
            except Exception:
                pass
        out[k] = pats
    return out

def compile_extra_patterns(items):
    out = []
    for it in items or []:
        try:
            rgx = re.compile(it["regex"])
            lbl = it.get("label", "GENERIC")
            base = float(it.get("base", 0.70))
            out.append((rgx, lbl, base))
        except Exception:
            continue
    return out

COMPILED_CONTEXT_HINTS = compile_context_hints(REGISTRY.get("context_hints", {}))
COMPILED_EXTRA_PATTERNS = compile_extra_patterns(REGISTRY.get("patterns", []) + REGISTRY.get("derived_shapes", []))

def reload_registry(path: str = "detectors.yaml") -> bool:
    global REGISTRY, COMPILED_CONTEXT_HINTS, COMPILED_EXTRA_PATTERNS
    REGISTRY = load_registry(path)
    COMPILED_CONTEXT_HINTS = compile_context_hints(REGISTRY.get("context_hints", {}))
    COMPILED_EXTRA_PATTERNS = compile_extra_patterns(REGISTRY.get("patterns", []) + REGISTRY.get("derived_shapes", []))
    return True

def _token_to_shape_regex(token: str) -> Optional[str]:
    if not token or len(token) < 12:
        return None
    known_prefixes = ["sk-", "ghp_", "xoxb-", "ya29.", "AKIA", "ASIA", "AWS"]
    for p in known_prefixes:
        if token.startswith(p):
            rest_len = max(8, len(token) - len(p))
            return rf"\b{re.escape(p)}[A-Za-z0-9-_]{{{min(10, rest_len)},{rest_len+6}}}\b"
    head = re.escape(token[:3])
    rest_len = max(9, len(token) - 3)
    return rf"\b{head}[A-Za-z0-9-_]{{{min(10, rest_len)},{rest_len+6}}}\b"

def promote_shapes_to_registry(tokens: Optional[List[str]] = None, path: str = "detectors.yaml") -> int:
    global REGISTRY, COMPILED_EXTRA_PATTERNS, COMPILED_CONTEXT_HINTS
    REGISTRY = load_registry(path)
    patterns = REGISTRY.get("patterns", [])
    derived = REGISTRY.get("derived_shapes", [])

    if tokens:
        for tok in tokens:
            rx = _token_to_shape_regex(str(tok))
            if not rx:
                continue
            derived.append({"label": "PotentialSecret", "regex": rx, "base": 0.70})

    seen = {(p.get("label", "GENERIC"), p.get("regex")) for p in patterns if isinstance(p, dict)}
    added = 0
    for d in derived or []:
        if not isinstance(d, dict):
            continue
        key = (d.get("label", "GENERIC"), d.get("regex"))
        if key in seen or not key[1]:
            continue
        try:
            base = float(d.get("base", 0.70))
        except Exception:
            base = 0.70
        patterns.append({"label": key[0], "regex": key[1], "base": base})
        seen.add(key)
        added += 1

    REGISTRY["patterns"] = patterns
    COMPILED_CONTEXT_HINTS = compile_context_hints(REGISTRY.get("context_hints", {}))
    COMPILED_EXTRA_PATTERNS = compile_extra_patterns(patterns)
    logger.info(f"promote_shapes_to_registry: added {added} shape(s)")
    return added

# ---------- Context adjustments (soft; no hard block) ----------
_POSSESSIVE_AFTER = re.compile(
    r"""^(?:['’]s|\s*’s|\s*s')\s+
        (?:email|e[-_\s]*mail|api[-_\s]*key|ip(?:v4|v6)?\s*address|uuid|credit\s*card|card\s*number)
    """,
    re.IGNORECASE | re.VERBOSE
)
_LABEL_JUST_BEFORE = re.compile(
    r"""(?:email|e[-_\s]*mail|api[-_\s]*key|ip(?:v4|v6)?\s*address|uuid|credit\s*card|card\s*number)\s*$""",
    re.IGNORECASE | re.VERBOSE
)

def entity_context_adjustment(text: str, start: int, end: int) -> float:
    before = text[max(0, start-16):start]
    after  = text[end:min(len(text), end+16)]
    if _POSSESSIVE_AFTER.match(after.strip()):
        return +0.10
    if _LABEL_JUST_BEFORE.search(before.strip()):
        return -0.08
    return 0.0

# ---------- Patterns ----------
BUILTIN_PATTERNS = {
    "UUID": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-f]{12}\b".replace('A-f','A-F'),
    "IPV4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
    "IPV4_CIDR": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:[0-9]|[12][0-9]|3[0-2])\b",
    "IPV6": r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
}
EMAIL_LOCAL = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
EMAIL_DOMAIN = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
EMAIL_TLD = r"[A-Za-z]{2,63}"
EMAIL_PATTERN_STRICT = re.compile(rf"\b{EMAIL_LOCAL}@{EMAIL_DOMAIN}\.{EMAIL_TLD}\b")
EMAIL_PATTERN_LOOSE  = re.compile(rf"\b{EMAIL_LOCAL}@{EMAIL_DOMAIN}(?:\.{EMAIL_TLD})?\b")
API_KEY = re.compile(r"\bsk-[A-Za-z0-9]{8,}\b")

# ---------- Confidence ----------
def context_score(text: str, start: int, end: int) -> float:
    window = text[max(0, start-24):min(len(text), end+24)].lower()
    score = 0.0
    for name, hints in COMPILED_CONTEXT_HINTS.items():
        if name in ("EMAIL","IPV4","IPV6","UUID","CREDIT_CARD","API_KEY"):
            for h in hints:
                if h.search(window):
                    score += 0.05
    return max(0.0, min(score, 0.15))

def build_confidence(base: float, extras=None) -> float:
    total = base + sum(extras or [])
    return max(0.0, min(total, 0.99))

# ---------- Helpers ----------
def luhn_ok(digits: str) -> bool:
    s = re.sub(r"\D", "", digits or "")
    if not s:
        return False
    checksum = 0
    dbl = False
    for ch in reversed(s):
        d = ord(ch) - 48
        if dbl:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
        dbl = not dbl
    return checksum % 10 == 0

def _preview(text: str, start: int, end: int) -> str:
    return text[start:end]

# ---------- Redaction mask ----------
def get_mask(label: str) -> str:
    # Strict uniform mask for Redact mode
    return "[REDACTED]"

# ---------- Ranking / Dedupe ----------
CANONICAL_LABELS = {"EMAIL","IPV4","IPV6","UUID","CREDIT_CARD","API_KEY","INTL_IBAN","INTL_BIC","INTL_VAT","PHONE","FI_HETU","FI_BUSINESS_ID","JWT","AWS_ACCESS_KEY","AWS_SECRET_KEY","AZURE_CONN_STRING","AZURE_SAS"}

def _label_rank(label: str) -> int:
    if label in CANONICAL_LABELS:
        return 3
    if label in ("PERSON","ORG","GPE"):
        return 2
    return 1

def _dedupe_same_span(findings: list) -> list:
    best = {}
    for f in findings:
        key = (f["start"], f["end"])
        cur = best.get(key)
        if cur is None:
            best[key] = f
            continue
        r_new = (_label_rank(f["label"]), f["confidence"])
        r_old = (_label_rank(cur["label"]), cur["confidence"])
        if r_new > r_old:
            best[key] = f
    return sorted(best.values(), key=lambda x: (x["start"], x["end"]))

def _trim_possessive_span(text: str, start: int, end: int) -> tuple:
    tail = text[max(0, end-2):end]
    if tail in ("'s","’s"):
        return start, end-2
    return start, end

# ---------- Add finding ----------
def _add_finding(out_list: list, label: str, start: int, end: int, original: str, base: float,
                 text: str, reasoning=None, replacement: Optional[str]=None,
                 debug: bool=False, debug_sink: Optional[list]=None) -> None:
    conf = build_confidence(base, [context_score(text, start, end)])
    item = {
        "id": f"f-{len(out_list)+1:04d}",
        "label": label,
        "confidence": round(conf, 3),
        "start": start,
        "end": end,
        "preview": _preview(text, start, end),
        "reasoning": reasoning or [],
        "replacement": replacement or get_mask(label),
        "original": original
    }
    out_list.append(item)
    if debug and debug_sink is not None:
        debug_sink.append({
            "event": "add",
            "label": label,
            "start": start,
            "end": end,
            "original": original,
            "confidence": round(conf, 3),
            "reasoning": reasoning or [],
        })

def _remove_overlaps(preferred: List[dict], others: List[dict]) -> List[dict]:
    cleaned = []
    for o in others:
        if not any(not (o["end"] <= p["start"] or o["start"] >= p["end"]) for p in preferred):
            cleaned.append(o)
    return preferred + cleaned

# ---------- Scan ----------
def scan_text(text: str,
              include_low: bool = False,
              use_ner: bool = True,
              intl_ids: bool = False,
              extra_patterns: bool = True,
              strict_email: bool = True,
              debug: bool = False,
              exclude_spans: Optional[List[Tuple[int,int]]] = None,
              label_hints: Optional[List[Tuple[int,int,str,float]]] = None) -> dict:
    dbg = [] if debug else None
    det: List[dict] = []
    ml: List[dict] = []
    disc: List[dict] = []

    # Emails
    email_pat = EMAIL_PATTERN_STRICT if strict_email else EMAIL_PATTERN_LOOSE
    for m in email_pat.finditer(text):
        _add_finding(det, "EMAIL", m.start(), m.end(), m.group(0),
                     base=0.72 if strict_email else 0.66, text=text,
                     reasoning=["email_regex"], debug=debug, debug_sink=dbg)

    # API keys
    for m in API_KEY.finditer(text):
        _add_finding(det, "API_KEY", m.start(), m.end(), m.group(0),
                     base=0.80, text=text, reasoning=["api_key_regex"], debug=debug, debug_sink=dbg)

    # Built-ins
    for name, pat in BUILTIN_PATTERNS.items():
        for m in re.finditer(pat, text, flags=re.IGNORECASE if name == "IPV6" else 0):
            base = 0.7 if name in ("IPV4","IPV6") else 0.65
            reason = ["regex_match"]
            if name == "CREDIT_CARD":
                base = 0.6 + (0.2 if luhn_ok(m.group(0)) else -0.2)
                reason.append("luhn_" + ("pass" if luhn_ok(m.group(0)) else "fail"))
            _add_finding(det, name, m.start(), m.end(), m.group(0), base=base,
                         text=text, reasoning=reason, debug=debug, debug_sink=dbg)

    # Extra patterns
    if extra_patterns:
        for rgx, lbl, base in COMPILED_EXTRA_PATTERNS:
            for m in rgx.finditer(text):
                _add_finding(det, lbl, m.start(), m.end(), m.group(0),
                             base=base, text=text, reasoning=["registry_pattern"], debug=debug, debug_sink=dbg)

    # Intl IDs
    if intl_ids and HAS_STDNUM:
        for m in re.finditer(r"[A-Z]{2}[0-9A-Z]{13,34}", text):
            if std_iban.is_valid(m.group(0).replace(" ", "")):
                _add_finding(det, "INTL_IBAN", m.start(), m.end(), m.group(0),
                             base=0.8, text=text, reasoning=["stdnum_iban_valid"],
                             debug=debug, debug_sink=dbg)
        for m in re.finditer(r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?", text):
            if std_bic.is_valid(m.group(0)):
                _add_finding(det, "INTL_BIC", m.start(), m.end(), m.group(0),
                             base=0.8, text=text, reasoning=["stdnum_bic_valid"],
                             debug=debug, debug_sink=dbg)
        for m in re.finditer(r"[A-Z]{2}[A-Z0-9]{6,14}", text):
            if std_vat.is_valid(m.group(0)):
                _add_finding(det, "INTL_VAT", m.start(), m.end(), m.group(0),
                             base=0.7, text=text, reasoning=["stdnum_vat_valid"],
                             debug=debug, debug_sink=dbg)

    
    # IPv4 CIDR subnets
    for m in re.finditer(BUILTIN_PATTERNS["IPV4_CIDR"], text):
        _add_finding(det, "IPV4_CIDR", m.start(), m.end(), m.group(0),
                     base=0.95, text=text,
                     reasoning=["regex_match:cidr"], debug=debug, debug_sink=dbg)

    # Business service codes like CIN12345678
    for m in re.finditer(r"\bCIN\d{6,}\b", text):
        _add_finding(det, "BUSINESS_ID", m.start(), m.end(), m.group(0),
                     base=0.80, text=text,
                     reasoning=["regex_match:CIN"], debug=debug, debug_sink=dbg)

    # NER
    if use_ner and nlp is not None:
        doc = nlp(text)
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG", "GPE"):
                if ent.label_ == "ORG" and ent.text.strip().upper() in {"IP","API","UUID"}:
                    continue
                s, e = _trim_possessive_span(text, ent.start_char, ent.end_char)
                adj = entity_context_adjustment(text, s, e)
                _add_finding(ml, ent.label_, s, e, text[s:e],
                             base=0.58 + adj, text=text,
                             reasoning=["spacy_ner", f"ctx_adj:{adj:+.2f}"],
                             debug=debug, debug_sink=dbg)

    # Label hints (forced adds)
    if label_hints:
        for hs, he, hlabel, hbase in label_hints:
            try:
                base = float(hbase)
            except Exception:
                base = 0.58
            _add_finding(disc, hlabel, int(hs), int(he), text[int(hs):int(he)],
                         base=base, text=text, reasoning=["label_hint"], debug=debug, debug_sink=dbg)

    # De-overlap: prefer det over ml; prefer det+ml over disc
    ml = _remove_overlaps(det, ml)
    disc = _remove_overlaps(det + ml, disc)
    findings = det + ml + disc

    # Exact-span dedupe to avoid duplicate replacements
    findings = _dedupe_same_span(findings)

    # Exclude key/header spans
    if exclude_spans:
        kept = []
        for f in findings:
            inside = False
            for (xs, xe) in exclude_spans:
                if f["start"] >= xs and f["end"] <= xe:
                    inside = True
                    if debug and dbg is not None:
                        dbg.append({
                            "event": "skip",
                            "label": f["label"],
                            "start": f["start"],
                            "end": f["end"],
                            "original": f.get("original", ""),
                            "reasoning": ["in_excluded_span"],
                        })
                    break
            if not inside:
                kept.append(f)
        findings = kept

    if not include_low:
        findings = [f for f in findings if f["confidence"] >= 0.55]

    return {
        "summary": {
            "total": len(findings),
            "high_confidence": sum(1 for f in findings if f["confidence"] >= 0.80),
            "medium_confidence": sum(1 for f in findings if 0.55 <= f["confidence"] < 0.80),
            "low_confidence": sum(1 for f in findings if f["confidence"] < 0.55),
        },
        "findings": findings,
        "debug": (dbg or []),
    }

# ---------- Pseudonymisation & Replacement ----------
def _format_cc(num: str) -> str:
    s = re.sub(r"\D", "", num)
    return " ".join([s[i:i+4] for i in range(0, len(s), 4)])

def _rand_base62(n: int = 28) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    rng = random.Random(1337)
    return "".join(rng.choice(alphabet) for _ in range(n))

def _pseudonymise_value(label: str, original: str, ip_mode: str = "rfc5737") -> str:
    fk = Faker()
    if label == "EMAIL":
        return f"user+{_stable_token(label, original, 10)}@example.test"
    if label == "IPV4":
        # Use selected IPv4 pseudonymisation space
        if ip_mode == "linklocal":
            # 169.254.0.0/16 (avoid .0 and .255 endings)
            a = 169; b = 254; c = random.randint(0, 255); d = random.randint(1, 254)
            return f"{a}.{b}.{c}.{d}"
        # Default to documentation ranges (TEST-NET-1/2/3)
        base = random.choice(["192.0.2.", "198.51.100.", "203.0.113."])
        return f"{base}{random.randint(1,254)}"
    if label == "IPV6":
        return fk.ipv6()
    if label == "PHONE":
        return "+358" + _stable_token(label, original, 8)
    if label in ("FI_HETU","FI_BUSINESS_ID"):
        return "[REDACTED]"
    if label == "UUID":
        return str(uuid.uuid4())
    if label == "PERSON":
        return "Person_" + _stable_token(label, original, 8)
    if label in ("API_KEY","GENERIC_TOKEN","DERIVED_KEY","PotentialSecret","AWS_SECRET_KEY"):
        return "redact-" + _stable_token(label, original, 28)
    if label == "CREDIT_CARD":
        try:
            num = fk.credit_card_number()
        except Exception:
            num = "4111111111111111"
        return _format_cc(num)
    if label == "API_KEY" or label in ("GENERIC_TOKEN","DERIVED_KEY","PotentialSecret"):
        return "redact-" + _rand_base62(28)
    if label == "PERSON":
        return fk.name()
    if label == "IPV4_CIDR":
        try:
            ip, mask = original.split("/")
            mask = int(mask)
        except Exception:
            return "198.51.100.0/24"
        if ip_mode == "linklocal":
            # Map to link-local network with preserved mask
            return f"169.254.0.0/{mask if 0 <= mask <= 32 else 24}"
        # map to a documentation /mask on TEST-NET-2
        return f"198.51.100.0/{mask if 0 <= mask <= 32 else 24}"
    if label == "BUSINESS_ID":
        # preserve CIN prefix and digit count
        import re as _re
        m = _re.match(r"(CIN)(\d+)", original)
        if not m:
            return "CIN00000000"
        prefix, digits = m.groups()
        return prefix + "".join(str(random.randint(0,9)) for _ in range(len(digits)))
    if label == "ORG":
        return fk.company()
    if label == "GPE":
        return fk.city()
    return "[REDACTED]"

def _apply_mode_replacement(label: str, original: str, mode: str, cache: dict, ip_mode: str = "rfc5737") -> str:
    key = (label, original)
    if mode == "pass":
        return original
    if mode == "redact":
        return get_mask(label)  # uniform "[REDACTED]"
    # pseudonymise
    if key not in cache:
        cache[key] = _pseudonymise_value(label, original, ip_mode=ip_mode)
    return cache[key]

def apply_replacements_from_findings(text: str, findings: List[dict], selected_ids: Optional[List[str]] = None,
                                     mode: str = "redact", ip_mode: str = "rfc5737") -> str:
    chosen = findings if selected_ids is None else [f for f in findings if f["id"] in set(selected_ids)]
    cache = {}
    for f in sorted(chosen, key=lambda x: x["start"], reverse=True):
        orig = text[f["start"]:f["end"]]
        repl = _apply_mode_replacement(f["label"], orig, mode, cache, ip_mode=ip_mode)
        text = text[:f["start"]] + repl + text[f["end"]:]
    return text
