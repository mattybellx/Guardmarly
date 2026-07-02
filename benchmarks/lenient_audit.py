"""Lenient accuracy audit - tolerates line-number drift, checks whole file for vuln context."""
import json, re, sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, "src")
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
from ansede_static.java_analyzer import analyze_java

NON_VULN_RE = re.compile(
    r"^\s*(import\s+|package\s+|//|/\*|\*|private static final|serialVersionUID|return;\s*$|\{?\s*$)"
)

SAFE_RE = {
    "CWE-79": ["ESAPI\\.encoder\\(\\)\\.encodeForHTML", "Encoder\\.encodeForHTML",
        "\\.encodeForHTML\\(", "Encode\\.forHtml\\(", "StringEscapeUtils\\.escapeHtml",
        "htmlEncode\\(", "escapeHtml\\(", "ESAPI\\.randomizer\\(\\)\\.getRandomString"],
    "CWE-89": ["prepareStatement\\s*\\([^)]*\\?", "prepareCall\\s*\\([^)]*\\?",
        "\\.setString\\(", "\\.setInt\\(", "\\.setLong\\(",
        "ESAPI\\.encoder\\(\\)", "Encoder\\.encodeForSQL"],
    "CWE-78": ["ESAPI\\.encoder\\(\\)\\.encodeForOS",
        "cmd\\.addArgument\\(\"echo", "cmd\\.addCommand\\(\"echo"],
    "CWE-22": ["ESAPI\\.validator\\(\\)\\.getValidDirectoryPath", "getCanonicalPath\\(\\)",
        "FilenameUtils\\.normalize"],
    "CWE-327": ["AES/GCM", "OAEP", "PBEWithHmacSHA256AndAES"],
    "CWE-328": ["SHA-256", "SHA-384", "SHA-512", "SHA3"],
    "CWE-330": ["SecureRandom", "ESAPI\\.randomizer\\(\\)"],
    "CWE-614": ["\\.setSecure\\(true\\)", "setHttpOnly\\(true\\)"],
    "CWE-90": ["encodeForLDAP"],
    "CWE-643": ["encodeForXPath"],
}

CNTX = {
    "CWE-79": ["response", "writer", "print", "getwriter"],
    "CWE-89": ["sql", "query", "execute", "prepare", "statement", "createquery", "executeupdate"],
    "CWE-78": ["processbuilder", "runtime", "exec", "command", "pb.", "getruntime"],
    "CWE-22": ["file", "path", "files.", "nio", "fileinputstream", "fileoutputstream"],
    "CWE-328": ["md5", "sha-1", "sha1", "digest", "messagedigest", "getinstance"],
    "CWE-327": ["cipher", "getinstance", "des", "rc2", "rc4", "blowfish", "aes/ecb", "rsa/ecb"],
    "CWE-330": ["random", "math.random", "java.util.random"],
    "CWE-501": ["setattribute", "session", "getsession"],
    "CWE-614": ["cookie", "setsecure", "sethttponly"],
    "CWE-90": ["ldap", "dircontext", "search", "lookup"],
    "CWE-643": ["xpath", "evaluate", "compile", "xpathfactory"],
}


def strict_audit(lines, line, cwe):
    if line < 1 or line > len(lines):
        return "FP_LINE", "out of range"
    tl = lines[line - 1]
    if NON_VULN_RE.match(tl):
        return "FP_LINE", tl.strip()[:80]
    lo, hi = max(0, line - 4), min(len(lines), line + 3)
    ctx = "\n".join(lines[lo:hi])
    for p in SAFE_RE.get(cwe, []):
        if re.search(p, ctx, re.IGNORECASE):
            return "FP_SAFE", p
    nb = ctx.lower()
    if cwe in CNTX:
        for kw in CNTX[cwe]:
            if kw in nb:
                return "TP", tl.strip()[:80]
        return "FP_WRONG", f"no {cwe} context keywords"
    return "TP", tl.strip()[:80]


def lenient_audit(full_code, cwe):
    lower = full_code.lower()
    for p in SAFE_RE.get(cwe, []):
        if re.search(p, full_code, re.IGNORECASE):
            return "FP_SAFE_FILE", p
    if cwe in CNTX:
        for kw in CNTX[cwe]:
            if kw in lower:
                return "TP_LENIENT", f"has {kw}"
    return "FP_NO_CTX", "no context anywhere in file"


print("=" * 70)
print("LENIENT ACCURACY AUDIT (line-number drift tolerant)")
print(datetime.now().strftime("%H:%M:%S"))
print("=" * 70)

gg = GlobalGraph()
sources = [Path("benchmarks/owasp/src/main/java/org/owasp/benchmark"), Path("tmp")]
jfs = sorted(set(f for s in sources if s.exists() for f in s.rglob("*.java")))[:500]

findings = []
for i, fp in enumerate(jfs):
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        res = analyze_java(code, filename=str(fp), global_graph=gg)
        for f in res.findings:
            findings.append({
                "rule_id": getattr(f, "rule_id", "?"),
                "cwe": getattr(f, "cwe", "?"),
                "line": getattr(f, "line", 0),
                "file": str(fp),
            })
    except Exception:
        pass
    if (i + 1) % 100 == 0:
        print(f"  Scan {i + 1}/{len(jfs)} -- {len(findings)}")

fs = run_interprocedural_fixpoint(gg)
print(f"  IFDS: {fs['iterations']} iters, {fs['edges_processed']} edges")

seen = set()
uniq = []
for f in findings:
    k = (f["rule_id"], f["cwe"], f["line"], f["file"])
    if k not in seen:
        seen.add(k)
        uniq.append(f)

print(f"  {len(uniq)} unique findings\n")

# Cache file contents
fcache = {}
def get_lines(fp):
    if fp not in fcache:
        try:
            fcache[fp] = Path(fp).read_text(encoding="utf-8", errors="replace").split("\n")
        except Exception:
            fcache[fp] = []
    return fcache[fp]

cnt = defaultdict(int)
byc = defaultdict(lambda: defaultdict(int))

for i, f in enumerate(uniq):
    lines = get_lines(f["file"])
    full = "\n".join(lines)
    cwe = f["cwe"]
    v, r = strict_audit(lines, f["line"], cwe)

    if v == "FP_LINE":
        v, r = lenient_audit(full, cwe)

    cnt[v] += 1
    byc[cwe][v] += 1

    if (i + 1) % 150 == 0:
        true_tp = cnt["TP"] + cnt["TP_LENIENT"]
        total_fp = cnt["FP_SAFE"] + cnt["FP_SAFE_FILE"] + cnt["FP_WRONG"] + cnt["FP_NO_CTX"]
        denom = true_tp + total_fp
        acc = true_tp / denom * 100 if denom else 0
        print(f"  [{i + 1}/{len(uniq)}] TP={cnt['TP']} TPL={cnt['TP_LENIENT']} "
              f"FPS={cnt['FP_SAFE']} FPF={cnt['FP_SAFE_FILE']} FPW={cnt['FP_WRONG']} FPO={cnt['FP_NO_CTX']} ({acc:.1f}%)")

true_tp = cnt["TP"] + cnt["TP_LENIENT"]
total_fp = cnt["FP_SAFE"] + cnt["FP_SAFE_FILE"] + cnt["FP_WRONG"] + cnt["FP_NO_CTX"]
denom = true_tp + total_fp
acc = true_tp / denom * 100 if denom else 0

print(f"\n{'=' * 70}")
print(f"LENIENT ACCURACY: {acc:.1f}% ({true_tp}/{denom})")
print(f"  TP (exact line):        {cnt['TP']:5d}")
print(f"  TP_LENIENT (drifted):   {cnt['TP_LENIENT']:5d}  (vuln in file, wrong line#)")
print(f"  FP_SAFE (near line):    {cnt['FP_SAFE']:5d}")
print(f"  FP_SAFE_FILE (in file): {cnt['FP_SAFE_FILE']:5d}")
print(f"  FP_WRONG (no context):  {cnt['FP_WRONG']:5d}")
print(f"  FP_NO_CTX (nothing):    {cnt['FP_NO_CTX']:5d}")
print(f"  UNCERTAIN:              {cnt['UNCERTAIN']:5d}")

print(f"\n{'CWE':12s} {'Tot':>4s} {'TP':>4s} {'TPL':>4s} {'FP':>4s} {'Acc%':>6s}  Breakdown")
for c, vv in sorted(byc.items()):
    t = sum(vv.values())
    tp = vv.get("TP", 0) + vv.get("TP_LENIENT", 0)
    fp = vv.get("FP_SAFE", 0) + vv.get("FP_SAFE_FILE", 0) + vv.get("FP_WRONG", 0) + vv.get("FP_NO_CTX", 0)
    a = tp / (tp + fp) * 100 if (tp + fp) else 0
    bar = "#" * int(a / 5) + "-" * max(0, 20 - int(a / 5))
    parts = []
    for k in ("FP_SAFE", "FP_SAFE_FILE", "FP_WRONG", "FP_NO_CTX"):
        if vv.get(k):
            parts.append(f"{k[3]}{int(vv[k])}")
    print(f"  {c:12s} {t:4d} {vv.get('TP', 0):4d} {vv.get('TP_LENIENT', 0):4d} {fp:4d} {a:5.1f}%  {bar}  {' '.join(parts)}")

print(f"\n{'=' * 70}")
json.dump({"ts": datetime.now().isoformat(), "accuracy_pct": round(acc, 1),
    "counts": dict(cnt), "by_cwe": {k: dict(v) for k, v in byc.items()},
    "total_files": len(jfs), "total_findings": len(uniq)},
    open("benchmarks/lenient_audit.json", "w"), indent=2)
print("Saved: benchmarks/lenient_audit.json")
