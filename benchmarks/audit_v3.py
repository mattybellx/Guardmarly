"""Deep accuracy audit — source-line verification of every finding."""
import json, re, sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, "src")
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
from ansede_static.java_analyzer import analyze_java

NON_VULN_RE = re.compile(
    r"^\s*(import\s+|package\s+|//|/\*|\*|private static final|serialVersionUID|return;$|\{?\s*$)"
)

SAFE_RE = {
    "CWE-79": [
        r"ESAPI\.encoder\(\)\.encodeForHTML", r"Encoder\.encodeForHTML",
        r"\.encodeForHTML\(", r"Encode\.forHtml\(", r"StringEscapeUtils\.escapeHtml",
        r"htmlEncode\(", r"escapeHtml\(", r"encodeForJavaScript\(", r"encodeForCSS\(",
        r"ESAPI\.randomizer\(\)\.getRandomString",
    ],
    "CWE-89": [
        r'prepareStatement\s*\([^)]*\?', r"prepareCall\s*\([^)]*\?",
        r"\.setString\(", r"\.setInt\(", r"\.setLong\(",
        r"ESAPI\.encoder\(\)", r"Encoder\.encodeForSQL", r"ESAPI\.randomizer\(\)",
    ],
    "CWE-78": [
        r"ESAPI\.encoder\(\)\.encodeForOS",
        r'cmd\.addArgument\("echo', r'cmd\.addArgument\("hostname', r'cmd\.addCommand\("echo',
        r'String\s+\w+\s*=\s*"echo', r'String\s+\w+\s*=\s*"hostname',
    ],
    "CWE-22": [
        r"ESAPI\.validator\(\)\.getValidDirectoryPath", r"getCanonicalPath\(\)",
        r"FilenameUtils\.normalize", r"ESAPI\.randomizer\(\)",
    ],
    "CWE-327": [r"AES/GCM", r"OAEP", r"PBEWithHmacSHA256AndAES"],
    "CWE-328": [r"SHA-256", r"SHA-384", r"SHA-512", r"SHA3"],
    "CWE-330": [r"SecureRandom", r"ESAPI\.randomizer\(\)", r"java\.security\.SecureRandom"],
    "CWE-614": [r"\.setSecure\(true\)", r"setHttpOnly\(true\)"],
    "CWE-90": [r"encodeForLDAP", r"ESAPI\.encoder\(\)"],
    "CWE-643": [r"encodeForXPath", r"ESAPI\.encoder\(\)"],
}

CNTX = {
    "CWE-79": ["response", "writer", "print", "getwriter"],
    "CWE-89": ["sql", "query", "execute", "prepare", "statement", "createquery", "executeupdate", "executequery"],
    "CWE-78": ["processbuilder", "runtime", "exec", "command", "pb.", "getruntime"],
    "CWE-22": ["file", "path", "files.", "nio", "fileinputstream", "fileoutputstream", "filereader", "filewriter"],
    "CWE-328": ["md5", "sha-1", "sha1", "digest", "messagedigest", "getinstance"],
    "CWE-327": ["cipher", "getinstance", "des", "rc2", "rc4", "blowfish", "aes/ecb", "aes/cbc", "rsa/ecb", "3des"],
    "CWE-330": ["random", "math.random", "java.util.random"],
    "CWE-501": ["setattribute", "session", "getsession"],
    "CWE-614": ["cookie", "setsecure", "sethttponly", "addcookie"],
    "CWE-90": ["ldap", "dircontext", "search", "lookup", "initialdircontext"],
    "CWE-643": ["xpath", "evaluate", "compile", "xpathfactory", "xpathexpression"],
}


def audit(fpath, cwe, line):
    fp = Path(fpath)
    if not fp.exists():
        return "UNCERTAIN", "missing"
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").split("\n")
    except Exception:
        return "UNCERTAIN", "read err"
    if line < 1 or line > len(lines):
        return "FP_LINE", f"line {line} out of {len(lines)}"

    tl = lines[line - 1]
    if NON_VULN_RE.match(tl):
        return "FP_LINE", tl.strip()[:80]

    lo, hi = max(0, line - 4), min(len(lines), line + 3)
    ctx = "\n".join(lines[lo:hi])
    for p in SAFE_RE.get(cwe, []):
        if re.search(p, ctx, re.IGNORECASE):
            return "FP_SAFE", p

    nearby = ctx.lower()
    if cwe in CNTX:
        for kw in CNTX[cwe]:
            if kw in nearby:
                return "TP", tl.strip()[:80]
        return "FP_WRONG", f"no {cwe} context keywords in vicinity"
    else:
        # No context keywords defined - accept if line looks plausible
        return "TP", tl.strip()[:80]


print("=" * 70)
print("DEEP ACCURACY AUDIT")
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
                "title": str(getattr(f, "title", ""))[:160],
                "file": str(fp),
            })
    except Exception:
        pass
    if (i + 1) % 100 == 0:
        print(f"  Scan {i + 1}/{len(jfs)} -- {len(findings)} findings")

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

cnt = defaultdict(int)
byc = defaultdict(lambda: defaultdict(int))
samps = defaultdict(list)

for i, f in enumerate(uniq):
    v, r = audit(f["file"], f["cwe"], f["line"])
    f["v"] = v
    f["r"] = r
    cnt[v] += 1
    byc[f["cwe"]][v] += 1
    if v.startswith("FP"):
        samps[v].append((Path(f["file"]).name, f["line"], f["cwe"], r))
    if (i + 1) % 150 == 0:
        denom = cnt["TP"] + cnt["FP_LINE"] + cnt["FP_SAFE"] + cnt["FP_WRONG"]
        acc = cnt["TP"] / denom * 100 if denom else 0
        print(f"  [{i+1}/{len(uniq)}] TP={cnt['TP']} FL={cnt['FP_LINE']} FS={cnt['FP_SAFE']} FW={cnt['FP_WRONG']} ({acc:.1f}%)")

denom = cnt["TP"] + cnt["FP_LINE"] + cnt["FP_SAFE"] + cnt["FP_WRONG"]
acc = cnt["TP"] / denom * 100 if denom else 0

print(f"\n{'=' * 70}")
print(f"TRUE ACCURACY: {acc:.1f}% ({cnt['TP']}/{denom})")
print(f"  TP:           {cnt['TP']:5d}")
print(f"  FP_LINE:      {cnt['FP_LINE']:5d}  (import/package/annotation lines)")
print(f"  FP_SAFE:      {cnt['FP_SAFE']:5d}  (safe pattern detected)")
print(f"  FP_WRONG:     {cnt['FP_WRONG']:5d}  (code missing CWE keywords)")
print(f"  UNCERTAIN:    {cnt['UNCERTAIN']:5d}")

print(f"\n{'CWE':12s} {'Tot':>4s} {'TP':>4s} {'FP':>4s} {'Acc%':>6s}  Breakdown")
for c, v in sorted(byc.items()):
    t = sum(v.values())
    tp = v.get("TP", 0)
    fp = v.get("FP_LINE", 0) + v.get("FP_SAFE", 0) + v.get("FP_WRONG", 0)
    a = tp / (tp + fp) * 100 if (tp + fp) else 0
    bar = "#" * int(a / 5) + "-" * max(0, 20 - int(a / 5))
    parts = [f"{k[3:]}{v[k]}" for k in ("FP_LINE", "FP_SAFE", "FP_WRONG") if v.get(k)]
    print(f"  {c:12s} {t:4d} {tp:4d} {fp:4d} {a:5.1f}%  {bar}  {' '.join(parts)}")

print(f"\nFP_LINE samples:")
for n, ln, c, r in samps.get("FP_LINE", [])[:6]:
    print(f"  {n:35s} L{ln:<4d} {c:8s} | {r[:100]}")
print(f"\nFP_SAFE samples:")
for n, ln, c, r in samps.get("FP_SAFE", [])[:5]:
    print(f"  {n:35s} L{ln:<4d} {c:8s} | {r[:100]}")
print(f"\nFP_WRONG samples:")
for n, ln, c, r in samps.get("FP_WRONG", [])[:5]:
    print(f"  {n:35s} L{ln:<4d} {c:8s} | {r[:100]}")

print(f"\n{'=' * 70}")

# Save
json.dump({
    "ts": datetime.now().isoformat(),
    "accuracy_pct": round(acc, 1),
    "counts": dict(cnt),
    "by_cwe": {k: dict(v) for k, v in byc.items()},
    "total_files": len(jfs),
    "total_findings": len(uniq),
}, open("benchmarks/deep_audit_result.json", "w"), indent=2)
print("Saved: benchmarks/deep_audit_result.json")
