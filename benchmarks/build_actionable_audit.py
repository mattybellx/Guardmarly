"""
build_actionable_audit.py — Groups all audited findings by rule/CWE,
assigns concrete fix actions, and writes a single actionable report.
"""
import json
from pathlib import Path
from collections import defaultdict

INPUT = Path(__file__).parent / "audit_results" / "round1_java_audited.json"
OUTPUT = Path(__file__).parent / "audit_results" / "ACTIONABLE_FIX_LIST.md"

data = json.loads(INPUT.read_text())

# Group by rule_id
by_rule = defaultdict(list)
for f in data["findings"]:
    by_rule[f["rule"]].append(f)

# ── Fix templates per rule ──────────────────────────────────────
FIX_TEMPLATES = {
    "JV-016": {
        "title": "CWE-117 Log Injection — blind regex flags all log concatenation",
        "file": "src/ansede_static/java_analyzer.py",
        "status": "✅ FIXED 2026-07-06",
        "fix": "Added taint-source check: only flag if request.getParameter/getHeader/getCookie/etc on same line.",
        "before_count": 247,
        "after_expected": 0,
    },
    "JV-025": {
        "title": "CWE-330 Weak PRNG — flags Random/Math.random() everywhere",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "_check_weak_random()",
        "status": "⬜ NOT FIXED",
        "fix": "Add test-file suppression: skip if filepath contains 'test' or 'Test'. Also skip Math.random() unless in a method with @GetMapping/@PostMapping or security keywords (token/session/password/key).",
        "before_count": None,  # varies by run
        "after_expected": "~90% reduction",
        "lines": "L797-910",
    },
    "JV-021": {
        "title": "CWE-330 Weak PRNG — flags SecureRandom field declarations",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "_check_weak_random()",
        "status": "⬜ NOT FIXED",
        "fix": "JV-021 fires alongside JV-025 for the same line. Merge or suppress duplicate. Also skip if class is 'SecureRandom'.",
        "before_count": None,
        "after_expected": "merge with JV-025",
        "lines": "L797-910",
    },
    "JV-030": {
        "title": "CWE-89 SQL Injection — interprocedural taint false flow",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "_check_interprocedural_taint()",
        "status": "⬜ NOT FIXED",
        "fix": "JV-030 applies interprocedural taint to file I/O methods (write, writeLines, readLine). These are NOT SQL sinks. Add a sink-family check: only flag if the taint reaches an actual SQL sink (executeQuery, executeUpdate, createQuery, etc.), not generic write() calls.",
        "before_count": None,
        "after_expected": "~90% reduction",
        "lines": "search for _check_interprocedural_taint",
    },
    "JV-006": {
        "title": "CWE-79 XSS — flags out.println() to non-HTTP streams",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "_check_xss()",
        "status": "⬜ NOT FIXED",
        "fix": "JV-006 flags any out.println() or PrintWriter.write() as XSS. These are often writing to files, sockets, or logs — not HTTP responses. Add check: only flag if the PrintWriter/OutputStream is an HttpServletResponse.getWriter() or JspWriter.",
        "before_count": None,
        "after_expected": "~80% reduction",
        "lines": "search for _check_xss",
    },
    "JV-011": {
        "title": "CWE-79 XSS — same as JV-006 but different detector path",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "status": "⬜ NOT FIXED",
        "fix": "Same fix as JV-006 — only flag HTTP response writers, not file/stream writers.",
        "before_count": None,
        "after_expected": "~80% reduction",
    },
    "JV-008": {
        "title": "CWE-22 Path Traversal — flags all file move/copy operations",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "_check_path_traversal()",
        "status": "⬜ NOT FIXED",
        "fix": "JV-008 flags any Files.move/copy without checking if paths are user-controlled. Add taint-source check: only flag if source/target path comes from request.getParameter/getHeader/etc.",
        "before_count": None,
        "after_expected": "~70% reduction",
    },
    "JV-012": {
        "title": "CWE-328 Weak Hash — flags MD5 for checksums/file IDs",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "function": "search for CWE-328",
        "status": "⬜ NOT FIXED",
        "fix": "JV-012 flags MessageDigest.getInstance('MD5'). MD5 is fine for checksums/file identification. Only flag if used in security context (password hashing, token generation, signature). Add context check for 'password'/'token'/'auth' keywords nearby.",
        "before_count": None,
        "after_expected": "~60% reduction",
    },
    "JV-022": {
        "title": "CWE-327 Weak Crypto — duplicates JV-012 for same line",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "status": "⬜ NOT FIXED",
        "fix": "JV-022 fires on same line as JV-012 (both flag MD5). Merge into single finding or suppress duplicate.",
        "before_count": None,
        "after_expected": "merge with JV-012",
    },
    "JV-010": {
        "title": "CWE-79 XSS — another XSS detector variant",
        "file": "src/ansede_static/java_ast_analyzer.py",
        "status": "⬜ NOT FIXED",
        "fix": "Same as JV-006/JV-011 — only flag HTTP response writers.",
    },
    "JV-017": {
        "title": "CWE-1188 Dangerous Default — flags DEBUG=true constants",
        "file": "src/ansede_static/java_analyzer.py",
        "status": "⬜ NOT FIXED",
        "fix": "JV-017 flags `public static final boolean DEBUG = true`. This is a build configuration, not a security issue. Suppress for boolean constants named DEBUG/VERBOSE/TRACE.",
        "before_count": None,
        "after_expected": "~90% reduction",
    },
}

# ── Build actionable report ─────────────────────────────────────
lines = []
lines.append("# Actionable Fix List — Java Blind Audit Round 1")
lines.append("")
lines.append(f"**Date:** 2026-07-06 | **Repos:** 10 | **LOC:** 370,024 | **Findings audited:** {data['summary']['total']}")
lines.append("")
lines.append("## Summary")
lines.append("")
lines.append(f"| Verdict | Count | % |")
lines.append(f"|---------|-------|---|")
for v in ["TP", "FP", "LIKELY_FP", "NEEDS_REVIEW"]:
    c = data["summary"]["verdicts"].get(v, 0)
    pct = c / data["summary"]["total"] * 100
    lines.append(f"| {v} | {c} | {pct:.1f}% |")
lines.append(f"| **Total** | **{data['summary']['total']}** | |")
lines.append("")
lines.append(f"**Estimated Precision:** {data['summary']['precision_estimate']:.1f}%")
lines.append("")

# Per-rule breakdown with actions
lines.append("## Per-Rule Breakdown with Fix Actions")
lines.append("")

for rule_id in sorted(by_rule.keys()):
    findings = by_rule[rule_id]
    verdicts = defaultdict(int)
    cwes = set()
    for f in findings:
        verdicts[f["verdict"]] += 1
        cwes.add(f["cwe"])

    template = FIX_TEMPLATES.get(rule_id, {})
    title = template.get("title", f"Rule {rule_id}")
    status = template.get("status", "⬜ NOT FIXED")
    fix_file = template.get("file", "unknown")
    fix_desc = template.get("fix", "No fix template — needs manual analysis")
    function = template.get("function", "")
    fix_lines = template.get("lines", "")

    lines.append(f"### {rule_id}: {title}")
    lines.append(f"")
    lines.append(f"**Status:** {status}")
    lines.append(f"**File to edit:** `{fix_file}`")
    if function:
        lines.append(f"**Function:** `{function}`")
    if fix_lines:
        lines.append(f"**Lines:** {fix_lines}")
    lines.append(f"")
    lines.append(f"| Verdict | Count |")
    lines.append(f"|---------|-------|")
    for v in ["TP", "FP", "LIKELY_FP", "NEEDS_REVIEW"]:
        if verdicts.get(v, 0) > 0:
            lines.append(f"| {v} | {verdicts[v]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append(f"")
    lines.append(f"**CWEs flagged:** {', '.join(sorted(cwes))}")
    lines.append(f"")
    lines.append(f"**Fix:** {fix_desc}")
    lines.append(f"")
    lines.append(f"**Sample findings:**")
    for f in findings[:3]:
        lines.append(f"- `{f['file']}` L{f['line']}: {f['title'][:100]}")
        lines.append(f"  → {f['reason'][:120]}")
    lines.append("")

# Priority order
lines.append("## Priority Order (do in this sequence)")
lines.append("")
lines.append("| # | Rule | Status | File | Effort | Impact |")
lines.append("|---|------|--------|------|--------|--------|")
lines.append("| 1 | JV-016 | ✅ DONE | java_analyzer.py | 30 min | 247 FPs eliminated |")
lines.append("| 2 | JV-025 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~200 FPs eliminated |")
lines.append("| 3 | JV-021 | ⬜ TODO | java_ast_analyzer.py | 10 min | merge duplicate |")
lines.append("| 4 | JV-030 | ⬜ TODO | java_ast_analyzer.py | 30 min | ~15 FPs eliminated |")
lines.append("| 5 | JV-006/JV-011/JV-010 | ⬜ TODO | java_ast_analyzer.py | 30 min | ~10 FPs eliminated |")
lines.append("| 6 | JV-008 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~3 FPs eliminated |")
lines.append("| 7 | JV-012/JV-022 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~5 FPs eliminated |")
lines.append("| 8 | JV-017 | ⬜ TODO | java_analyzer.py | 10 min | ~1 FP eliminated |")
lines.append("")

# Silent repos that need manual check
lines.append("## Silent Repos (0 findings — manual check needed)")
lines.append("")
lines.append("These repos produced zero findings. Someone should manually verify they don't contain real vulnerabilities:")
lines.append("")
for repo_name in ["AnimatedSvgView", "Project-Euler-solutions", "BlurEffectForAndroidDesign", "Shimmer-android", "MaterialRatingBar", "PinchImageView", "RWidgetHelper", "android-testing-templates", "ExpansionPanel"]:
    lines.append(f"- [ ] `{repo_name}` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec")
lines.append("")

OUTPUT.write_text("\n".join(lines), encoding="utf-8")
print(f"Actionable fix list written to: {OUTPUT}")
print(f"Rules covered: {len(by_rule)}")
print(f"Rules with fix templates: {sum(1 for r in by_rule if r in FIX_TEMPLATES)}")
