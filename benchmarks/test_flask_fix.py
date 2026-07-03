"""Quick Flask scan to measure framework noise suppression improvement."""
from pathlib import Path
from ansede_static.python_analyzer import analyze_python, _is_framework_internal_python_path

flask_root = Path("campaign/v2_100/repos/py-flask")
if not flask_root.exists():
    print("Flask not found")
    exit(1)

total_findings = 0
suppressed = 0
files_scanned = 0
samples = []

for py_file in list(flask_root.rglob("*.py"))[:100]:
    try:
        code = py_file.read_text(encoding="utf-8", errors="replace")
        result = analyze_python(code, str(py_file))
        files_scanned += 1
        for f in result.findings:
            total_findings += 1
            conf = getattr(f, "confidence", 1.0)
            sev = f.severity.value
            is_fw = _is_framework_internal_python_path(str(py_file))
            if conf < 0.5 or sev == "low":
                suppressed += 1
            if len(samples) < 8:
                samples.append((py_file.name, sev, f.cwe or "N/A", conf, is_fw, f.title[:70]))
    except Exception:
        pass

print(f"Flask scan: {files_scanned} files, {total_findings} findings")
print(f"  Suppressed (low sev/conf): {suppressed} ({suppressed/total_findings*100:.0f}%)" if total_findings else "  No findings")
print(f"  Kept: {total_findings - suppressed}")
print()
print("Sample findings:")
for name, sev, cwe, conf, is_fw, title in samples:
    print(f"  [{sev:8}] {cwe:8} conf={conf:.2f} fw={is_fw} | {name:<30} {title}")
