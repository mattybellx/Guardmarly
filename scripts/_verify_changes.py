"""Quick verification script for the optimization plan changes."""
import sys
from pathlib import Path

print("=" * 60)
print("Optimization Plan — Verification Report")
print("=" * 60)

# Track 1: rust_parser fast_triage
print("\n[Track 1] rust_parser fast_triage API:")
try:
    from ansede_static.engine.rust_parser import fast_triage, TriageResult, HAS_RUST_CORE
    print(f"  HAS_RUST_CORE = {HAS_RUST_CORE}")
    print(f"  TriageResult  = {TriageResult.__name__}")
    print(f"  fast_triage   = {fast_triage.__name__}")
    print("  => PASS")
except Exception as e:
    print(f"  => FAIL: {e}")

# Track 1: zero-dep verifier exists
print("\n[Track 1] Zero-Dependency Verifier:")
zv = Path("scripts/verify_zero_dep.py")
if zv.exists():
    lines = len(zv.read_text().splitlines())
    print(f"  Script exists: {zv}")
    print(f"  Lines: {lines}")
    print("  => PASS")
else:
    print("  => FAIL: script not found")

# Track 2: Spring YAML rules
print("\n[Track 2] Spring Registry YAML:")
try:
    import yaml
    reg = Path("src/ansede_static/registry/spring_boot.yaml")
    data = yaml.safe_load(reg.read_text())
    total = len(data.get("rules", []))
    new_ids = [r["id"] for r in data["rules"] if "ownership" in r.get("id", "") or "authenticated-ownership" in r.get("id", "")]
    print(f"  YAML parse: OK")
    print(f"  Total rules: {total}")
    print(f"  New ownership rules: {len(new_ids)}")
    for rid in new_ids:
        r = next(r for r in data["rules"] if r["id"] == rid)
        print(f"    [{r['cwe']}] {rid}")
        print(f"          type={r['pattern_type']}, severity={r['severity']}")
    print("  => PASS")
except Exception as e:
    print(f"  => FAIL: {e}")

# Track 3: LLM triage few-shot expansion
print("\n[Track 3] LLM Triage Few-Shot Expansion:")
try:
    from ansede_static.engine.llm_triage import (
        _MAX_MEMORY_EXAMPLES, _MAX_FEW_SHOT, _DEFAULT_FEW_SHOT_TARGET,
        _get_few_shot_context, _few_shot_example_count, _load_few_shot_sidecar,
    )
    counts = _few_shot_example_count()
    print(f"  _MAX_MEMORY_EXAMPLES = {_MAX_MEMORY_EXAMPLES} (was 100)")
    print(f"  _MAX_FEW_SHOT = {_MAX_FEW_SHOT} (was 3)")
    print(f"  _DEFAULT_FEW_SHOT_TARGET = {_DEFAULT_FEW_SHOT_TARGET}")
    print(f"  Sidecar total: {counts.get('sidecar_total', 0)}")
    print(f"  Memory total: {counts.get('memory_total', 0)}")
    print(f"  Coverage: {counts.get('coverage_pct', 0)}%")
    print("  => PASS")
except Exception as e:
    print(f"  => FAIL: {e}")

# Track 4: action.yml + ci-workflow
print("\n[Track 4] CI/CD Ecosystem:")
ay = Path("action.yml")
cw = Path("ci-workflow.example.yml")
print(f"  action.yml: {'EXISTS' if ay.exists() else 'MISSING'}")
print(f"  ci-workflow.example.yml: {'EXISTS' if cw.exists() else 'MISSING'}")
if ay.exists():
    content = ay.read_text()
    has_incremental = "incremental-sha256" in content
    print(f"  incremental-sha256 input: {'YES' if has_incremental else 'MISSING'}")
print("  => PASS" if ay.exists() and cw.exists() else "  => FAIL")

# Track 6: build_exe.py
print("\n[Track 6] Standalone .exe Builder:")
be = Path("scripts/build_exe.py")
if be.exists():
    content = be.read_text()
    has_verify = "verify_build" in content
    has_pyinstaller = "_build_pyinstaller" in content
    has_skip = "--skip-lsp" in content
    print(f"  verify_build(): {'YES' if has_verify else 'MISSING'}")
    print(f"  PyInstaller fallback: {'YES' if has_pyinstaller else 'MISSING'}")
    print(f"  --skip-lsp flag: {'YES' if has_skip else 'MISSING'}")
    print("  => PASS")
else:
    print("  => FAIL: script not found")

# Overall
print("\n" + "=" * 60)
print("All checks complete.")
print("=" * 60)
