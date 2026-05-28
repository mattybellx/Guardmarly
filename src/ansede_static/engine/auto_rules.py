"""
ansede_static.engine.auto_rules
───────────────────────────────
Generate heuristic audit rules from persistent LLM memory.

The output is intentionally simple:
  - ``community_rules/auto_generated/manifest.json`` keeps the canonical rule set
  - ``community_rules/auto_generated/rules.py`` is a human-readable snapshot

Rules operate on ``AuditedFinding`` records and are designed to reduce the
volume of ``NEEDS_REVIEW`` results before optional LLM triage runs.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from ansede_static.engine.audit import AuditedFinding, Verdict

_LLM_MEMORY_PATH = Path.home() / ".ansede" / "llm_memory.json"
_AUTO_RULES_DIR = Path(__file__).resolve().parents[3] / "community_rules" / "auto_generated"
_MANIFEST_PATH = _AUTO_RULES_DIR / "manifest.json"
_PYTHON_SNAPSHOT_PATH = _AUTO_RULES_DIR / "rules.py"

_MIN_ENTRIES_FOR_RULE = 5
_MIN_CONFIDENCE_FOR_RULE = 0.80
_MAX_RULES = 50


@dataclass
class AutoRule:
    """Generated heuristic rule derived from past LLM classifications."""

    rule_id: str
    cwe: str
    agent: str
    verdict: str
    confidence: float
    pattern: str | None
    file_path_pattern: str | None
    analysis_kind: str
    description: str
    source_count: int
    reasoning: str


def _normalize_cwe(cwe: str | None) -> str:
    token = (cwe or "").strip().upper()
    if not token:
        return ""
    if token.startswith("CWE-"):
        return token
    if token.isdigit():
        return f"CWE-{token}"
    return token


def _normalize_verdict(verdict: str | None) -> str:
    token = (verdict or "").strip().upper()
    mapping = {
        "TRUE_POSITIVE": "TP",
        "TP": "TP",
        "LIKELY_FALSE_POSITIVE": "LIKELY_FP",
        "LIKELY_FP": "LIKELY_FP",
        "FALSE_POSITIVE": "FP",
        "FP": "FP",
        "NEEDS_REVIEW": "NEEDS_REVIEW",
        "VENDOR_NOISE": "VENDOR_NOISE",
    }
    return mapping.get(token, token)


def load_memory() -> list[dict[str, Any]]:
    """Load persistent LLM memory from disk."""
    try:
        if _LLM_MEMORY_PATH.exists():
            with open(_LLM_MEMORY_PATH, encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return data
    except Exception:
        pass
    return []


def group_entries(entries: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group memory entries by ``(CWE, agent, verdict)``."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        cwe = _normalize_cwe(str(entry.get("cwe", "")))
        agent = str(entry.get("agent", "?")).strip() or "?"
        verdict = _normalize_verdict(str(entry.get("verdict", "")))
        key = f"{cwe}/{agent}/{verdict}"
        groups.setdefault(key, []).append(entry)
    return groups


def longest_common_subsequence(a: str, b: str) -> str:
    """Return the longest common subsequence between *a* and *b*."""
    if not a or not b:
        return ""
    n = len(a)
    m = len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n):
        for j in range(m):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i + 1][j], dp[i][j + 1])

    result: list[str] = []
    i, j = n, m
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            result.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return "".join(reversed(result))


def extract_pattern_from_snippets(snippets: list[str]) -> str | None:
    """Extract a regex-ish pattern from similar code snippets."""
    cleaned = [snippet.strip()[:200] for snippet in snippets if snippet and snippet.strip()]
    if len(cleaned) < 2:
        return None

    best = longest_common_subsequence(cleaned[0], cleaned[1])
    if len(best) < 10:
        for i in range(min(5, len(cleaned))):
            for j in range(i + 1, min(5, len(cleaned))):
                candidate = longest_common_subsequence(cleaned[i], cleaned[j])
                if len(candidate) > len(best):
                    best = candidate

    if len(best) < 10:
        return None

    pattern = re.escape(best)
    pattern = pattern.replace(r"\ ", r"\s+")
    pattern = pattern.replace(r"\n", r"\s*")
    return pattern


def extract_path_pattern(file_paths: list[str]) -> str | None:
    """Extract a shared path prefix from memory entries when available."""
    cleaned = [p.replace("\\", "/").strip().lower() for p in file_paths if p]
    if len(cleaned) < 3:
        return None

    segment_lists = [path.split("/") for path in cleaned]
    min_len = min(len(parts) for parts in segment_lists)
    common: list[str] = []
    for index in range(min_len):
        token = segment_lists[0][index]
        if token and all(parts[index] == token for parts in segment_lists):
            common.append(token)
        else:
            break
    if len(common) >= 2:
        return "/".join(common)
    return None


def generate_rule(
    cwe: str,
    agent: str,
    verdict: str,
    entries: list[dict[str, Any]],
    rule_counter: list[int],
) -> AutoRule | None:
    """Generate one ``AutoRule`` from a grouped slice of memory entries."""
    if len(entries) < _MIN_ENTRIES_FOR_RULE:
        return None

    confidences = [float(entry.get("confidence", 0.0) or 0.0) for entry in entries]
    average_confidence = sum(confidences) / len(confidences)
    if average_confidence < _MIN_CONFIDENCE_FOR_RULE:
        return None

    snippets = [str(entry.get("code_snippet", "")) for entry in entries]
    file_paths = [str(entry.get("file_path", "")) for entry in entries]
    pattern = extract_pattern_from_snippets(snippets)
    path_pattern = extract_path_pattern(file_paths)
    analysis_kind = str(entries[-1].get("analysis_kind", "pattern") or "pattern")
    reasoning = str(entries[-1].get("reasoning", "")).strip()[:200]

    rule_counter[0] += 1
    source_count = len(entries)
    description = (
        f"Auto-generated from {source_count} LLM memory entries "
        f"(avg confidence: {average_confidence:.0%}) for {cwe or '?'} in {agent}."
    )
    return AutoRule(
        rule_id=f"AUTO-{rule_counter[0]:03d}",
        cwe=cwe,
        agent=agent,
        verdict=verdict,
        confidence=average_confidence,
        pattern=pattern,
        file_path_pattern=path_pattern,
        analysis_kind=analysis_kind,
        description=description,
        source_count=source_count,
        reasoning=reasoning,
    )


def generate_rules(memory: list[dict[str, Any]] | None = None) -> list[AutoRule]:
    """Generate auto-rules from on-disk memory or an injected fixture list."""
    if memory is None:
        memory = load_memory()

    groups = group_entries(memory)
    rules: list[AutoRule] = []
    rule_counter = [0]
    for key, entries in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        if rule_counter[0] >= _MAX_RULES:
            break
        cwe, agent, verdict = key.split("/", 2)
        rule = generate_rule(cwe, agent, verdict, entries, rule_counter)
        if rule is not None:
            rules.append(rule)
    return rules


def _snapshot_python(rules: list[AutoRule]) -> str:
    lines = [
        '"""Auto-generated heuristic rules from ansede-static LLM memory."""',
        "from __future__ import annotations",
        "",
        "import re",
        "",
        f"# Total rules: {len(rules)}",
    ]
    for rule in rules:
        fn_name = f"rule_{rule.rule_id.lower().replace('-', '_')}"
        lines.extend([
            "",
            f"def {fn_name}(file_path: str, code_snippet: str, agent: str, cwe: str) -> bool:",
            f"    \"\"\"{rule.description}\"\"\"",
            f"    if agent != {rule.agent!r}:",
            "        return False",
            f"    if cwe != {rule.cwe!r}:",
            "        return False",
        ])
        if rule.file_path_pattern:
            lines.extend([
                f"    if {rule.file_path_pattern!r} in file_path.replace('\\\\', '/').lower():",
                "        return True",
            ])
        if rule.pattern:
            lines.extend([
                f"    if re.search(r{rule.pattern!r}, code_snippet):",
                "        return True",
            ])
        lines.append("    return False")
    return "\n".join(lines) + "\n"


def save_rules(rules: list[AutoRule]) -> None:
    """Persist generated rules to the auto-generated community-rules folder."""
    _AUTO_RULES_DIR.mkdir(parents=True, exist_ok=True)
    serializable = [asdict(rule) for rule in rules]
    with open(_MANIFEST_PATH, "w", encoding="utf-8") as handle:
        json.dump(serializable, handle, indent=2)
    with open(_PYTHON_SNAPSHOT_PATH, "w", encoding="utf-8") as handle:
        handle.write(_snapshot_python(rules))


def load_rules() -> list[AutoRule]:
    """Load persisted auto-rules from disk."""
    try:
        if _MANIFEST_PATH.exists():
            with open(_MANIFEST_PATH, encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, list):
                rules: list[AutoRule] = []
                for item in payload:
                    if isinstance(item, dict):
                        rules.append(AutoRule(**item))
                return rules
    except Exception:
        pass
    return []


def apply_rules_to_audit(audit_findings: list[AuditedFinding], rules: list[AutoRule]) -> list[AuditedFinding]:
    """Apply generated auto-rules to audited findings."""
    updated: list[AuditedFinding] = []
    for audited in audit_findings:
        applied = audited
        finding_agent = (audited.finding.agent or "").strip()
        finding_cwe = _normalize_cwe(audited.finding.cwe)
        file_path = audited.file_path.replace("\\", "/").lower()
        code = audited.code_snippet or ""

        for rule in rules:
            if rule.agent != finding_agent:
                continue
            if _normalize_cwe(rule.cwe) != finding_cwe:
                continue
            if rule.file_path_pattern and rule.file_path_pattern not in file_path:
                continue
            if rule.pattern:
                try:
                    if not re.search(rule.pattern, code):
                        continue
                except re.error:
                    continue

            verdict_name = _normalize_verdict(rule.verdict)
            if verdict_name == "TP":
                new_verdict = Verdict.TP
            elif verdict_name == "FP":
                new_verdict = Verdict.FP
            elif verdict_name == "VENDOR_NOISE":
                new_verdict = Verdict.VENDOR_NOISE
            elif verdict_name == "LIKELY_FP":
                new_verdict = Verdict.LIKELY_FP
            else:
                new_verdict = Verdict.NEEDS_REVIEW

            applied = AuditedFinding(
                finding=audited.finding,
                file_path=audited.file_path,
                line=audited.line,
                verdict=new_verdict,
                reasoning=f"AUTO-RULE {rule.rule_id}: {rule.description}",
                code_snippet=audited.code_snippet,
                runtime_hint=audited.runtime_hint,
            )
            break

        updated.append(applied)
    return updated