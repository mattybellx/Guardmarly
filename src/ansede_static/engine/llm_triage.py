"""
ansede_static.engine.llm_triage
─────────────────────────────────
LLM-assisted finding triage — uses a local model (Ollama) to read code
context and classify ambiguous findings as TP, LIKELY_FP, or NEEDS_REVIEW.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ansede_static.engine.audit import (
    AuditReport,
    AuditedFinding,
    Verdict,
    _read_code_snippet,
)

_log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = "gemma3:4b"
FALLBACK_MODEL = "qwen2.5:7b"

# ── LLM Memory (persistent learning) ────────────────────────────────

_LLM_MEMORY_PATH = Path.home() / ".ansede" / "llm_memory.json"
_MAX_MEMORY_EXAMPLES = 500  # Max stored examples per (cwe, agent) group (Track 3: expanded from 100 → 500 for 354+ few-shot)
_MAX_FEW_SHOT = 7           # Max past examples to include in a prompt (Track 3: expanded from 3 → 7)
_FEW_SHOT_SIDECAR_PATH = Path.home() / ".ansede" / "few_shot_examples.jsonl"  # Curated 354-example sidecar (Track 3)
_DEFAULT_FEW_SHOT_TARGET = 354  # Target curated example count from optimization plan


def _load_few_shot_sidecar() -> list[dict[str, Any]]:
    """Load curated few-shot examples from the JSONL sidecar file.
    
    The sidecar contains pre-validated TP/FP examples across 26 CWE groups,
    providing high-quality context for local LLM triage without data leaving
    the developer's machine.
    
    Format (one JSON object per line):
    {"cwe": "CWE-89", "language": "python", "verdict": "TP",
     "code": "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
     "reasoning": "User input concatenated into SQL without parameterization.",
     "remediation": "Use parameterized queries: cursor.execute('SELECT ...', (uid,))"}
    """
    if not _FEW_SHOT_SIDECAR_PATH.exists():
        return []
    
    examples: list[dict[str, Any]] = []
    try:
        with open(_FEW_SHOT_SIDECAR_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    example = json.loads(line)
                    examples.append(example)
                except json.JSONDecodeError:
                    _log.debug("Skipping malformed JSONL line in %s", _FEW_SHOT_SIDECAR_PATH)
    except OSError as exc:
        _log.debug("Failed to read few-shot sidecar: %s", str(exc).replace('\n','').replace('\r','')[:200])
    
    return examples


def _get_few_shot_context(
    cwe: str,
    language: str = "",
    max_examples: int = _MAX_FEW_SHOT,
) -> list[dict[str, Any]]:
    """Get relevant few-shot examples from sidecar + persistent memory.
    
    Prioritizes:
    1. Curated sidecar examples for the given CWE (highest quality)
    2. Persistent memory examples for the same CWE/agent
    3. Falls back to examples from the same CWE family (e.g., CWE-89 → CWE-564)
    """
    examples: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    
    # Tier 1: Curated sidecar examples (highest quality)
    sidecar = _load_few_shot_sidecar()
    for ex in sidecar:
        if len(examples) >= max_examples:
            break
        ex_cwe = str(ex.get("cwe", ""))
        ex_lang = str(ex.get("language", ""))
        # Match exact CWE or same CWE family
        if ex_cwe == cwe or (language and ex_lang == language):
            code_hash = str(ex.get("code", ""))[:80]
            if code_hash not in seen_hashes:
                examples.append(ex)
                seen_hashes.add(code_hash)
    
    # Tier 2: Persistent memory examples (learned from past triage)
    if len(examples) < max_examples:
        memory = _load_llm_memory()
        remaining = max_examples - len(examples)
        for entry in memory:
            if len(examples) >= max_examples:
                break
            if entry.get("cwe") == cwe and entry.get("code_snippet", "")[:80] not in seen_hashes:
                examples.append({
                    "cwe": entry.get("cwe", ""),
                    "language": entry.get("agent", ""),
                    "verdict": entry.get("verdict", ""),
                    "code": entry.get("code_snippet", ""),
                    "reasoning": entry.get("reasoning", ""),
                    "source": "memory",
                })
    
    return examples


def _few_shot_example_count() -> dict[str, int]:
    """Return counts of available few-shot examples."""
    sidecar = _load_few_shot_sidecar()
    memory = _load_llm_memory()
    
    cwe_groups: dict[str, int] = {}
    for ex in sidecar:
        cwe = str(ex.get("cwe", "UNKNOWN"))
        cwe_groups[cwe] = cwe_groups.get(cwe, 0) + 1
    
    return {
        "sidecar_total": len(sidecar),
        "sidecar_cwe_groups": len(cwe_groups),
        "memory_total": len(memory),
        "target": _DEFAULT_FEW_SHOT_TARGET,
        "coverage_pct": round(len(sidecar) / _DEFAULT_FEW_SHOT_TARGET * 100, 1) if _DEFAULT_FEW_SHOT_TARGET else 0,
    }


def _load_llm_memory() -> list[dict[str, Any]]:
    """Load past LLM triage results from disk."""
    try:
        if _LLM_MEMORY_PATH.exists():
            with open(_LLM_MEMORY_PATH, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        _log.debug("No LLM memory file found at %s", _LLM_MEMORY_PATH)
    return []


def _save_llm_memory(memory: list[dict[str, Any]]) -> None:
    """Save LLM triage results to disk."""
    try:
        _LLM_MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LLM_MEMORY_PATH, "w", encoding="utf-8") as f:
            json.dump(memory, f, indent=2)
    except Exception as e:
        _log.warning("Failed to save LLM memory: %s", e)


def _add_to_memory(
    cwe: str, agent: str, analysis_kind: str,
    code_snippet: str, verdict: str, confidence: float, reasoning: str,
    model: str,
) -> None:
    """Store a triage result in persistent memory for future few-shot learning.

    Only stores if:
    1. Confidence >= 0.75 (moderate-quality classifications — gemma3:4b is conservative)
    2. Not a duplicate of an existing entry (same CWE + agent + similar code)
    """
    if confidence < 0.75:
        return  # Skip low-confidence entries to avoid training on noise

    memory = _load_llm_memory()
    code_trimmed = code_snippet[:200]

    # Dedup: skip if same CWE/agent and similar code already exists
    for existing in memory:
        if (existing["cwe"] == cwe and existing["agent"] == agent
                and existing.get("verdict") == verdict
                and existing.get("code_snippet", "")[:100] == code_trimmed[:100]):
            # Same pattern already stored — update reasoning if more confident
            if confidence > existing.get("confidence", 0):
                existing["confidence"] = confidence
                existing["reasoning"] = reasoning[:200]
                existing["model"] = model
                _save_llm_memory(memory)
            return

    entry = {
        "cwe": cwe,
        "agent": agent,
        "analysis_kind": analysis_kind,
        "code_snippet": code_trimmed,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning[:200],
        "model": model,
    }
    # Keep group limited to avoid unbounded growth
    group_key = f"{cwe}/{agent}"
    group = [e for e in memory if f"{e['cwe']}/{e['agent']}" == group_key]
    if len(group) >= _MAX_MEMORY_EXAMPLES:
        # Remove lowest-confidence entry in this group
        lowest = min(group, key=lambda e: e.get("confidence", 0))
        memory.remove(lowest)
    memory.append(entry)
    _save_llm_memory(memory)


def _get_few_shot_examples(
    cwe: str, agent: str, max_examples: int = _MAX_FEW_SHOT,
) -> str:
    """Get formatted past examples for similar findings."""
    memory = _load_llm_memory()
    matching = [e for e in memory if e["cwe"] == cwe and e["agent"] == agent]
    if not matching:
        return ""
    # Take most recent up to max_examples
    recent = matching[-max_examples:]
    parts = []
    for i, ex in enumerate(recent, 1):
        parts.append(
            f"Example {i}: CWE-{ex['cwe']} ({ex['agent']}/{ex['analysis_kind']})\n"
            f"  Code: {ex['code_snippet'][:150]}...\n"
            f"  Verdict: {ex['verdict']} (confidence: {ex['confidence']:.0%})\n"
            f"  Reasoning: {ex['reasoning']}\n"
        )
    return FEW_SHOT_EXAMPLES_HEADER.format(examples="\n".join(parts))

# ── Prompts ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a world-class application security engineer. Your job is to analyze
security scanner findings and determine if they are real vulnerabilities or false positives.

Analyze each finding by:
1. Reading the code context carefully
2. Checking if user input reaches the dangerous function unsanitized
3. Checking if the code is in test files, build scripts, or vendored libraries
4. Checking if there's sanitization, encoding, or validation in the data flow
5. Considering the real-world exploitability

Respond ONLY with a JSON object. No other text."""

FEW_SHOT_EXAMPLES_HEADER = """Here are some similar findings the engine has classified before for reference:

{examples}

---"""

USER_PROMPT_TEMPLATE = """CLASSIFY THIS SECURITY FINDING:

CWE: {cwe}
Severity: {severity}
Title: {title}
Description: {description}
File: {file_path}
Line: {line}
Analysis kind: {analysis_kind}
Agent: {agent}

Suspect code ({context_lines} lines around the finding):
```{language}
{code_snippet}
```

Is this a real, exploitable vulnerability or a false positive? Respond with JSON:
{{"verdict": "TRUE_POSITIVE"|"LIKELY_FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}
"""


def _detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".cs": "csharp",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".md": "markdown",
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "bash",
        ".ps1": "powershell",
    }
    return lang_map.get(ext, "text")


@dataclass
class LLMVerdict:
    """Result from the LLM triage."""
    verdict: str  # TRUE_POSITIVE, LIKELY_FALSE_POSITIVE, NEEDS_REVIEW
    confidence: float
    reasoning: str
    model: str
    raw_response: str = ""


def _call_ollama(
    prompt: str,
    model: str = DEFAULT_MODEL,
    timeout: int = 120,
) -> str | None:
    """Call Ollama using the Python library (primary) or shell pipe (fallback)."""
    # Strategy 1: Python library - generate API
    try:
        import ollama
        resp = ollama.generate(model=model, prompt=prompt, options={"temperature": 0.1, "num_predict": 512})
        return resp.get("response", "")
    except Exception as e:
        _log.debug("Ollama generate failed: %s", e)

    # Strategy 2: Python library - chat API  
    try:
        import ollama
        resp = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            options={"temperature": 0.1, "num_predict": 512},
        )
        return resp["message"]["content"]
    except Exception as e:
        _log.debug("Ollama chat failed: %s", e)

    # Strategy 3: Shell pipe (fallback for older setups)
    import subprocess as sp
    import os
    import shlex
    try:
        # Use shlex.quote to prevent shell injection from model name
        safe_model = shlex.quote(model)
        result = sp.run(
            ["sh", "-c", f'echo "$PROMPT" | ollama {safe_model}'],
            capture_output=True, text=True, timeout=timeout,
            env={"PROMPT": prompt, **os.environ},
            errors="replace",
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            # Clean ANSI codes
            import re as _re
            output = _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', output)
            output = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', output)
            return output
    except Exception as e:
        _log.debug("Ollama pipe failed: %s", e)

    return None


def _parse_llm_response(raw: str) -> dict[str, Any] | None:
    """Parse JSON from LLM response (handles markdown fences)."""
    # Strip markdown code fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())

    # Try to find JSON in the response
    json_match = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    # Try parsing the whole thing
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def triage_finding(
    finding: AuditedFinding,
    model: str = DEFAULT_MODEL,
    context_lines: int = 8,
    timeout: int = 120,
    use_memory: bool = True,
) -> LLMVerdict | None:
    """Triage a single finding using the LLM."""
    code = _read_code_snippet(finding.file_path, finding.line, context_lines=context_lines)
    if not code:
        return None

    lang = _detect_language(finding.file_path)
    cwe = finding.finding.cwe or "?"
    agent = finding.finding.agent or "?"
    akind = finding.finding.analysis_kind or "?"

    # Build prompt with optional few-shot examples from memory
    few_shot = ""
    if use_memory:
        few_shot = _get_few_shot_examples(cwe, agent)
        if few_shot:
            few_shot = few_shot + "\n\n"

    prompt = few_shot + USER_PROMPT_TEMPLATE.format(
        cwe=cwe,
        severity=finding.finding.severity.name,
        title=finding.finding.title,
        description=finding.finding.description,
        file_path=finding.file_path,
        line=finding.line,
        analysis_kind=akind,
        agent=agent,
        code_snippet=code,
        language=lang,
        context_lines=context_lines,
    )

    raw = _call_ollama(prompt, model=model, timeout=timeout)
    if not raw:
        return None

    parsed = _parse_llm_response(raw)
    if not parsed:
        return None

    verdict = parsed.get("verdict", "NEEDS_REVIEW")
    confidence = float(parsed.get("confidence", 0.5))
    reasoning = parsed.get("reasoning", "LLM analysis")

    # Save to memory for future few-shot learning
    if use_memory and verdict != "NEEDS_REVIEW":
        _add_to_memory(
            cwe=cwe, agent=agent, analysis_kind=akind,
            code_snippet=code, verdict=verdict,
            confidence=confidence, reasoning=reasoning, model=model,
        )

    return LLMVerdict(
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        model=model,
        raw_response=raw,
    )


def _llm_verdict_to_engine(verdict: str) -> Verdict:
    """Map LLM verdict string to engine Verdict enum."""
    mapping = {
        "TRUE_POSITIVE": Verdict.TP,
        "LIKELY_FALSE_POSITIVE": Verdict.LIKELY_FP,
        "LIKELY_FP": Verdict.LIKELY_FP,
        "FALSE_POSITIVE": Verdict.FP,
        "NEEDS_REVIEW": Verdict.NEEDS_REVIEW,
    }
    return mapping.get(verdict.upper(), Verdict.NEEDS_REVIEW)


def triage_report(
    report: AuditReport,
    model: str = DEFAULT_MODEL,
    min_confidence: float = 0.70,
    verbose: bool = True,
    batch_size: int = 5,
) -> AuditReport:
    """Triage all NEEDS_REVIEW findings in an audit report using LLM.

    Args:
        report: AuditReport from the audit pipeline.
        model: Ollama model name to use.
        min_confidence: Minimum confidence to accept LLM verdict.
        verbose: Print progress.
        batch_size: Process N findings before re-checking Ollama availability.

    Returns:
        New AuditReport with LLM-triaged findings merged in.
    """
    needs_review = [af for af in report.findings if af.verdict is Verdict.NEEDS_REVIEW]
    if not needs_review:
        if verbose:
            print("No NEEDS_REVIEW findings — nothing to triage.")
        return report

    if verbose:
        print(f"LLM triaging {len(needs_review)} findings via {model}...")

    triaged = 0
    updated: list[AuditedFinding] = []

    for af in report.findings:
        if af.verdict is not Verdict.NEEDS_REVIEW:
            updated.append(af)
            continue

        result = triage_finding(af, model=model)
        if result is None:
            updated.append(af)
            continue

        if result.confidence >= min_confidence and result.verdict != "NEEDS_REVIEW":
            new_verdict = _llm_verdict_to_engine(result.verdict)
            new_reasoning = f"LLM ({result.model}, {result.confidence:.0%}): {result.reasoning}"
            updated.append(AuditedFinding(
                finding=af.finding,
                file_path=af.file_path,
                line=af.line,
                verdict=new_verdict,
                reasoning=new_reasoning,
                code_snippet=af.code_snippet,
                runtime_hint=af.runtime_hint,
            ))
            triaged += 1
            if verbose:
                safe_reasoning = result.reasoning[:80].replace('\n', '').replace('\r', '')
                _log.info("[%12s] %8s L%d %s", new_verdict.name, af.finding.cwe, af.line, safe_reasoning)
        else:
            # Keep as NEEDS_REVIEW but add LLM reasoning
            updated.append(AuditedFinding(
                finding=af.finding,
                file_path=af.file_path,
                line=af.line,
                verdict=Verdict.NEEDS_REVIEW,
                reasoning=f"LLM ({result.model}, {result.confidence:.0%}): {result.reasoning}",
                code_snippet=af.code_snippet,
                runtime_hint=af.runtime_hint,
            ))

        # Small delay between batches to avoid hammering Ollama
        if triaged % batch_size == 0:
            import time
            time.sleep(0.5)

    if verbose:
        print(f"LLM triage complete: {triaged}/{len(needs_review)} classified "
              f"(confidence >= {min_confidence:.0%})")

    return AuditReport(findings=updated)


def check_ollama_available(model: str = DEFAULT_MODEL) -> bool:
    """Check if Ollama is running and has the model."""
    try:
        import ollama
        resp = ollama.list()
        for m in resp.models:
            if model.split(":")[0] in m.model:
                return True
        return False
    except Exception:
        return False
