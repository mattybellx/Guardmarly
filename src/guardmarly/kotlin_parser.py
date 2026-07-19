"""
guardmarly.kotlin_parser — Kotlin regex-based parser.
Fallback parser safe for environments without tree-sitter-kotlin.
"""
from __future__ import annotations
import re as _re
from dataclasses import dataclass, field

@dataclass
class KtCall:
    name: str; args: list[str]; line: int = 0

@dataclass
class KtAssign:
    target: str; value_text: str; line: int = 0

@dataclass
class KtFile:
    calls: list[KtCall] = field(default_factory=list)
    assigns: list[KtAssign] = field(default_factory=list)
    lines_scanned: int = 0


def parse_kotlin(code: str, filename: str = "") -> KtFile:
    kf = KtFile(lines_scanned=len(code.splitlines()))
    for m in _re.finditer(r'(\w+)\s*\(((?:[^()]|\([^)]*\))*)\)', code):
        kf.calls.append(KtCall(name=m.group(1),
            args=[a.strip() for a in m.group(2).split(',') if a.strip()],
            line=1 + code[:m.start()].count('\n')))
    for m in _re.finditer(r'(?:val|var)\s+(\w+)\s*=\s*(.+?)(?:\n|$)', code):
        kf.assigns.append(KtAssign(target=m.group(1), value_text=m.group(2).strip(),
                                    line=1 + code[:m.start()].count('\n')))
    return kf
