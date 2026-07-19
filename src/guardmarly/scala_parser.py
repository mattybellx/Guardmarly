"""guardmarly.scala_parser — Scala regex parser."""
from __future__ import annotations
import re as _re
from dataclasses import dataclass, field

@dataclass
class ScCall:
    name: str; args: list[str]; line: int = 0
@dataclass
class ScFile:
    calls: list[ScCall] = field(default_factory=list)
    lines_scanned: int = 0

def parse_scala(code: str, filename: str = "") -> ScFile:
    sf = ScFile(lines_scanned=len(code.splitlines()))
    for m in _re.finditer(r'(\w+(?:\.\w+)?)\s*\(((?:[^()]|\([^)]*\))*)\)', code):
        sf.calls.append(ScCall(name=m.group(1),
            args=[a.strip() for a in m.group(2).split(',') if a.strip()],
            line=1 + code[:m.start()].count('\n')))
    return sf
