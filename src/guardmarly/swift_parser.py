"""
guardmarly.swift_parser — Swift regex-based parser.
"""
from __future__ import annotations
import re as _re
from dataclasses import dataclass, field

@dataclass
class SwCall:
    name: str; args: list[str]; line: int = 0
@dataclass
class SwFile:
    calls: list[SwCall] = field(default_factory=list)
    lines_scanned: int = 0

def parse_swift(code: str, filename: str = "") -> SwFile:
    sf = SwFile(lines_scanned=len(code.splitlines()))
    for m in _re.finditer(r'(?:(\w+)\.)?(\w+)\s*\(((?:[^()]|\([^)]*\))*)\)', code):
        name = f"{m.group(1)}.{m.group(2)}" if m.group(1) else m.group(2)
        sf.calls.append(SwCall(name=name,
            args=[a.strip() for a in m.group(3).split(',') if a.strip()],
            line=1 + code[:m.start()].count('\n')))
    return sf
