"""Run production classifier on self-scan results."""
import json, os, sys
from dataclasses import dataclass, field

sys.path.insert(0, "src")

@dataclass
class FindingWrapper:
    """Wrap a dict finding for the Classifier."""
    line: int = 1
    triggering_code: str = ""
    cwe: str = ""
    title: str = ""
    description: str = ""
    confidence: float = 0.5
    analysis_kind: str = "pattern"
    rule_id: str = ""
    source_file: str = ""
    file_path: str = ""
    language: str = ""
    message: str = ""
    cwe_id: str = ""
    verdict: object = field(default=None)

    @staticmethod
    def from_dict(d: dict) -> "FindingWrapper":
        return FindingWrapper(
            line=d.get("line", 1),
            triggering_code=d.get("triggering_code", d.get("code", "")),
            cwe=d.get("cwe", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            confidence=d.get("confidence", 0.5),
            analysis_kind=d.get("analysis_kind", d.get("finding_class", "pattern")),
            rule_id=d.get("rule_id", ""),
            source_file=d.get("source_file", ""),
            file_path=d.get("file_path", ""),
            language=d.get("language", ""),
            message=d.get("message", ""),
            cwe_id=d.get("cwe_id", d.get("cwe", "")),
        )

f = open(os.path.join(os.environ["TEMP"], "ansede_self_scan.json"))
data = json.load(f)
f.close()

all_findings = []
for file_result in data.get("results", []):
    for f in file_result.get("findings", []):
        f["source_file"] = file_result["file"]
        f["file_path"] = file_result["file"]
        f["language"] = file_result.get("language", "")
        all_findings.append(FindingWrapper.from_dict(f))

print(f"Total raw findings: {len(all_findings)}")

from ansede_static.classifier import Classifier
c = Classifier()
results = c.classify_batch(all_findings)
print(c.summary(results))
print()
for r in results[:20]:
    f = r.finding if r.finding else r
    fid = getattr(f, "rule_id", "?")
    fname = getattr(f, "source_file", "?")
    line = getattr(f, "line", "?")
    msg = (getattr(f, "message", "") or getattr(f, "description", ""))[:100]
    print(f"  {r.verdict.value:12s} CWE-{getattr(f,'cwe_id','?') or getattr(f,'cwe','?')} {fid} @ {fname}:{line}")
    if msg:
        print(f"                  {msg}")
