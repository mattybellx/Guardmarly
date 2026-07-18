---
name: Precision Feedback
about: Report a false positive or false negative to help improve detection accuracy
title: "[Precision]: "
labels: ["precision"]
assignees: []
---

### Type
- [ ] False Positive (guardmarly reported a finding that is not a real vulnerability)
- [ ] False Negative (guardmarly missed a real vulnerability)

### Finding details (for false positives)
- Rule ID / CWE: [e.g. CWE-89, PY-001]
- File path:
- Line number:
- Finding title:

### Code context
```python
# Paste the relevant code here (for FPs: the flagged code, for FNs: the vulnerable code guardmarly missed)
```

### Why this is a false positive / false negative
Explain your reasoning. For FPs: why is this code safe? For FNs: what CWE should have been reported?

### Environment
- guardmarly version: [`guardmarly --version`]
- Language: [Python / JavaScript / Go / Java / C#]
