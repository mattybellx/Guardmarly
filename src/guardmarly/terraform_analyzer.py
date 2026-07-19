"""guardmarly.terraform_analyzer — Terraform/HCL security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_terraform(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="terraform", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        # Open S3 bucket
        for m in re.finditer(r'aws_s3_bucket_public_access_block.*?block_public_acls\s*=\s*false', code, re.DOTALL):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Public S3 bucket", description=f"Public S3 bucket at line {line}", line=line,
                suggestion="Set block_public_acls = true.", rule_id="TF-001", cwe="CWE-284",
                agent="terraform-analyzer", confidence=0.90, analysis_kind="pattern"))
        # Open security group
        for m in re.finditer(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Open security group (0.0.0.0/0)", description=f"Open CIDR at line {line}", line=line,
                suggestion="Restrict to specific IP ranges.", rule_id="TF-002", cwe="CWE-284",
                agent="terraform-analyzer", confidence=0.90, analysis_kind="pattern"))
        # Hardcoded secrets
        for m in re.finditer(r'(?:password|secret|api_key|token)\s*=\s*"([^"]{8,})"', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use Terraform variables or a secrets manager.", rule_id="TF-003",
                cwe="CWE-798", agent="terraform-analyzer", confidence=0.75, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Terraform error: {exc}"
    return result
