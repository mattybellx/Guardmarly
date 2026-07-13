"""
ansede_static.sbom
──────────────────
Software Bill of Materials (SBOM) generator.

Parses Python requirements.txt / pyproject.toml and JavaScript package.json
files found in a workspace root and produces a CycloneDX 1.4 JSON or SPDX 2.3
JSON document.

Zero external dependencies — pure stdlib only.

Usage:
    from ansede_static.sbom import generate_sbom
    sbom_json = generate_sbom(workspace_root=Path("."), fmt="cyclonedx")

CLI integration:
    ansede-static src/ --sbom cyclonedx --sbom-output sbom.json
    ansede-static src/ --sbom spdx --sbom-output sbom.spdx.json
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Internal component model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _Component:
    name: str
    version: str
    ecosystem: str          # "pypi" | "npm"
    source_file: str        # relative path to the manifest that declared it
    purl: str = ""          # Package URL (purl spec)
    bom_ref: str = ""       # unique identifier within the SBOM document

    def __post_init__(self) -> None:
        if not self.purl:
            self.purl = _make_purl(self.name, self.version, self.ecosystem)
        if not self.bom_ref:
            self.bom_ref = f"{self.ecosystem}:{self.name}@{self.version}"


def _make_purl(name: str, version: str, ecosystem: str) -> str:
    """Build a Package URL (purl) string for a component."""
    if ecosystem == "pypi":
        norm_name = name.lower().replace("_", "-")
        if version:
            return f"pkg:pypi/{norm_name}@{version}"
        return f"pkg:pypi/{norm_name}"
    if ecosystem == "npm":
        if version:
            return f"pkg:npm/{name}@{version}"
        return f"pkg:npm/{name}"
    return f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}"


# ──────────────────────────────────────────────────────────────────────────────
# Manifest parsers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> list[_Component]:
    """Parse a requirements.txt / requirements-*.txt file."""
    components: list[_Component] = []
    rel = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return components

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Skip comments, blank lines, options, and URLs
        if not line or line.startswith(("#", "-", "http://", "https://")):
            continue
        # Strip inline comments
        line = line.split(" #")[0].strip()
        # Handle extras like requests[security]==2.28.0
        line = re.sub(r"\[.*?\]", "", line)
        # Match name and optional version specifier
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~]{1,2}\s*(.+?))?$", line)
        if not m:
            continue
        name, version = m.group(1).strip(), (m.group(2) or "").strip()
        # Normalise version: keep only the first specifier value
        version = re.split(r"[,;]", version)[0].strip().lstrip("=<>!~").strip()
        components.append(_Component(name=name, version=version, ecosystem="pypi", source_file=rel))
    return components


def _parse_pyproject_toml(path: Path) -> list[_Component]:
    """Parse [project] dependencies from a pyproject.toml (regex-only, no TOML lib)."""
    components: list[_Component] = []
    rel = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return components

    # Find the [project.dependencies] / dependencies = [...] block
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^\[project(?:\.optional-dependencies.*)?\]", stripped):
            in_deps = False
        if re.match(r"^dependencies\s*=\s*\[", stripped):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            # Extract quoted package spec
            m = re.search(r'["\']([^"\']+)["\']', stripped)
            if not m:
                continue
            spec = m.group(1).strip()
            spec = re.sub(r"\[.*?\]", "", spec)
            pm = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~]{1,2}\s*(.+?))?$", spec)
            if not pm:
                continue
            name = pm.group(1).strip()
            version = re.split(r"[,;]", (pm.group(2) or "").strip())[0].strip().lstrip("=<>!~").strip()
            components.append(_Component(name=name, version=version, ecosystem="pypi", source_file=rel))
    return components


def _parse_package_json(path: Path) -> list[_Component]:
    """Parse dependencies + devDependencies from a package.json."""
    components: list[_Component] = []
    rel = str(path)
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return components

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg_name, version_spec in data.get(section, {}).items():
            if not isinstance(version_spec, str):
                continue
            # Strip semver range operators: ^, ~, >=, <=, >, <, =
            version = re.sub(r"^[~^>=<]+", "", version_spec.strip()).split(" ")[0]
            # Skip workspace: or file: references
            if version.startswith(("workspace", "file:", "link:")):
                continue
            components.append(_Component(name=pkg_name, version=version, ecosystem="npm", source_file=rel))
    return components


# ──────────────────────────────────────────────────────────────────────────────
# Workspace scanner
# ──────────────────────────────────────────────────────────────────────────────

def _collect_components(workspace_root: Path) -> list[_Component]:
    """Walk *workspace_root* and collect components from all detected manifests."""
    components: list[_Component] = []
    seen_purls: set[str] = set()

    # Exclude noisy directories
    _SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", "dist", "build"}

    def _walk(root: Path) -> None:
        for child in sorted(root.iterdir()):
            if child.is_dir():
                if child.name in _SKIP_DIRS:
                    continue
                _walk(child)
            elif child.is_file():
                name = child.name.lower()
                if name == "requirements.txt" or re.match(r"requirements[_-][\w]+\.txt", name):
                    for comp in _parse_requirements_txt(child):
                        if comp.purl not in seen_purls:
                            seen_purls.add(comp.purl)
                            components.append(comp)
                elif name == "pyproject.toml":
                    for comp in _parse_pyproject_toml(child):
                        if comp.purl not in seen_purls:
                            seen_purls.add(comp.purl)
                            components.append(comp)
                elif name == "package.json":
                    for comp in _parse_package_json(child):
                        if comp.purl not in seen_purls:
                            seen_purls.add(comp.purl)
                            components.append(comp)

    if workspace_root.is_dir():
        _walk(workspace_root)
    return components


# ──────────────────────────────────────────────────────────────────────────────
# CycloneDX 1.4 serialiser
# ──────────────────────────────────────────────────────────────────────────────

def _to_cyclonedx(components: list[_Component], workspace_root: Path) -> dict[str, Any]:
    """Produce a CycloneDX 1.4 JSON document with NIST/OWASP compliance metadata."""
    from ansede_static.engine_version import get_engine_version

    # ── Collect compliance metadata from rules catalog ─────────────────
    cwe_list, owasp_map = _compliance_metadata()

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _iso_now(),
            "tools": [
                {
                    "vendor": "ansede",
                    "name": "ansede-static",
                    "version": get_engine_version(),
                }
            ],
            "component": {
                "type": "application",
                "name": workspace_root.name or "project",
                "version": "",
                "properties": [
                    {
                        "name": "ansede:scanner_version",
                        "value": get_engine_version(),
                    },
                    {
                        "name": "ansede:cwe_count",
                        "value": str(len(cwe_list)),
                    },
                    {
                        "name": "ansede:owasp_top10_coverage",
                        "value": f"{len(owasp_map)}/10",
                    },
                    {
                        "name": "ansede:nist_reference",
                        "value": "https://nvd.nist.gov/",
                    },
                    {
                        "name": "ansede:owasp_reference",
                        "value": "https://owasp.org/www-project-top-ten/",
                    },
                ],
            },
        },
        "components": [],
    }

    for comp in components:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": comp.bom_ref,
            "name": comp.name,
            "purl": comp.purl,
        }
        if comp.version:
            entry["version"] = comp.version
        # Minimal externalReferences to show where this dep was declared
        entry["externalReferences"] = [
            {
                "type": "distribution",
                "url": f"https://{'pypi.org/project' if comp.ecosystem == 'pypi' else 'npmjs.com/package'}/{comp.name}",
            }
        ]
        doc["components"].append(entry)  # type: ignore[attr-defined]

    return doc


# ──────────────────────────────────────────────────────────────────────────────
# SPDX 2.3 serialiser
# ──────────────────────────────────────────────────────────────────────────────

def _to_spdx(components: list[_Component], workspace_root: Path) -> dict[str, Any]:
    """Produce an SPDX 2.3 JSON document with NIST/OWASP compliance metadata."""
    from ansede_static.engine_version import get_engine_version

    cwe_list, owasp_map = _compliance_metadata()
    doc_ns = f"https://ansede.dev/sbom/{uuid.uuid4()}"
    packages: list[dict[str, Any]] = []

    for comp in components:
        spdx_id = f"SPDXRef-{comp.ecosystem}-{re.sub(r'[^A-Za-z0-9.]', '-', comp.name)}-{comp.version or 'unknown'}"
        pkg: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": comp.name,
            "downloadLocation": f"https://{'pypi.org/project' if comp.ecosystem == 'pypi' else 'npmjs.com/package'}/{comp.name}",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }
            ],
        }
        if comp.version:
            pkg["versionInfo"] = comp.version
        packages.append(pkg)

    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": _iso_now(),
            "creators": [f"Tool: ansede-static-{get_engine_version()}"],
            "licenseListVersion": "3.22",
        },
        "name": workspace_root.name or "project",
        "dataLicense": "CC0-1.0",
        "documentNamespace": doc_ns,
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg["SPDXID"],
            }
            for pkg in packages
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def generate_sbom(
    workspace_root: Path | str,
    fmt: str = "cyclonedx",
    *,
    indent: int = 2,
) -> str:
    """Generate a SBOM document for *workspace_root*.

    Parameters
    ----------
    workspace_root:
        Directory to scan for manifest files.
    fmt:
        Output format — ``"cyclonedx"`` (default) for CycloneDX 1.4 JSON or
        ``"spdx"`` for SPDX 2.3 JSON.
    indent:
        JSON indentation spaces (default 2).

    Returns
    -------
    str
        The serialised SBOM document as a JSON string.
    """
    root = Path(workspace_root)
    components = _collect_components(root)

    if fmt.lower() in ("spdx", "spdx-json"):
        doc = _to_spdx(components, root)
    else:
        doc = _to_cyclonedx(components, root)

    return json.dumps(doc, indent=indent, ensure_ascii=False)


def _iso_now() -> str:
    """Return current UTC time in ISO 8601 format without external deps."""
    import datetime
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _compliance_metadata() -> tuple[list[str], dict[str, list[str]]]:
    """Extract CWE and OWASP Top 10 coverage from the built-in rule catalog.

    Returns
    -------
    tuple[list[str], dict[str, list[str]]]
        (unique_cwe_list, owasp_to_cwe_map)
    """
    cwe_set: set[str] = set()
    owasp_map: dict[str, list[str]] = {}
    try:
        from ansede_static.rules import list_rule_contracts, _COMPLIANCE_TAG_MAP
        for contract in list_rule_contracts():
            cwe = (contract.cwe or "").strip().upper()
            if cwe and cwe.startswith("CWE-"):
                cwe_set.add(cwe)
            # Use the built-in compliance tag map for OWASP mapping
            tags = getattr(contract, "tags", ()) or ()
            for tag in tags:
                tag_norm = tag.strip()
                if tag_norm in _COMPLIANCE_TAG_MAP:
                    for owasp_cat in _COMPLIANCE_TAG_MAP[tag_norm]:
                        owasp_map.setdefault(owasp_cat, []).append(cwe if cwe else tag_norm)
        # Ensure we at least report known coverage from the tag map itself
        if not owasp_map and _COMPLIANCE_TAG_MAP:
            for tag, cats in _COMPLIANCE_TAG_MAP.items():
                for cat in cats:
                    owasp_map.setdefault(cat, []).append(tag)
    except Exception:
        pass
    return sorted(cwe_set), {k: sorted(set(v)) for k, v in owasp_map.items()}
