"""
ansede_static.v2.baseline
──────────────────────────
Baseline management for suppressing known / accepted findings (spec §6.2).

A baseline is a JSON file produced by ``ansede baseline generate`` that
records a fingerprint for every known finding.  Subsequent scans compare
new findings against the baseline and mark matches as ``suppressed=True``.

Fingerprint algorithm
─────────────────────
Each finding is fingerprinted by hashing:
    rule_id + "\x00" + file_path + "\x00" + str(line) + "\x00" + source_hash

where source_hash is a BLAKE2b-20 digest of the triggering source line
(stripped of leading/trailing whitespace).  This makes the fingerprint
stable across minor line-number drift (within a ~5-line window when the
source text is unchanged) while remaining unique enough to avoid collisions.

File format
───────────
{
  "ansede_baseline_version": 1,
  "generated_at": "<ISO-8601 UTC>",
  "findings": {
    "<fingerprint-hex>": {
      "rule_id": "...",
      "file": "...",
      "line": 42,
      "title": "..."
    }
  }
}
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

_FORMAT_VERSION = 1


def _fingerprint(rule_id: str, file_path: str, line: int, source_text: str) -> str:
    """Return a BLAKE2b-20 hex fingerprint for a finding."""
    source_hash = hashlib.blake2b(
        source_text.strip().encode("utf-8"), digest_size=20
    ).hexdigest()
    key = "\x00".join([rule_id, file_path, str(line), source_hash])
    return hashlib.blake2b(key.encode("utf-8"), digest_size=20).hexdigest()


class BaselineStore:
    """
    Persistent set of baseline fingerprints.

    Usage::

        store = BaselineStore.load(Path("baseline.json"))
        for finding in scan_results:
            if store.is_baseline_match(finding):
                finding = finding._replace(suppressed=True)

    Generating::

        store = BaselineStore.generate(findings)
        store.save(Path("baseline.json"))
    """

    def __init__(self, fingerprints: dict[str, dict]) -> None:
        self._fps: dict[str, dict] = fingerprints

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def generate(cls, findings: list) -> "BaselineStore":
        """
        Build a BaselineStore from a list of findings.

        Accepts both v1 ``Finding`` objects and v2 ``Finding`` dataclasses —
        the only required attributes are ``rule_id``, ``line``, ``title``,
        and either ``location.file_path`` (v2) or a ``file`` attribute (v1).
        """
        fps: dict[str, dict] = {}
        for f in findings:
            fp = _finding_fingerprint(f)
            if fp is None:
                continue
            fps[fp] = {
                "rule_id": getattr(f, "rule_id", ""),
                "file": _get_file(f),
                "line": _get_line(f),
                "title": getattr(f, "title", ""),
            }
        return cls(fps)

    @classmethod
    def load(cls, path: Path) -> "BaselineStore":
        """Load a baseline file.  Returns an empty store on any read error."""
        if not path.is_file():
            _log.debug("baseline: file not found at %s; returning empty store", path)
            return cls({})
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            version = data.get("ansede_baseline_version", 0)
            if version != _FORMAT_VERSION:
                _log.warning(
                    "baseline: format version %s is unsupported (expected %s); "
                    "returning empty store — run `ansede baseline generate` to regenerate.",
                    version,
                    _FORMAT_VERSION,
                )
                return cls({})
            findings_raw = data.get("findings", {})
            if not isinstance(findings_raw, dict):
                _log.warning("baseline: 'findings' key is not an object; returning empty store")
                return cls({})
            return cls(findings_raw)
        except Exception as exc:
            _log.warning("baseline: failed to load %s: %s; returning empty store", path, exc)
            return cls({})

    # ── Query ─────────────────────────────────────────────────────────────────

    def is_baseline_match(self, finding: object) -> bool:
        """Return True when *finding* matches a recorded baseline fingerprint."""
        fp = _finding_fingerprint(finding)
        return fp is not None and fp in self._fps

    def __len__(self) -> int:
        return len(self._fps)

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self._fps

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """Write the baseline to *path* as UTF-8 JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "ansede_baseline_version": _FORMAT_VERSION,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "findings": self._fps,
        }
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        _log.debug("baseline: wrote %d fingerprints to %s", len(self._fps), path)

    def merge(self, other: "BaselineStore") -> "BaselineStore":
        """Return a new BaselineStore containing fingerprints from both stores."""
        merged = {**self._fps, **other._fps}
        return BaselineStore(merged)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_file(finding: object) -> str:
    """Extract file path from either v1 or v2 Finding."""
    # v2 Finding has a .location attribute with .file_path
    loc = getattr(finding, "location", None)
    if loc is not None:
        return str(getattr(loc, "file_path", ""))
    return str(getattr(finding, "file", "") or "")


def _get_line(finding: object) -> int:
    """Extract line number from either v1 or v2 Finding."""
    loc = getattr(finding, "location", None)
    if loc is not None:
        return int(getattr(loc, "line", 0) or 0)
    return int(getattr(finding, "line", 0) or 0)


def _get_source_text(finding: object) -> str:
    """Extract triggering source text from either v1 or v2 Finding."""
    # v2 Finding: raw_text on the triggering node (via location); fall back to title
    triggering = getattr(finding, "triggering_code", None)
    if triggering:
        return str(triggering)
    # v2: message
    msg = getattr(finding, "message", None)
    if msg:
        return str(msg)
    # v1: description
    return str(getattr(finding, "description", "") or getattr(finding, "title", ""))


def _finding_fingerprint(finding: object) -> Optional[str]:
    """Compute the baseline fingerprint for *finding*, or None on error."""
    try:
        rule_id = str(getattr(finding, "rule_id", "") or "")
        file_path = _get_file(finding)
        line = _get_line(finding)
        source_text = _get_source_text(finding)
        if not rule_id:
            return None
        return _fingerprint(rule_id, file_path, line, source_text)
    except Exception as exc:
        _log.debug("baseline: fingerprint failed for %r: %s", finding, exc)
        return None
