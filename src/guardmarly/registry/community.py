"""Community rule registry management for guardmarly."""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from guardmarly.config import _normalized_rule_token, load_config
from guardmarly.yaml_rules import (
    CustomRule,
    default_community_rules_dir,
    load_community_rule_text,
    load_community_rules,
)


DEFAULT_REGISTRY_URL = (
    "https://raw.githubusercontent.com/mattybellx/Guardmarly/master/community_rules/index.json"
)


class RegistryError(RuntimeError):
    """Base class for registry failures."""


class NoCommunityRulesCachedError(RegistryError):
    """Raised when offline fetch is requested with an empty rule cache."""


@dataclass(frozen=True)
class RegistryFetchSummary:
    fetched: int
    skipped: int
    warnings: tuple[str, ...] = field(default_factory=tuple)


def community_rules_dir(path: str | Path | None = None) -> Path:
    """Return the install directory for community rules."""
    return Path(path) if path is not None else default_community_rules_dir()


def _installed_rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return [
        path
        for path in sorted(directory.iterdir())
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}
    ]


def _rule_filename(rule_id: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in rule_id)
    return f"{safe}.yaml"


def _download_text(url: str, *, timeout: float = 10.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def list_installed_community_rules(directory: str | Path | None = None) -> list[CustomRule]:
    """Return every successfully loaded installed community rule."""
    return load_community_rules(community_rules_dir(directory))


def fetch_registry_rules(
    *,
    registry_url: str = DEFAULT_REGISTRY_URL,
    install_dir: str | Path | None = None,
    offline: bool = False,
) -> RegistryFetchSummary:
    """Fetch community rules from a registry index into the local cache."""
    target_dir = community_rules_dir(install_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    if offline:
        cached = _installed_rule_files(target_dir)
        if not cached:
            raise NoCommunityRulesCachedError(
                "No community rules cached. Run 'guardmarly registry --fetch' first."
            )
        return RegistryFetchSummary(fetched=0, skipped=0, warnings=())

    warnings: list[str] = []
    try:
        index_text = _download_text(registry_url)
    except (OSError, urllib.error.URLError) as exc:
        raise RegistryError(f"Failed to fetch registry index from {registry_url}: {exc}") from exc

    try:
        index_data = json.loads(index_text)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"Registry index at {registry_url} is not valid JSON: {exc}") from exc

    rules_data = index_data.get("rules", []) if isinstance(index_data, dict) else []
    if not isinstance(rules_data, list):
        raise RegistryError("Registry index must contain a top-level 'rules' list")

    fetched = 0
    skipped = 0
    for entry in rules_data:
        if not isinstance(entry, dict):
            skipped += 1
            warnings.append("Skipped registry entry that was not an object")
            continue
        rule_id = str(entry.get("id", "")).strip()
        url = str(entry.get("url", "")).strip()
        if not rule_id or not url:
            skipped += 1
            warnings.append(f"Skipped registry entry missing id/url: {entry!r}")
            continue
        try:
            rule_text = _download_text(url)
        except (OSError, urllib.error.URLError) as exc:
            skipped += 1
            warnings.append(f"Skipped {rule_id}: download failed ({exc})")
            continue
        parsed = load_community_rule_text(rule_text, source_label=url)
        if parsed is None:
            skipped += 1
            warnings.append(f"Skipped {rule_id}: schema validation failed")
            continue
        if parsed.rule_id != rule_id:
            skipped += 1
            warnings.append(f"Skipped {rule_id}: downloaded file declared id {parsed.rule_id!r}")
            continue
        (target_dir / _rule_filename(rule_id)).write_text(rule_text, encoding="utf-8")
        fetched += 1

    return RegistryFetchSummary(fetched=fetched, skipped=skipped, warnings=tuple(warnings))


def remove_installed_rule(rule_id: str, directory: str | Path | None = None) -> bool:
    """Remove an installed community rule by its rule ID."""
    target_dir = community_rules_dir(directory)
    for path in _installed_rule_files(target_dir):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parsed = load_community_rule_text(content, source_label=str(path))
        if parsed is not None and parsed.rule_id == rule_id:
            path.unlink(missing_ok=True)
            return True
    fallback = target_dir / _rule_filename(rule_id)
    if fallback.exists():
        fallback.unlink(missing_ok=True)
        return True
    return False


def _build_registry_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardmarly registry")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--fetch", action="store_true", help="Download and cache community rules locally.")
    action.add_argument("--list", action="store_true", help="List installed community rules.")
    action.add_argument("--remove", metavar="RULE_ID", help="Remove one installed community rule by ID.")
    parser.add_argument("--registry-url", default=DEFAULT_REGISTRY_URL, help="Override the registry index URL.")
    parser.add_argument("--offline", action="store_true", help="Never make network calls; use cached rules only.")
    parser.add_argument("--install-dir", default=None, help="Override the install directory (primarily for tests).")
    return parser


def handle_registry_command(
    argv: list[str],
    *,
    workspace_root: str | Path | None = None,
) -> int:
    """Entry point for ``guardmarly registry``."""
    parser = _build_registry_parser()
    args = parser.parse_args(argv)
    install_dir = community_rules_dir(args.install_dir)

    if args.fetch:
        try:
            summary = fetch_registry_rules(
                registry_url=args.registry_url,
                install_dir=install_dir,
                offline=args.offline,
            )
        except NoCommunityRulesCachedError as exc:
            print(str(exc))
            return 2
        except RegistryError as exc:
            print(f"guardmarly: registry error: {exc}")
            return 2

        for warning in summary.warnings:
            print(f"WARNING: {warning}")
        if args.offline:
            cached_count = len(list_installed_community_rules(install_dir))
            print(f"Using {cached_count} cached community rule(s).")
        else:
            print(f"Fetched {summary.fetched} rules, skipped {summary.skipped} (schema errors).")
        return 0

    if args.list:
        cfg = load_config(Path(workspace_root) if workspace_root is not None else Path.cwd())
        disabled = {
            _normalized_rule_token(token)
            for token in getattr(cfg, "disable_rules", [])
            if isinstance(token, str) and token.strip()
        }
        rules = list_installed_community_rules(install_dir)
        if not rules:
            print("No community rules installed.")
            return 0
        for rule in rules:
            markers: list[str] = []
            if _normalized_rule_token(rule.rule_id) in disabled or (rule.cwe and _normalized_rule_token(rule.cwe) in disabled):
                markers.append("[disabled]")
            suffix = f" {' '.join(markers)}" if markers else ""
            languages = ",".join(rule.languages) or "all"
            print(f"{rule.rule_id} {rule.cwe or '-'} {rule.severity.value} {languages}{suffix}")
        return 0

    removed = remove_installed_rule(str(args.remove), install_dir)
    if removed:
        print(f"Removed {args.remove}")
        return 0
    print(f"Community rule not found: {args.remove}")
    return 2
