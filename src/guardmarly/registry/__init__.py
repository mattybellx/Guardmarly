"""
guardmarly.registry
───────────────────────
Zero-dependency framework rule sharding system.

Exports the public API for lazy-loading framework-specific security rule packs.
Each pack is a YAML file bundled with the package under src/guardmarly/registry/.

Usage (internal):
    from guardmarly.registry import load_packs_for_source, count_registry_rules
"""
from guardmarly.registry.loader import (
    detect_frameworks,
    load_packs_for_language,
    load_packs_for_source,
    load_all_registry_packs,
    count_registry_rules,
    list_registry_pack_names,
)
from guardmarly.registry.sharded_loader import (
    load_custom_rules_for_code,
    load_rules_for_code,
)
from guardmarly.registry.community import (
    NoCommunityRulesCachedError,
    RegistryError,
    RegistryFetchSummary,
    community_rules_dir,
    default_community_rules_dir,
    fetch_registry_rules,
    handle_registry_command,
    list_installed_community_rules,
    remove_installed_rule,
)

__all__ = [
    "detect_frameworks",
    "load_packs_for_language",
    "load_packs_for_source",
    "load_all_registry_packs",
    "count_registry_rules",
    "list_registry_pack_names",
    "load_custom_rules_for_code",
    "load_rules_for_code",
]
