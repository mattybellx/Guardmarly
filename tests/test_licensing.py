from __future__ import annotations

from ansede_static.licensing import (
    LicenseInfo,
    bump_guarded_autofix_count,
    remaining_guarded_autofix_quota,
)


def _license(tier: str) -> LicenseInfo:
    return LicenseInfo(
        tier=tier,
        licensee=f"{tier}@example.com",
        seats=1,
        issued_at=0,
        expires_at=0,
        key_id=f"{tier}-key",
        raw_payload={"tier": tier},
    )


def test_free_guarded_autofix_quota_decrements(monkeypatch, tmp_path):
    count_file = tmp_path / "guarded_autofix_count.json"
    hash_file = tmp_path / ".guarded_autofix_integrity"

    monkeypatch.setattr("ansede_static.licensing._guarded_autofix_count_file", lambda: count_file)
    monkeypatch.setattr("ansede_static.licensing._guarded_autofix_hash_file", lambda: hash_file)
    monkeypatch.setattr("ansede_static.licensing.load_license", lambda: _license("free"))

    assert remaining_guarded_autofix_quota() == 50

    used = bump_guarded_autofix_count(7)

    assert used == 7
    assert remaining_guarded_autofix_quota() == 43


def test_pro_guarded_autofix_quota_is_unlimited(monkeypatch):
    monkeypatch.setattr("ansede_static.licensing.load_license", lambda: _license("pro"))

    assert remaining_guarded_autofix_quota() is None
    assert bump_guarded_autofix_count(5) == 0
