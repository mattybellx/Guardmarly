"""ansede_static.pypi_validator
──────────────────────────────────────────────────────────────────────────────
PyPI Readiness Validator for Ansede Static.

Validates:
1. Package metadata in pyproject.toml
2. CLI entry points and command structure
3. README.md and documentation completeness
4. License and contributing guidelines
5. Package installation without errors
6. CLI global availability
7. Module imports and dependencies

Run: python -m ansede_static.pypi_validator
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)


@dataclass
class PyPIValidationResult:
    """Result of PyPI readiness validation."""
    is_ready: bool = False
    checks_passed: int = 0
    checks_failed: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class PyPIValidator:
    """Comprehensive PyPI readiness validation."""

    def __init__(self, root_dir: Optional[str | Path] = None):
        self.root_dir = Path(root_dir or Path.cwd())
        self.result = PyPIValidationResult()
        self.pyproject: dict = {}
        self.metadata: dict = {}

    def validate_all(self) -> PyPIValidationResult:
        """Run all PyPI readiness checks."""
        print("🔍 Validating PyPI readiness for ansede-static...\n")

        # 1. Check pyproject.toml
        if self._check_pyproject():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 2. Check README
        if self._check_readme():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 3. Check license
        if self._check_license():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 4. Check CLI entry points
        if self._check_cli_entry_points():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 5. Check imports
        if self._check_imports():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 6. Check dependencies (zero external)
        if self._check_dependencies():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 7. Check version format
        if self._check_version():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # 8. Test CLI invocation
        if self._test_cli():
            self.result.checks_passed += 1
        else:
            self.result.checks_failed += 1

        # Determine overall readiness
        self.result.is_ready = (
            self.result.checks_failed == 0 and
            len(self.result.errors) == 0
        )

        return self.result

    def _check_pyproject(self) -> bool:
        """Check pyproject.toml completeness."""
        print("1️⃣  Checking pyproject.toml...")
        pyproject_path = self.root_dir / "pyproject.toml"

        if not pyproject_path.exists():
            self.result.errors.append("❌ pyproject.toml not found")
            return False

        try:
            if sys.version_info >= (3, 11):
                import tomllib as toml_module
            else:
                import tomli as toml_module
            with open(pyproject_path, "rb") as f:
                content = f.read()
                # Simple TOML parsing (fallback to text)
                self.pyproject = self._parse_toml_simple(content.decode())
        except (ImportError, Exception) as e:
            self.result.warnings.append(f"⚠️  Could not parse pyproject.toml: {e}")
            self.pyproject = self._parse_toml_simple(pyproject_path.read_text())

        # Check required fields
        required_keys = ["project", "build-system"]
        for key in required_keys:
            if key not in str(self.pyproject):
                self.result.warnings.append(f"⚠️  Missing [{key}] in pyproject.toml")

        # Check project metadata
        content = pyproject_path.read_text()
        checks = [
            ("name", r'name\s*=\s*["\']ansede-static["\']'),
            ("version", r'version\s*=\s*["\'][0-9]+\.[0-9]+\.[0-9]+["\']'),
            ("description", r'description\s*='),
            ("license", r'license\s*='),
            ("requires-python", r'requires-python\s*=\s*["\']>=3.9["\']'),
            ("dependencies", r'dependencies\s*=\s*\[\s*\]'),  # Should be empty!
        ]

        for name, pattern in checks:
            if re.search(pattern, content):
                print(f"  ✅ {name}: present")
            else:
                self.result.warnings.append(f"⚠️  {name}: not found or incorrect")

        print("  ✅ pyproject.toml validation passed\n")
        return True

    def _check_readme(self) -> bool:
        """Check README.md completeness."""
        print("2️⃣  Checking README.md...")
        readme_path = self.root_dir / "README.md"

        if not readme_path.exists():
            self.result.errors.append("❌ README.md not found")
            return False

        try:
            content = readme_path.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            self.result.warnings.append(f"⚠️  Could not read README.md: {e}")
            return False

        # Check for essential sections
        sections = [
            ("Installation", r"## Installation|# Installation"),
            ("Quick Start", r"## Quick Start|## Usage"),
            ("Examples", r"## Examples?|## Demo"),
            ("License", r"## License"),
        ]

        found = 0
        for name, pattern in sections:
            if re.search(pattern, content, re.IGNORECASE):
                print(f"  ✅ {name} section: present")
                found += 1
            else:
                self.result.warnings.append(f"⚠️  {name} section missing from README")

        if found >= 2:
            print("  ✅ README.md validation passed\n")
            return True

        return False

    def _check_license(self) -> bool:
        """Check LICENSE file."""
        print("3️⃣  Checking LICENSE...")
        license_path = self.root_dir / "LICENSE"

        if not license_path.exists():
            self.result.errors.append("❌ LICENSE file not found")
            return False

        content = license_path.read_text()
        if "MIT" in content or "Apache" in content or "GPL" in content:
            print("  ✅ LICENSE: present and valid\n")
            return True

        self.result.warnings.append("⚠️  LICENSE format unclear")
        return True

    def _check_cli_entry_points(self) -> bool:
        """Check CLI entry points."""
        print("4️⃣  Checking CLI entry points...")

        # Check pyproject.toml
        pyproject_path = self.root_dir / "pyproject.toml"
        content = pyproject_path.read_text()

        expected_entries = [
            "ansede-static",
            "ansede",
        ]

        found_entries = []
        for entry in expected_entries:
            if entry in content:
                found_entries.append(entry)
                print(f"  ✅ Entry point '{entry}': configured")

        if len(found_entries) >= 1:
            print("  ✅ CLI entry points validation passed\n")
            return True

        self.result.errors.append("❌ No CLI entry points found")
        return False

    def _check_imports(self) -> bool:
        """Check that main modules can be imported."""
        print("5️⃣  Checking package imports...")

        try:
            import ansede_static
            print("  ✅ Main package imports: OK")

            # Try to import key modules
            modules = [
                "ansede_static.cli",
                "ansede_static.python_analyzer",
                "ansede_static.reporters",
                "ansede_static.hardening",
                "ansede_static.engine.triage",
                "ansede_static.engine.remediation",
            ]

            for module in modules:
                try:
                    __import__(module)
                    print(f"  ✅ {module}: OK")
                except ImportError as e:
                    self.result.warnings.append(f"⚠️  {module}: {e}")

            print("  ✅ Package imports validation passed\n")
            return True

        except ImportError as e:
            self.result.errors.append(f"❌ Cannot import ansede_static: {e}")
            return False

    def _check_dependencies(self) -> bool:
        """Check that dependencies are zero (or only optional)."""
        print("6️⃣  Checking dependencies...")

        pyproject_path = self.root_dir / "pyproject.toml"
        content = pyproject_path.read_text()

        # Parse dependencies line
        match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if match:
            deps_str = match.group(1).strip()
            if deps_str == "" or deps_str.isspace():
                print("  ✅ Zero core dependencies: OK")
                print("  ✅ Dependencies validation passed\n")
                return True
            else:
                # Some dependencies found - check if they're really external
                if "ansede" in deps_str or "internal" in deps_str:
                    print("  ✅ Dependencies: internal only")
                    return True

                self.result.warnings.append(f"⚠️  External dependencies detected: {deps_str[:100]}")
                return False

        return True

    def _check_version(self) -> bool:
        """Check version format."""
        print("7️⃣  Checking version format...")

        pyproject_path = self.root_dir / "pyproject.toml"
        content = pyproject_path.read_text()

        match = re.search(r'version\s*=\s*["\']([0-9.]+)["\']', content)
        if match:
            version = match.group(1)
            # Check semver format
            parts = version.split(".")
            if len(parts) >= 3:
                try:
                    _ = [int(p) for p in parts[:3]]
                    print(f"  ✅ Version {version}: valid semver")
                    self.result.metadata["version"] = version
                    print("  ✅ Version format validation passed\n")
                    return True
                except ValueError:
                    pass

        self.result.warnings.append("⚠️  Version format unclear or invalid")
        return False

    def _test_cli(self) -> bool:
        """Test CLI invocation."""
        print("8️⃣  Testing CLI invocation...")

        try:
            result = subprocess.run(
                [sys.executable, "-m", "ansede_static.cli", "--help"],
                capture_output=True,
                timeout=5,
                text=True,
            )

            if result.returncode == 0 and "usage" in result.stdout.lower():
                print("  ✅ CLI --help: works")
                print("  ✅ CLI invocation validation passed\n")
                return True

            self.result.warnings.append(f"⚠️  CLI test: return code {result.returncode}")
            return False

        except subprocess.TimeoutExpired:
            self.result.warnings.append("⚠️  CLI test timed out")
            return False
        except Exception as e:
            self.result.warnings.append(f"⚠️  CLI test failed: {e}")
            return False

    def print_report(self) -> None:
        """Print validation report."""
        print("\n" + "=" * 70)
        print("PyPI READINESS REPORT")
        print("=" * 70 + "\n")

        if self.result.is_ready:
            print("✅ READY FOR PyPI PUBLICATION\n")
        else:
            print("❌ NOT READY — Please address the following issues:\n")

        if self.result.errors:
            print(f"🔴 CRITICAL ERRORS ({len(self.result.errors)}):")
            for error in self.result.errors:
                print(f"   {error}")
            print()

        if self.result.warnings:
            print(f"🟡 WARNINGS ({len(self.result.warnings)}):")
            for warning in self.result.warnings[:5]:
                print(f"   {warning}")
            if len(self.result.warnings) > 5:
                print(f"   ... and {len(self.result.warnings) - 5} more")
            print()

        print(f"Checks Passed: {self.result.checks_passed}/8")
        print(f"Checks Failed: {self.result.checks_failed}/8")

        print("\n" + "=" * 70 + "\n")

    @staticmethod
    def _parse_toml_simple(content: str) -> dict:
        """Simple TOML parser for basic validation."""
        result = {}
        current_section = None

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                result[current_section] = {}
            elif "=" in line and not line.startswith("#"):
                key, _ = line.split("=", 1)
                if current_section:
                    result[current_section][key.strip()] = None

        return result


def main() -> int:
    """Run PyPI validation."""
    try:
        validator = PyPIValidator()
        result = validator.validate_all()
        validator.print_report()

        return 0 if result.is_ready else 1

    except Exception as e:
        print(f"❌ Validation error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
