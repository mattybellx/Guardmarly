"""
guardmarly.js_engine.project_context
─────────────────────────────────────────
Project-level context detection — determines whether a JS file runs in a
browser, Node.js, or isomorphic context, and collects framework/domain hints.

This lets rules filter out findings that don't apply to the detected runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto

# ── Regex patterns for runtime detection ──────────────────────────────

# Strong browser DOM signals (these almost never appear in pure Node.js)
_DOM_API_RE = re.compile(
    r"\b(?:"
    r"document\.(?:getElementById|querySelector|createElement|createTextNode|"
    r"body|head|cookie|documentElement|write|writeln|location|title|"
    r"addEventListener|createEvent|createRange|execCommand|"
    r"querySelectorAll|getElementsByClassName|getElementsByTagName)"
    r")\s*\(",
    re.IGNORECASE,
)

_WINDOW_API_RE = re.compile(
    r"\b(?:"
    r"window\.(?:location|navigator|innerWidth|innerHeight|"
    r"addEventListener|removeEventListener|open|close|"
    r"postMessage|requestAnimationFrame|setTimeout|setInterval|"
    r"matchMedia|scrollTo|scrollBy|getComputedStyle|"
    r"localStorage|sessionStorage)"
    r")\s*\(",
    re.IGNORECASE,
)

_BROWSER_GLOBALS_RE = re.compile(
    r"\b(?:"
    r"XMLHttpRequest|ActiveXObject|History\.pushState|"
    r"location\.(?:href|search|hash|pathname|reload|assign|replace)|"
    r"navigator\.(?:userAgent|platform|language|cookieEnabled|"
    r"geolocation|mediaDevices|serviceWorker|sendBeacon)|"
    r"localStorage\.(?:getItem|setItem|removeItem|clear)|"
    r"sessionStorage\.(?:getItem|setItem|removeItem|clear)|"
    r"fetch\s*\(|"      # bare fetch() — browser native (Node also has it from 18+ but often with require)
    r"innerHTML\s*[+]=|outerHTML\s*[+]=|"
    r"addEventListener\s*\(|removeEventListener\s*\("
    r")\s*(?:[.(])?",
)

# Strong Node.js signals
_NODE_REQUIRE_FS_RE = re.compile(
    r"""require\s*\(\s*['"]"""
    r"(?:fs|fs/promises|path|child_process|os|net|cluster|"
    r"dgram|http2|stream|worker_threads|perf_hooks|async_hooks|"
    r"crypto|tls|https|http|url|querystring|util|events|readline)"
    r"""['"]\s*\)""",
    re.IGNORECASE | re.VERBOSE,
)

_NODE_GLOBAL_RE = re.compile(
    r"\b(?:"
    r"__dirname|__filename|module\.exports|exports\.\w+|"
    r"process\.(?:env|argv|cwd|exit|pid|platform|version|"
    r"stdout|stderr|stdin|nextTick|on|hrtime|memoryUsage|"
    r"uptime|chdir|umask|kill|abort)|"
    r"Buffer\.(?:from|alloc|allocUnsafe|isBuffer|byteLength)|"
    r"globalThis|global\b(?:\s*\.\s*|\s*\[|$)|"
    r"require\s*\(|require\.(?:resolve|cache|main)"
    r")(?!\s*\()",
)

# Path heuristics: files in certain directories are likely browser or Node
_BROWSER_PATH_MARKERS: tuple[str, ...] = (
    "/frontend/", "/public/", "/static/", "/assets/",
    "/browser/", "/client/", "/ui/", "/views/",
    "/templates/", "/www/", "/htdocs/",
)
_NODE_PATH_MARKERS: tuple[str, ...] = (
    "/server/", "/backend/", "/api/", "/routes/",
    "/controllers/", "/middleware/", "/models/",
    "/services/", "/migrations/", "/bin/",
    "/scripts/", "/cmd/", "/cmd/",
)
_TEST_PATH_MARKERS: tuple[str, ...] = (
    "/test/", "/tests/", "/__tests__/", "/spec/",
    "/e2e/", "/cypress/", "/playwright/",
    "/perf/", "/bench/", "/benchmarks/", "/examples/",
)


class Runtime(Enum):
    """Detected runtime environment for a JS file."""
    BROWSER = auto()
    NODE = auto()
    ISOMORPHIC = auto()  # used in both environments
    TEST = auto()         # test files (often use Node APIs but in a test context)
    UNKNOWN = auto()


@dataclass
class ProjectContext:
    """Detected project-level context for a single JS source file.

    This is computed once per file and passed to rule checkers so they
    can skip findings that aren't applicable to the detected runtime.
    """
    runtime: Runtime = Runtime.UNKNOWN
    file_path: str = ""
    has_browser_apis: bool = False
    has_node_apis: bool = False
    is_test_file: bool = False
    is_vendor: bool = False

    # Framework hints (populated when detected)
    detected_frameworks: list[str] = field(default_factory=list)

    @property
    def is_browser(self) -> bool:
        return self.runtime is Runtime.BROWSER

    @property
    def is_node(self) -> bool:
        return self.runtime is Runtime.NODE

    @property
    def is_isomorphic(self) -> bool:
        return self.runtime is Runtime.ISOMORPHIC

    @property
    def is_test(self) -> bool:
        return self.runtime is Runtime.TEST

    @property
    def skip_node_rules(self) -> bool:
        """If True, Node.js-specific rules should be skipped for this file.

        This is the primary signal for downstream rule filtering.
        """
        return (
            self.runtime is Runtime.BROWSER
            or self.runtime is Runtime.UNKNOWN and self.has_browser_apis
        )

    @property
    def skip_browser_rules(self) -> bool:
        """If True, browser-specific rules should be skipped for this file."""
        return (
            self.runtime is Runtime.NODE
            or self.runtime is Runtime.TEST
        )


def _normalized_path(fp: str) -> str:
    """Normalize a file path to forward-slash form for pattern matching."""
    return fp.replace("\\", "/").lower()


def _detect_from_path(file_path: str) -> tuple[bool, bool, bool]:
    """Detect browser/Node/test hints from the file path alone."""
    norm = _normalized_path(file_path)
    is_browser_path = any(m in norm for m in _BROWSER_PATH_MARKERS)
    is_node_path = any(m in norm for m in _NODE_PATH_MARKERS)
    is_test_path = any(m in norm for m in _TEST_PATH_MARKERS)
    return is_browser_path, is_node_path, is_test_path


# ── FS callee disambiguation ──────────────────────────────────────────
# Regex patterns for destructured fs imports.
# The key pattern: "open" must appear as a bare destructured name, not
# aliased like "open: fsOpen".  We use a negative lookahead for ":".
_FS_DESTRUCTURE_RE = re.compile(
    r"""const\s*\{[^}]*?\bopen\b(?!\s*:)[^}]*?\}\s*=\s*require\s*\(\s*['"]fs['"]\s*\)""",
    re.VERBOSE,
)
_FS_IMPORT_DESTRUCTURE_RE = re.compile(
    r"""import\s*\{[^}]*?\bopen\b(?!\s*:)[^}]*?\}\s*from\s*['"]fs['"]""",
    re.VERBOSE,
)


def is_fs_callee(callee: str, *, code: str = "") -> bool:
    """Determine whether a callee named ``open``/``openSync`` is a filesystem operation.

    Handles two patterns:

    1. Dotted receiver::

         fs.open(path)        → callee is ``"fs.open"``, receiver is ``"fs"`` ✅
         xhr.open(method,url) → callee is ``"xhr.open"``, receiver is ``"xhr"`` ❌

    2. Destructured import (bare call)::

         const { open } = require('fs');
         open(path)            → callee is ``"open"``, bare, needs code scan ✅

    For the dotted case the check is purely lexical — for the bare case
    the caller must supply the surrounding source *code* so we can look
    for a destructured ``fs`` import.
    """
    short = callee.rsplit(".", 1)[-1]
    if short not in {"open", "openSync", "resolve", "join"}:
        return True  # Not an ambiguous callee — let other rules handle it

    # Pattern 1: Dotted receiver — check if receiver is fs or path module
    if "." in callee:
        receiver = callee.rsplit(".", 1)[0]
        return receiver in {"fs", "node:fs", "fs/promises", "path"}

    # Pattern 2: Bare call (no dot) — needs code scan for destructured import
    if not code:
        return False  # Can't verify without code — safest to skip

    return bool(_FS_DESTRUCTURE_RE.search(code) or _FS_IMPORT_DESTRUCTURE_RE.search(code))


def classify_runtime(code: str, file_path: str = "") -> ProjectContext:
    """Classify the runtime context of a JS source file.

    Examines the source code and file path to determine whether this file
    runs in a browser, Node.js, or both environments.
    """
    ctx = ProjectContext(file_path=file_path)

    # 1. Check file path hints
    path_browser, path_node, path_test = _detect_from_path(file_path)
    ctx.is_test_file = path_test
    ctx.is_vendor = "node_modules" in _normalized_path(file_path)

    # 2. Scan code for browser DOM APIs
    ctx.has_browser_apis = bool(
        _DOM_API_RE.search(code)
        or _WINDOW_API_RE.search(code)
        or _BROWSER_GLOBALS_RE.search(code)
    )

    # 3. Scan code for Node.js APIs
    ctx.has_node_apis = bool(
        _NODE_REQUIRE_FS_RE.search(code)
        or _NODE_GLOBAL_RE.search(code)
    )

    # 4. Determine runtime from signals
    if ctx.is_test_file:
        ctx.runtime = Runtime.TEST
    elif ctx.has_browser_apis and ctx.has_node_apis:
        # Check which is dominant
        browser_matches = (
            len(_DOM_API_RE.findall(code))
            + len(_WINDOW_API_RE.findall(code))
            + len(_BROWSER_GLOBALS_RE.findall(code))
        )
        node_matches = (
            len(_NODE_REQUIRE_FS_RE.findall(code))
            + len(_NODE_GLOBAL_RE.findall(code))
        )
        if browser_matches > node_matches * 3:
            ctx.runtime = Runtime.BROWSER
        elif node_matches > browser_matches * 3:
            ctx.runtime = Runtime.NODE
        else:
            ctx.runtime = Runtime.ISOMORPHIC
    elif ctx.has_browser_apis:
        ctx.runtime = Runtime.BROWSER
    elif ctx.has_node_apis:
        ctx.runtime = Runtime.NODE
    elif path_browser and not path_node:
        ctx.runtime = Runtime.BROWSER
    elif path_node and not path_browser:
        ctx.runtime = Runtime.NODE
    else:
        ctx.runtime = Runtime.UNKNOWN

    # 5. Detect common frameworks
    _detect_frameworks(code, ctx)

    return ctx


def _detect_frameworks(code: str, ctx: ProjectContext) -> None:
    """Populate ctx.detected_frameworks with framework hints."""
    if re.search(r"React\.(createElement|Component|useState|useEffect)\s*\(", code):
        ctx.detected_frameworks.append("react")
    if re.search(r"(?:from\s+['\"]react['\"]|require\s*\(\s*['\"]react['\"]\s*\))", code):
        ctx.detected_frameworks.append("react")
    if re.search(r"(?:app\.(?:get|post|put|delete|use|listen)\s*\()", code):
        ctx.detected_frameworks.append("express")
    if re.search(r"(?:axios\.(?:get|post|put|delete|request)\s*\()", code):
        ctx.detected_frameworks.append("axios")
    if re.search(r"\bVue\b", code):
        ctx.detected_frameworks.append("vue")
    if re.search(r"\bangular\.module|Component\s*\(\s*\{", code):
        ctx.detected_frameworks.append("angular")
    if re.search(r"\bmodals?\.(?:open|close|show|hide)\s*\(", code):
        ctx.detected_frameworks.append("ui-modal-framework")
