from __future__ import annotations

import os
import re
import time
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path

from guardmarly._types import TraceFrame
from guardmarly.hardening import detect_minified
from guardmarly.ir.global_graph import GlobalGraph
from guardmarly.js_engine.common import COMMENT_LINE_RE, strip_comments
from guardmarly.js_engine.project_context import is_fs_callee
from guardmarly.js_engine.constants import (
    OWNERSHIP_KEY_RE,
    PRINCIPAL_REF_RE,
    VERIFICATION_CALL_RE,
    PRIVILEGE_KEY_RE,
    REQUEST_OBJECT_ARG_RE,
    LOOKUP_CALLEE_PARTS,
    MUTATION_CALLEE_PARTS,
    PATH_CALLEE_PARTS,
    SSRF_CALLEES,
)
from guardmarly.js_engine.structure import collect_calls, mask_js_text, parse_object_literal, split_top_level_args
from guardmarly.js_engine.taint import (
	append_trace,
	extract_taint_traces,
	merge_traces,
	sanitizer_frames_for_expr,
	trace_for_expr,
	trace_has_sanitizer,
)

_JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_SIMPLE_NAME_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
# LOOKUP_CALLEE_PARTS, MUTATION_CALLEE_PARTS, PATH_CALLEE_PARTS, SSRF_CALLEES,
# AUTH_MIDDLEWARE_RE, PRIVILEGE_MIDDLEWARE_RE, OWNERSHIP_KEY_RE, PRINCIPAL_REF_RE,
# VERIFICATION_CALL_RE, PRIVILEGE_KEY_RE, REQUEST_OBJECT_ARG_RE
# are all imported from js_engine.constants
_FUNCTION_DECL_RE = re.compile(
	r"(?P<prefix>export\s+default\s+|export\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)?\s*\((?P<params>[^)]*)\)\s*\{",
	re.S,
)
_ARROW_ASSIGN_RE = re.compile(
	r"(?P<prefix>export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
	r"(?P<params>\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{",
	re.S,
)
_FUNCTION_ASSIGN_RE = re.compile(
	r"(?P<prefix>export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
	r"function(?:\s+[A-Za-z_$][\w$]*)?\s*\((?P<params>[^)]*)\)\s*\{",
	re.S,
)
_ASSIGNMENT_RE = re.compile(r"(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$")
_EXPORTS_FUNCTION_RE = re.compile(
	r"(?:(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*))\s*=\s*(?:async\s*)?"
	r"function(?:\s+[A-Za-z_$][\w$]*)?\s*\((?P<params>[^)]*)\)\s*\{",
	re.S,
)
_EXPORTS_ARROW_RE = re.compile(
	r"(?:(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*))\s*=\s*(?:async\s*)?"
	r"(?P<params>\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{",
	re.S,
)
_MODULE_EXPORT_FUNCTION_RE = re.compile(
	r"module\.exports\s*=\s*(?:async\s*)?function(?:\s+(?P<name>[A-Za-z_$][\w$]*))?\s*\((?P<params>[^)]*)\)\s*\{",
	re.S,
)
_MODULE_EXPORT_ARROW_RE = re.compile(
	r"module\.exports\s*=\s*(?:async\s*)?(?P<params>\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{",
	re.S,
)
_CLASS_RE = re.compile(
	r"(?P<decorators>(?:\s*@[^\n]+\n)*)\s*(?P<prefix>export\s+default\s+|export\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)"
	r"(?:\s+extends[^{]+)?\s*\{",
	re.MULTILINE,
)
_CLASS_METHOD_RE = re.compile(
	r"(?P<decorators>(?:\s*@[^\n]+\n)*)\s*(?:(?:public|private|protected|static|readonly|async)\s+)*"
	r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*\{",
	re.MULTILINE,
)
_CLASS_FIELD_RE = re.compile(
	r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:readonly\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*:\s*(?P<type>[A-Za-z_$][\w$.<>\[\]]*)",
	re.MULTILINE,
)
_CONSTRUCTOR_PROPERTY_RE = re.compile(
	r"^(?:(?:@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s*)*)(?:public|private|protected)\s+(?:readonly\s+)?"
	r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:\?)?\s*:\s*(?P<type>[A-Za-z_$][\w$.<>\[\]]*)$",
)
_TYPED_PARAM_RE = re.compile(
	r"^(?:(?:@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s*)*)(?P<name>[A-Za-z_$][\w$]*)\s*(?:\?)?\s*:\s*(?P<type>[A-Za-z_$][\w$.<>\[\]]*)$",
)
_THIS_ASSIGN_RE = re.compile(
	r"\bthis\.(?P<prop>[A-Za-z_$][\w$]*)\s*=\s*(?P<value>[A-Za-z_$][\w$]*|new\s+[A-Za-z_$][\w$]*)\b",
	re.IGNORECASE,
)
_CALL_ALIAS_RE = re.compile(
	r"^(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<target>(?:this\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;?$",
	re.IGNORECASE,
)
_RETURN_RE = re.compile(r"\breturn\b")
_EXPORT_NAMED_FROM_RE = re.compile(r"export\s*\{([^}]*)\}\s*from\s*[\"']([^\"']+)[\"']", re.S)
_EXPORT_STAR_FROM_RE = re.compile(r"export\s*\*\s*from\s*[\"']([^\"']+)[\"']")
_EXPORT_STAR_AS_RE = re.compile(r"export\s*\*\s*as\s*([A-Za-z_$][\w$]*)\s*from\s*[\"']([^\"']+)[\"']")
_WORKSPACE_MARKERS = ("pyproject.toml", "package.json", "guardmarly.json", "action.yml", ".git")
_WORKSPACE_IGNORE_DIRS = {
	".git",
	".hg",
	".svn",
	".venv",
	"venv",
	"node_modules",
	"dist",
	"build",
	"coverage",
	"__pycache__",
	".mypy_cache",
	".pytest_cache",
	"public",
	"static",
	"assets",
	"vendor",
	"bower_components",
	".next",
	".nuxt",
	"out",
}
_WORKSPACE_REFRESH_INTERVAL_NS = 5_000_000_000
_WORKSPACE_GRAPH_CACHE: dict[str, JsWorkspaceGraph] = {}
_DEFAULT_IFDS_CALL_STRING_K = GlobalGraph.DEFAULT_CALL_STRING_K


@dataclass(frozen=True)
class JSImportBinding:
	local_name: str
	source: str
	imported_name: str
	is_namespace: bool = False


@dataclass(frozen=True)
class JSExportBinding:
	export_name: str
	local_name: str = ""
	source: str = ""
	imported_name: str = ""
	is_namespace: bool = False


@dataclass(frozen=True)
class JsFunctionDef:
	name: str
	params: tuple[str, ...]
	body: str
	line: int
	file_path: str
	lookup_key: str = ""
	owner_class: str = ""


@dataclass(frozen=True)
class JsClassDef:
	name: str
	methods: dict[str, JsFunctionDef]
	property_types: dict[str, str]
	line: int
	file_path: str


@dataclass(frozen=True)
class HelperEffect:
	kind: str
	param_index: int
	sink_label: str
	helper_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReturnEffect:
	param_index: int
	source_suffix: str = ""
	helper_chain: tuple[str, ...] = ()
	sanitizer_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionSummary:
	effects: tuple[HelperEffect, ...] = ()
	return_effects: tuple[ReturnEffect, ...] = ()
	verifies_auth: bool = False
	privilege_guard: bool = False
	ownership_guard: bool = False


@dataclass
class JsFileIndex:
	file_path: str
	code: str
	functions: dict[str, JsFunctionDef] = field(default_factory=dict)
	classes: dict[str, JsClassDef] = field(default_factory=dict)
	exports: dict[str, JSExportBinding] = field(default_factory=dict)
	export_stars: tuple[str, ...] = ()
	imports: dict[str, JSImportBinding] = field(default_factory=dict)


@dataclass
class JsProjectIndex:
	files: dict[str, JsFileIndex] = field(default_factory=dict)
	summaries: dict[tuple[str, str], FunctionSummary] = field(default_factory=dict)
	workspace_root: str = ""


@dataclass
class JsWorkspaceGraph:
	root_path: str
	files: dict[str, JsFileIndex] = field(default_factory=dict)
	file_mtimes: dict[str, int] = field(default_factory=dict)
	last_refresh_ns: int = 0


@lru_cache(maxsize=16384)
def _normalize_path(path: str | Path) -> str:
	try:
		return str(Path(path).resolve(strict=False))
	except OSError:
		return str(path)


def _discover_workspace_root(file_path: str) -> str:
	current = Path(file_path).resolve(strict=False).parent
	for candidate in (current, *current.parents):
		if any((candidate / marker).exists() for marker in _WORKSPACE_MARKERS):
			return _normalize_path(candidate)
	return _normalize_path(current)


def _iter_workspace_js_files(root: Path) -> list[Path]:
	files: list[Path] = []
	for dirpath, dirnames, filenames in os.walk(root):
		dirnames[:] = [name for name in dirnames if name not in _WORKSPACE_IGNORE_DIRS]
		for filename in filenames:
			candidate = Path(dirpath) / filename
			if candidate.suffix in _JS_EXTENSIONS and not _is_generated_js_asset(candidate):
				files.append(candidate)
	return files


def _is_generated_js_asset(candidate: Path) -> bool:
	name = candidate.name.lower()
	if name.endswith((".min.js", ".bundle.js", ".chunk.js")):
		return True
	try:
		if candidate.stat().st_size > 250_000:
			return True
	except OSError:
		return False
	return False


def _get_workspace_graph(root_path: str) -> JsWorkspaceGraph:
	normalized_root = _normalize_path(root_path)
	graph = _WORKSPACE_GRAPH_CACHE.get(normalized_root)
	if graph is None:
		graph = JsWorkspaceGraph(root_path=normalized_root)
		_WORKSPACE_GRAPH_CACHE[normalized_root] = graph
	_refresh_workspace_graph(graph)
	return graph


def _refresh_workspace_graph(graph: JsWorkspaceGraph) -> None:
	now = time.monotonic_ns()
	if graph.last_refresh_ns and now - graph.last_refresh_ns < _WORKSPACE_REFRESH_INTERVAL_NS:
		return
	graph.last_refresh_ns = now

	root = Path(graph.root_path)
	if not root.exists():
		graph.files.clear()
		graph.file_mtimes.clear()
		return

	seen_paths: set[str] = set()
	for candidate in _iter_workspace_js_files(root):
		normalized = _normalize_path(candidate)
		seen_paths.add(normalized)
		try:
			mtime_ns = candidate.stat().st_mtime_ns
		except OSError:
			continue
		if graph.file_mtimes.get(normalized) == mtime_ns:
			continue
		try:
			code = candidate.read_text(encoding="utf-8", errors="replace")
		except OSError:
			continue
		graph.files[normalized] = _build_file_index(normalized, code)
		graph.file_mtimes[normalized] = mtime_ns

	stale_paths = set(graph.files) - seen_paths
	for stale_path in stale_paths:
		graph.files.pop(stale_path, None)
		graph.file_mtimes.pop(stale_path, None)


def _consume_balanced_segment(text: str, start_index: int, opener: str, closer: str) -> int | None:
	depth = 0
	state = "default"
	index = start_index
	while index < len(text):
		ch = text[index]
		nxt = text[index + 1] if index + 1 < len(text) else ""

		if state == "line_comment":
			if ch == "\n":
				state = "default"
			index += 1
			continue

		if state == "block_comment":
			if ch == "*" and nxt == "/":
				index += 2
				state = "default"
				continue
			index += 1
			continue

		if state in {"single", "double", "template"}:
			if ch == "\\" and index + 1 < len(text):
				index += 2
				continue
			if state == "single" and ch == "'":
				state = "default"
			elif state == "double" and ch == '"':
				state = "default"
			elif state == "template" and ch == "`":
				state = "default"
			index += 1
			continue

		if ch == "/" and nxt == "/":
			state = "line_comment"
			index += 2
			continue
		if ch == "/" and nxt == "*":
			state = "block_comment"
			index += 2
			continue
		if ch == "'":
			state = "single"
			index += 1
			continue
		if ch == '"':
			state = "double"
			index += 1
			continue
		if ch == "`":
			state = "template"
			index += 1
			continue

		if ch == opener:
			depth += 1
		elif ch == closer:
			depth -= 1
			if depth == 0:
				return index
		index += 1
	return None


def _consume_statement_end(text: str, start_index: int) -> int:
	paren_depth = 0
	bracket_depth = 0
	brace_depth = 0
	state = "default"
	seen_non_whitespace = False
	index = start_index
	while index < len(text):
		ch = text[index]
		nxt = text[index + 1] if index + 1 < len(text) else ""

		if state == "line_comment":
			if ch == "\n":
				state = "default"
				return index
			index += 1
			continue

		if state == "block_comment":
			if ch == "*" and nxt == "/":
				index += 2
				state = "default"
				continue
			index += 1
			continue

		if state in {"single", "double", "template"}:
			if ch == "\\" and index + 1 < len(text):
				index += 2
				continue
			if state == "single" and ch == "'":
				state = "default"
			elif state == "double" and ch == '"':
				state = "default"
			elif state == "template" and ch == "`":
				state = "default"
			index += 1
			continue

		if ch == "/" and nxt == "/":
			state = "line_comment"
			index += 2
			continue
		if ch == "/" and nxt == "*":
			state = "block_comment"
			index += 2
			continue
		if ch == "'":
			state = "single"
			index += 1
			continue
		if ch == '"':
			state = "double"
			index += 1
			continue
		if ch == "`":
			state = "template"
			index += 1
			continue

		if ch == "(":
			paren_depth += 1
			seen_non_whitespace = True
		elif ch == ")":
			paren_depth = max(paren_depth - 1, 0)
			seen_non_whitespace = True
		elif ch == "[":
			bracket_depth += 1
			seen_non_whitespace = True
		elif ch == "]":
			bracket_depth = max(bracket_depth - 1, 0)
			seen_non_whitespace = True
		elif ch == "{":
			brace_depth += 1
			seen_non_whitespace = True
		elif ch == "}":
			brace_depth = max(brace_depth - 1, 0)
			seen_non_whitespace = True
		elif ch == ";" and not (paren_depth or bracket_depth or brace_depth):
			return index
		elif ch == "\n" and seen_non_whitespace and not (paren_depth or bracket_depth or brace_depth):
			return index
		elif not ch.isspace():
			seen_non_whitespace = True
		index += 1
	return len(text)


def _extract_param_names(raw_params: str) -> tuple[str, ...]:
	text = raw_params.strip()
	if text.startswith("(") and text.endswith(")"):
		text = text[1:-1]
	names: list[str] = []
	for part in split_top_level_args(text):
		candidate = part.strip()
		if not candidate:
			continue
		if candidate.startswith("..."):
			candidate = candidate[3:].strip()
		if "=" in candidate:
			candidate = candidate.split("=", 1)[0].strip()
		if candidate.startswith("{") or candidate.startswith("["):
			continue
		if _SIMPLE_NAME_RE.fullmatch(candidate):
			names.append(candidate)
	return tuple(names)


def _find_identifier_value(text: str) -> str | None:
	candidate = text.strip()
	if _SIMPLE_NAME_RE.fullmatch(candidate):
		return candidate
	return None


def _resolve_relative_import(current_file: str, source: str) -> str | None:
	if not source.startswith(("./", "../")):
		return None
	base = Path(current_file).resolve(strict=False).parent
	raw_target = (base / source).resolve(strict=False)
	if raw_target.suffix in _JS_EXTENSIONS and raw_target.exists():
		return _normalize_path(raw_target)

	candidates = [raw_target.with_suffix(ext) for ext in _JS_EXTENSIONS]
	candidates.extend(Path(f"{raw_target}{ext}") for ext in _JS_EXTENSIONS)
	candidates.extend((raw_target / f"index{ext}") for ext in _JS_EXTENSIONS)
	for candidate in candidates:
		if candidate.exists():
			return _normalize_path(candidate)
	if raw_target.suffix:
		return _normalize_path(raw_target)
	return None


def _parse_named_bindings(bindings_text: str) -> list[tuple[str, str]]:
	bindings: list[tuple[str, str]] = []
	for part in bindings_text.split(","):
		candidate = part.strip()
		if not candidate:
			continue
		if " as " in candidate:
			imported_name, local_name = [item.strip() for item in candidate.split(" as ", 1)]
			bindings.append((local_name, imported_name))
			continue
		if ":" in candidate:
			imported_name, local_name = [item.strip() for item in candidate.split(":", 1)]
			bindings.append((local_name, imported_name))
			continue
		bindings.append((candidate, candidate))
	return bindings


def _parse_imports(code: str, current_file: str) -> dict[str, JSImportBinding]:
	imports: dict[str, JSImportBinding] = {}

	for match in re.finditer(
		r"import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([^}]*)\}\s+from\s+[\"']([^\"']+)[\"']",
		code,
		re.S,
	):
		default_local, named_bindings, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		imports[default_local] = JSImportBinding(default_local, resolved, "default")
		for local_name, imported_name in _parse_named_bindings(named_bindings):
			imports[local_name] = JSImportBinding(local_name, resolved, imported_name)

	for match in re.finditer(r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+[\"']([^\"']+)[\"']", code):
		local_name, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		imports[local_name] = JSImportBinding(local_name, resolved, "*", is_namespace=True)

	for match in re.finditer(r"import\s+\{([^}]*)\}\s+from\s+[\"']([^\"']+)[\"']", code, re.S):
		named_bindings, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		for local_name, imported_name in _parse_named_bindings(named_bindings):
			imports[local_name] = JSImportBinding(local_name, resolved, imported_name)

	for match in re.finditer(r"import\s+([A-Za-z_$][\w$]*)\s+from\s+[\"']([^\"']+)[\"']", code):
		local_name, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		imports[local_name] = JSImportBinding(local_name, resolved, "default")

	for match in re.finditer(
		r"(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)",
		code,
		re.S,
	):
		named_bindings, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		for local_name, imported_name in _parse_named_bindings(named_bindings):
			imports[local_name] = JSImportBinding(local_name, resolved, imported_name)

	for match in re.finditer(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*[\"']([^\"']+)[\"']\s*\)", code):
		local_name, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		imports[local_name] = JSImportBinding(local_name, resolved, "*", is_namespace=True)

	return imports


def _parse_function_matches(
	code: str,
	masked: str,
	pattern: re.Pattern[str],
	*,
	exported_name: str | None = None,
	anonymous_default_name: str | None = None,
) -> dict[str, JsFunctionDef]:
	functions: dict[str, JsFunctionDef] = {}
	for match in pattern.finditer(masked):
		name = match.groupdict().get("name") or anonymous_default_name or "default"
		params = _extract_param_names(match.group("params"))
		brace_index = masked.find("{", match.start())
		if brace_index < 0:
			continue
		close_brace = _consume_balanced_segment(code, brace_index, "{", "}")
		if close_brace is None:
			continue
		line = code.count("\n", 0, match.start()) + 1
		body = code[brace_index + 1:close_brace]
		functions[name] = JsFunctionDef(
			name=name,
			params=params,
			body=body,
			line=line,
			file_path="",
		)
	return functions


def _parse_functions(code: str, file_path: str) -> dict[str, JsFunctionDef]:
	masked = mask_js_text(code)
	raw_functions: dict[str, JsFunctionDef] = {}
	for pattern, anonymous_default_name in (
		(_FUNCTION_DECL_RE, "default"),
		(_ARROW_ASSIGN_RE, None),
		(_FUNCTION_ASSIGN_RE, None),
		(_EXPORTS_FUNCTION_RE, None),
		(_EXPORTS_ARROW_RE, None),
		(_MODULE_EXPORT_FUNCTION_RE, "default"),
		(_MODULE_EXPORT_ARROW_RE, "default"),
	):
		for name, function_def in _parse_function_matches(
			code,
			masked,
			pattern,
			anonymous_default_name=anonymous_default_name,
		).items():
			raw_functions[name] = JsFunctionDef(
				name=function_def.name,
				params=function_def.params,
				body=function_def.body,
				line=function_def.line,
				file_path=file_path,
					lookup_key=function_def.name,
			)
	return raw_functions


def _normalize_type_name(raw_type: str) -> str:
	text = raw_type.strip()
	for separator in ("<", "[", "|"):
		if separator in text:
			text = text.split(separator, 1)[0].strip()
	return text.split(".")[-1].strip()


def _parse_constructor_bindings(raw_params: str, body: str) -> dict[str, str]:
	property_types: dict[str, str] = {}
	param_types: dict[str, str] = {}
	for part in split_top_level_args(raw_params):
		candidate = part.strip()
		if not candidate:
			continue
		if "=" in candidate:
			candidate = candidate.split("=", 1)[0].strip()
		property_match = _CONSTRUCTOR_PROPERTY_RE.match(candidate)
		if property_match:
			property_types[property_match.group("name")] = _normalize_type_name(property_match.group("type"))
			continue
		param_match = _TYPED_PARAM_RE.match(candidate)
		if param_match:
			param_types[param_match.group("name")] = _normalize_type_name(param_match.group("type"))

	for match in _THIS_ASSIGN_RE.finditer(body):
		property_name = match.group("prop")
		value = match.group("value").strip()
		if value.startswith("new "):
			property_types[property_name] = _normalize_type_name(value[4:])
			continue
		if value in param_types:
			property_types[property_name] = param_types[value]
	return property_types


def _parse_class_methods(code: str, file_path: str) -> tuple[dict[str, JsClassDef], dict[str, JsFunctionDef]]:
	masked = mask_js_text(code)
	classes: dict[str, JsClassDef] = {}
	method_functions: dict[str, JsFunctionDef] = {}

	for class_match in _CLASS_RE.finditer(masked):
		class_name = class_match.group("name")
		class_brace_index = masked.find("{", class_match.end() - 1)
		if class_brace_index < 0:
			continue
		class_close = _consume_balanced_segment(code, class_brace_index, "{", "}")
		if class_close is None:
			continue
		code[class_brace_index + 1:class_close]
		class_body_masked = masked[class_brace_index + 1:class_close]
		class_line = code.count("\n", 0, class_match.start()) + 1
		property_types: dict[str, str] = {}
		for field_match in _CLASS_FIELD_RE.finditer(class_body_masked):
			property_types[field_match.group("name")] = _normalize_type_name(field_match.group("type"))

		methods: dict[str, JsFunctionDef] = {}
		for method_match in _CLASS_METHOD_RE.finditer(class_body_masked):
			method_name = method_match.group("name")
			absolute_brace = class_brace_index + 1 + method_match.end() - 1
			method_close = _consume_balanced_segment(code, absolute_brace, "{", "}")
			if method_close is None:
				continue
			method_start = class_brace_index + 1 + method_match.start()
			method_line = code.count("\n", 0, method_start) + 1
			method_body = code[absolute_brace + 1:method_close]
			if method_name == "constructor":
				property_types.update(_parse_constructor_bindings(method_match.group("params"), method_body))
				continue
			lookup_key = f"{class_name}.{method_name}"
			function_def = JsFunctionDef(
				name=method_name,
				params=_extract_param_names(method_match.group("params")),
				body=method_body,
				line=method_line,
				file_path=file_path,
				lookup_key=lookup_key,
				owner_class=class_name,
			)
			methods[method_name] = function_def
			method_functions[lookup_key] = function_def

		classes[class_name] = JsClassDef(
			name=class_name,
			methods=methods,
			property_types=property_types,
			line=class_line,
			file_path=file_path,
		)

	return classes, method_functions


def _make_local_export(export_name: str, local_name: str) -> JSExportBinding:
	return JSExportBinding(export_name=export_name, local_name=local_name)


def _make_reexport(export_name: str, source: str, imported_name: str, *, is_namespace: bool = False) -> JSExportBinding:
	return JSExportBinding(
		export_name=export_name,
		source=source,
		imported_name=imported_name,
		is_namespace=is_namespace,
	)


def _parse_exports(
	code: str,
	*,
	functions: dict[str, JsFunctionDef],
	classes: dict[str, JsClassDef],
	imports: dict[str, JSImportBinding],
	current_file: str,
) -> tuple[dict[str, JSExportBinding], tuple[str, ...]]:
	exports: dict[str, JSExportBinding] = {}
	export_stars: list[str] = []
	top_level_functions = {name for name, function_def in functions.items() if not function_def.owner_class}

	for match in _FUNCTION_DECL_RE.finditer(code):
		prefix = match.groupdict().get("prefix") or ""
		name = match.groupdict().get("name") or "default"
		if prefix.startswith("export default") and name in top_level_functions:
			exports["default"] = _make_local_export("default", name)
		elif prefix.startswith("export") and name in top_level_functions:
			exports[name] = _make_local_export(name, name)

	for pattern in (_ARROW_ASSIGN_RE, _FUNCTION_ASSIGN_RE):
		for match in pattern.finditer(code):
			prefix = match.groupdict().get("prefix") or ""
			name = match.group("name")
			if prefix.startswith("export") and name in top_level_functions:
				exports[name] = _make_local_export(name, name)

	for match in _CLASS_RE.finditer(code):
		prefix = match.groupdict().get("prefix") or ""
		name = match.group("name")
		if prefix.startswith("export default") and name in classes:
			exports["default"] = _make_local_export("default", name)
		elif prefix.startswith("export") and name in classes:
			exports[name] = _make_local_export(name, name)

	for match in _EXPORT_NAMED_FROM_RE.finditer(code):
		bindings_text, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if not resolved:
			continue
		for export_name, source_name in _parse_named_bindings(bindings_text):
			exports[export_name] = _make_reexport(export_name, resolved, source_name)

	for match in _EXPORT_STAR_AS_RE.finditer(code):
		export_name, source = match.groups()
		resolved = _resolve_relative_import(current_file, source)
		if resolved:
			exports[export_name] = _make_reexport(export_name, resolved, "*", is_namespace=True)

	for match in _EXPORT_STAR_FROM_RE.finditer(code):
		resolved = _resolve_relative_import(current_file, match.group(1))
		if resolved:
			export_stars.append(resolved)

	for match in re.finditer(r"export\s*\{([^}]*)\}\s*(?!\s*from\b)", code, re.S):
		for export_name, local_name in _parse_named_bindings(match.group(1)):
			if local_name in top_level_functions or local_name in classes:
				exports[export_name] = _make_local_export(export_name, local_name)
				continue
			binding = imports.get(local_name)
			if binding:
				exports[export_name] = _make_reexport(
					export_name,
					binding.source,
					binding.imported_name,
					is_namespace=binding.is_namespace,
				)

	for match in re.finditer(r"(?:(?:module\.)?exports\.)([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)", code):
		export_name, local_name = match.groups()
		if local_name in top_level_functions or local_name in classes:
			exports[export_name] = _make_local_export(export_name, local_name)
			continue
		binding = imports.get(local_name)
		if binding:
			exports[export_name] = _make_reexport(export_name, binding.source, binding.imported_name, is_namespace=binding.is_namespace)

	for match in re.finditer(r"module\.exports\s*=\s*([A-Za-z_$][\w$]*)", code):
		local_name = match.group(1)
		if local_name in top_level_functions or local_name in classes:
			exports["default"] = _make_local_export("default", local_name)
			continue
		binding = imports.get(local_name)
		if binding:
			exports["default"] = _make_reexport("default", binding.source, binding.imported_name, is_namespace=binding.is_namespace)

	for match in re.finditer(r"module\.exports\s*=\s*(\{[\s\S]*?\})", code):
		try:
			object_exports = parse_object_literal(match.group(1))
		except Exception:  # noqa: BLE001
			continue
		for export_name, raw_value in object_exports.items():
			local_name = _find_identifier_value(raw_value) or export_name
			if local_name in top_level_functions or local_name in classes:
				exports[export_name] = _make_local_export(export_name, local_name)
				continue
			binding = imports.get(local_name)
			if binding:
				exports[export_name] = _make_reexport(export_name, binding.source, binding.imported_name, is_namespace=binding.is_namespace)

	if "default" in top_level_functions and "default" not in exports:
		exports["default"] = _make_local_export("default", "default")

	return exports, tuple(dict.fromkeys(export_stars))


def _build_file_index(file_path: str, code: str) -> JsFileIndex:
	imports = _parse_imports(code, file_path)
	functions = _parse_functions(code, file_path)
	classes, method_functions = _parse_class_methods(code, file_path)
	functions.update(method_functions)
	exports, export_stars = _parse_exports(
		code,
		functions=functions,
		classes=classes,
		imports=imports,
		current_file=file_path,
	)
	return JsFileIndex(
		file_path=file_path,
		code=code,
		functions=functions,
		classes=classes,
		exports=exports,
		export_stars=export_stars,
		imports=imports,
	)


def _iter_related_sources(file_index: JsFileIndex) -> tuple[str, ...]:
	sources = [binding.source for binding in file_index.imports.values()]
	sources.extend(binding.source for binding in file_index.exports.values() if binding.source)
	sources.extend(file_index.export_stars)
	return tuple(dict.fromkeys(source for source in sources if source))


def build_js_project_index(filename: str, code: str, *, fast: bool = False) -> JsProjectIndex | None:
	"""Build a JS project index for cross-file analysis.

	When ``fast=True`` (recommended for single-file scans), skips the
	expensive ``os.walk()`` workspace graph refresh and builds a minimal
	project containing only the current file and its direct imports.

	The ``fast`` flag is automatically enabled when the workspace contains
	more than 500 JS files or the filename is a basename-only string
	(which cannot resolve to a workspace root anyway).
	"""
	if not filename:
		return None
	if detect_minified(filename, code).is_minified:
		return None
	current_file = _normalize_path(filename)
	if not Path(current_file).is_file():
		return None
	workspace_root = _discover_workspace_root(current_file)

	# ── Fast path: single-file scan (no os.walk) ──────────────────────
	if not fast:
		# Auto-detect large workspaces — if the root has >500 JS files,
		# skip the expensive workspace refresh to avoid hangs.
		try:
			js_count = sum(1 for _ in _iter_workspace_js_files(Path(workspace_root)))
		except OSError:
			js_count = 9999
		if js_count > 500:
			fast = True

	if fast:
		# Minimal project: only the current file + direct imports
		project = JsProjectIndex(files={}, workspace_root=workspace_root)
		project.files[current_file] = _build_file_index(current_file, code)
		for source in _iter_related_sources(project.files[current_file]):
			if source not in project.files:
				_index_project_file(project, source, depth=0)
		return project

	# ── Full path: workspace-aware cross-file analysis ────────────────
	workspace_graph = _get_workspace_graph(workspace_root)
	project = JsProjectIndex(files=dict(workspace_graph.files), workspace_root=workspace_root)
	project.files[current_file] = _build_file_index(current_file, code)
	for source in _iter_related_sources(project.files[current_file]):
		if source not in project.files:
			_index_project_file(project, source, depth=0)
	return project


def _index_project_file(project: JsProjectIndex, file_path: str, *, code: str | None = None, depth: int) -> None:
	normalized = _normalize_path(file_path)
	if normalized in project.files or depth > 12:
		return

	if code is None:
		try:
			code = Path(normalized).read_text(encoding="utf-8", errors="replace")
		except OSError:
			return

	file_index = _build_file_index(normalized, code)
	project.files[normalized] = file_index

	for source in _iter_related_sources(file_index):
		_index_project_file(project, source, depth=depth + 1)


def _extract_call_aliases(code: str) -> dict[str, str]:
	aliases: dict[str, str] = {}
	for line in code.splitlines():
		stripped = strip_comments(line).strip()
		if not stripped:
			continue
		match = _CALL_ALIAS_RE.match(stripped)
		if not match:
			continue
		aliases[match.group("name")] = match.group("target")
	return aliases


def _normalize_callee_alias(callee: str, aliases: dict[str, str]) -> str:
	candidate = callee.strip()
	if candidate in aliases:
		return aliases[candidate]
	if "." not in candidate:
		return candidate
	head, tail = candidate.split(".", 1)
	if head in aliases:
		return f"{aliases[head]}.{tail}"
	return candidate


def _resolve_class_method(
	project: JsProjectIndex,
	file_path: str,
	class_name: str,
	method_name: str,
) -> tuple[str, JsFunctionDef] | None:
	resolved_class = resolve_js_class(project, file_path, class_name)
	if not resolved_class:
		return None
	resolved_file, class_def = resolved_class
	function_def = class_def.methods.get(method_name)
	if function_def:
		return (resolved_file, function_def)
	return None


def _resolve_class_property_method(
	project: JsProjectIndex,
	file_path: str,
	class_name: str,
	property_name: str,
	method_name: str,
) -> tuple[str, JsFunctionDef] | None:
	resolved_class = resolve_js_class(project, file_path, class_name)
	if not resolved_class:
		return None
	_, class_def = resolved_class
	target_class_name = class_def.property_types.get(property_name)
	if not target_class_name:
		return None
	return _resolve_class_method(project, file_path, target_class_name, method_name)


def resolve_js_class(
	project: JsProjectIndex | None,
	file_path: str,
	class_name: str,
	*,
	visited: set[tuple[str, str]] | None = None,
) -> tuple[str, JsClassDef] | None:
	if not project:
		return None
	normalized_file = _normalize_path(file_path)
	file_index = project.files.get(normalized_file)
	if not file_index:
		return None
	if visited is None:
		visited = set()
	key = (normalized_file, class_name)
	if key in visited:
		return None
	visited.add(key)

	if class_name in file_index.classes:
		return (normalized_file, file_index.classes[class_name])

	binding = file_index.imports.get(class_name)
	if binding:
		return _resolve_import_class_binding(project, binding, visited=visited)

	if "." in class_name:
		head, tail = class_name.split(".", 1)
		namespace_binding = file_index.imports.get(head)
		if namespace_binding and namespace_binding.is_namespace:
			return _resolve_exported_class(project, namespace_binding.source, tail.split(".", 1)[0], visited=visited)

	return None


def resolve_js_function(
	project: JsProjectIndex | None,
	file_path: str,
	callee: str,
	*,
	context_class: str | None = None,
) -> tuple[str, JsFunctionDef] | None:
	if not project:
		return None
	normalized_file = _normalize_path(file_path)
	file_index = project.files.get(normalized_file)
	if not file_index:
		return None

	normalized_callee = callee.strip()
	if context_class and normalized_callee.startswith("this."):
		parts = normalized_callee.split(".")
		if len(parts) == 2:
			resolved_method = _resolve_class_method(project, normalized_file, context_class, parts[1])
			if resolved_method:
				return resolved_method
		elif len(parts) >= 3:
			resolved_property_method = _resolve_class_property_method(project, normalized_file, context_class, parts[1], parts[2])
			if resolved_property_method:
				return resolved_property_method

	if normalized_callee in file_index.functions:
		return (normalized_file, file_index.functions[normalized_callee])

	direct_binding = file_index.imports.get(normalized_callee)
	if direct_binding:
		return _resolve_import_function_binding(project, direct_binding)

	if "." in normalized_callee:
		head, tail = normalized_callee.split(".", 1)
		binding = file_index.imports.get(head)
		if binding and binding.is_namespace:
			export_name = tail.split(".", 1)[0]
			return _resolve_exported_function(project, binding.source, export_name)

	short_name = normalized_callee.split(".")[-1]
	if short_name in file_index.functions:
		return (normalized_file, file_index.functions[short_name])
	return None


def _resolve_import_function_binding(project: JsProjectIndex, binding: JSImportBinding) -> tuple[str, JsFunctionDef] | None:
	if binding.is_namespace:
		return _resolve_exported_function(project, binding.source, "default")
	return _resolve_exported_function(project, binding.source, binding.imported_name)


def _resolve_import_class_binding(
	project: JsProjectIndex,
	binding: JSImportBinding,
	*,
	visited: set[tuple[str, str]] | None = None,
) -> tuple[str, JsClassDef] | None:
	if binding.is_namespace:
		return _resolve_exported_class(project, binding.source, "default", visited=visited)
	return _resolve_exported_class(project, binding.source, binding.imported_name, visited=visited)


def _resolve_exported_function(
	project: JsProjectIndex,
	file_path: str,
	export_name: str,
	visited: set[tuple[str, str]] | None = None,
) -> tuple[str, JsFunctionDef] | None:
	normalized = _normalize_path(file_path)
	file_index = project.files.get(normalized)
	if not file_index:
		return None
	if visited is None:
		visited = set()
	key = (normalized, export_name)
	if key in visited:
		return None
	visited.add(key)

	binding = file_index.exports.get(export_name)
	if binding:
		if binding.local_name:
			local_function = file_index.functions.get(binding.local_name)
			if local_function and not local_function.owner_class:
				return (normalized, local_function)
			import_binding = file_index.imports.get(binding.local_name)
			if import_binding:
				return _resolve_import_function_binding(project, import_binding)
		if binding.source:
			if binding.is_namespace:
				return _resolve_exported_function(project, binding.source, "default", visited=visited)
			return _resolve_exported_function(project, binding.source, binding.imported_name or export_name, visited=visited)

	local_function = file_index.functions.get(export_name)
	if local_function and not local_function.owner_class:
		return (normalized, local_function)

	for source in file_index.export_stars:
		resolved = _resolve_exported_function(project, source, export_name, visited=visited)
		if resolved:
			return resolved
	return None


def _resolve_exported_class(
	project: JsProjectIndex,
	file_path: str,
	export_name: str,
	*,
	visited: set[tuple[str, str]] | None = None,
) -> tuple[str, JsClassDef] | None:
	normalized = _normalize_path(file_path)
	file_index = project.files.get(normalized)
	if not file_index:
		return None
	if visited is None:
		visited = set()
	key = (normalized, export_name)
	if key in visited:
		return None
	visited.add(key)

	binding = file_index.exports.get(export_name)
	if binding:
		if binding.local_name:
			local_class = file_index.classes.get(binding.local_name)
			if local_class:
				return (normalized, local_class)
			import_binding = file_index.imports.get(binding.local_name)
			if import_binding:
				return _resolve_import_class_binding(project, import_binding, visited=visited)
		if binding.source:
			if binding.is_namespace:
				return _resolve_exported_class(project, binding.source, "default", visited=visited)
			return _resolve_exported_class(project, binding.source, binding.imported_name or export_name, visited=visited)

	local_class = file_index.classes.get(export_name)
	if local_class:
		return (normalized, local_class)

	for source in file_index.export_stars:
		resolved = _resolve_exported_class(project, source, export_name, visited=visited)
		if resolved:
			return resolved
	return None


def summarize_js_function(
	project: JsProjectIndex | None,
	file_path: str,
	function_name: str,
	*,
	global_graph: object | None = None,
	visited: set[tuple[str, str]] | None = None,
) -> FunctionSummary:
	if not project:
		return FunctionSummary()

	normalized_file = _normalize_path(file_path)
	cache_key = (normalized_file, function_name)
	if cache_key in project.summaries:
		return project.summaries[cache_key]

	if visited is None:
		visited = set()
	if cache_key in visited:
		return FunctionSummary()
	visited.add(cache_key)

	file_index = project.files.get(normalized_file)
	if not file_index:
		return FunctionSummary()

	function_def = file_index.functions.get(function_name)
	if not function_def:
		return FunctionSummary()

	effects: list[HelperEffect] = []
	return_effects: list[ReturnEffect] = []
	depends_on: set[str] = set()
	verifies_auth = bool(VERIFICATION_CALL_RE.search(function_def.body))
	privilege_guard = _body_has_privilege_guard(function_def.body)
	ownership_guard = _body_has_ownership_guard(function_def.body)
	call_aliases = _extract_call_aliases(function_def.body)
	nested_calls = collect_calls(function_def.body)
	return_expressions = _collect_return_expressions(function_def.body, base_line=function_def.line)

	for param_index, param_name in enumerate(function_def.params):
		param_source_re = re.compile(
			rf"\b{re.escape(param_name)}\.(?:params|query|body|headers|cookies)(?:\.[A-Za-z_$][\w$]*)?\b",
			re.IGNORECASE,
		)
		initial_traces = {
			param_name: (TraceFrame(kind="source", label=f"parameter `{param_name}`", line=function_def.line),),
		}
		taint_traces = extract_taint_traces(
			function_def.body,
			line_offset=function_def.line - 1,
			initial_traces=initial_traces,
			direct_source_re=param_source_re,
		)
		effects.extend(_direct_effects_for_param(
			function_def, param_index, taint_traces,
			file_code=file_index.code,
			file_path=file_index.file_path,
		))

		for return_line, return_expr in return_expressions:
			wrapper_sanitizer_labels = tuple(
				frame.label
				for frame in sanitizer_frames_for_expr(return_expr, line=return_line)
				if frame.kind == "sanitizer"
			)
			return_calls = collect_calls(return_expr)
			pure_return_call = len(return_calls) == 1 and _is_pure_call_expression(return_expr, return_calls[0])
			if not pure_return_call and trace_for_expr(
				return_expr,
				taint_traces,
				line=return_line,
				direct_source_re=param_source_re,
			):
				return_effects.append(
					ReturnEffect(
						param_index,
						source_suffix=_parameter_source_suffix(return_expr, param_name),
						sanitizer_labels=wrapper_sanitizer_labels,
					)
				)
			for return_call in return_calls:
				normalized_return_callee = _normalize_callee_alias(return_call.callee, call_aliases)
				resolved_return = resolve_js_function(
					project,
					normalized_file,
					normalized_return_callee,
					context_class=function_def.owner_class or None,
				)
				if not resolved_return:
					continue
				resolved_return_file, resolved_return_function = resolved_return
				depends_on.add(f"{_normalize_path(resolved_return_file)}::{resolved_return_function.lookup_key or resolved_return_function.name}")
				nested_return_summary = summarize_js_function(
					project,
					resolved_return_file,
					resolved_return_function.lookup_key or resolved_return_function.name,
					global_graph=global_graph,
					visited=visited,
				)
				for nested_return in nested_return_summary.return_effects:
					if nested_return.param_index >= len(return_call.arguments):
						continue
					if not trace_for_expr(
						return_call.arguments[nested_return.param_index],
						taint_traces,
						line=return_line,
						direct_source_re=param_source_re,
					):
						continue
					return_effects.append(
						ReturnEffect(
							param_index,
							source_suffix=nested_return.source_suffix,
							helper_chain=(f"through `{normalized_return_callee}()`",) + nested_return.helper_chain,
							sanitizer_labels=tuple(dict.fromkeys(wrapper_sanitizer_labels + nested_return.sanitizer_labels)),
						)
					)

		for call in nested_calls:
			normalized_callee = _normalize_callee_alias(call.callee, call_aliases)
			resolved = resolve_js_function(
				project,
				normalized_file,
				normalized_callee,
				context_class=function_def.owner_class or None,
			)
			if not resolved:
				continue
			nested_file, nested_function = resolved
			depends_on.add(f"{_normalize_path(nested_file)}::{nested_function.lookup_key or nested_function.name}")
			nested_summary = summarize_js_function(
				project,
				nested_file,
				nested_function.lookup_key or nested_function.name,
				global_graph=global_graph,
				visited=visited,
			)
			if nested_summary.verifies_auth:
				verifies_auth = True
			if nested_summary.privilege_guard:
				privilege_guard = True
			if nested_summary.ownership_guard:
				ownership_guard = True
			for effect in nested_summary.effects:
				if effect.param_index >= len(call.arguments):
					continue
				argument_trace = trace_for_expr(
					call.arguments[effect.param_index],
					taint_traces,
					line=function_def.line + call.line - 1,
					direct_source_re=param_source_re,
				)
				if not argument_trace:
					continue
				if trace_has_sanitizer(argument_trace, effect.kind):
					continue
				helper_chain = (f"through `{normalized_callee}()`",) + effect.helper_chain
				effects.append(HelperEffect(effect.kind, param_index, effect.sink_label, helper_chain))

	summary = FunctionSummary(
		effects=_dedup_effects(effects),
		return_effects=_dedup_return_effects(return_effects),
		verifies_auth=verifies_auth,
		privilege_guard=privilege_guard,
		ownership_guard=ownership_guard,
	)
	project.summaries[cache_key] = summary
	if global_graph is not None and hasattr(global_graph, "record_function_summary"):
		try:
			from guardmarly.ir.global_graph import FunctionSummary as GraphFunctionSummary

			arg_sink_indexes = tuple(sorted({effect.param_index for effect in summary.effects}))
			arg_return_indexes = tuple(sorted({effect.param_index for effect in summary.return_effects}))
			global_graph.record_function_summary(GraphFunctionSummary(
				file_path=normalized_file,
				function_name=function_name,
				args_to_sink=arg_sink_indexes,
				args_to_return=arg_return_indexes,
				return_from_source=any(bool(effect.source_suffix) for effect in summary.return_effects),
				side_effect_symbols=(),
				depends_on=tuple(sorted(depends_on)),
			))
		except Exception:
			pass
	return summary


def _collect_return_expressions(body: str, *, base_line: int) -> list[tuple[int, str]]:
	matches: list[tuple[int, str]] = []
	masked = mask_js_text(body)
	for match in _RETURN_RE.finditer(masked):
		start = match.end()
		while start < len(body) and body[start].isspace():
			start += 1
		if start >= len(body) or body[start] == ";":
			continue
		end = _consume_statement_end(body, start)
		expr = body[start:end].strip()
		if not expr:
			continue
		line = base_line + body.count("\n", 0, match.start())
		matches.append((line, expr))
	return matches


def _unwrap_await(expr: str) -> str:
	text = expr.strip()
	if text.startswith("await "):
		return text[6:].strip()
	return text


def _is_pure_call_expression(expr: str, call) -> bool:
	return _unwrap_await(expr) == call.raw.strip()


def _parameter_source_suffix(expr: str, param_name: str) -> str:
	match = re.search(rf"\b{re.escape(param_name)}((?:\.[A-Za-z_$][\w$]*)+)\b", expr)
	return match.group(1) if match else ""


def _trace_helper_return_expression(
	project: JsProjectIndex | None,
	file_path: str,
	expr: str,
	taint_traces: dict[str, tuple[TraceFrame, ...]],
	*,
	line: int,
	global_graph: object | None = None,
) -> tuple[TraceFrame, ...]:
	if not project:
		return ()
	traces: list[tuple[TraceFrame, ...]] = []
	for call in collect_calls(expr):
		resolved = resolve_js_function(project, file_path, call.callee)
		if not resolved:
			continue
		resolved_file, function_def = resolved
		summary = summarize_js_function(
			project,
			resolved_file,
			function_def.lookup_key or function_def.name,
			global_graph=global_graph,
		)
		# Arg indexes whose return flow is already covered by the GlobalGraph IFDS
		# path below.  We skip them in the local return_effects loop to prevent
		# emitting duplicate parallel traces for the same data-flow edge.
		globally_handled_arg_indexes: set[int] = set()
		if global_graph is not None and hasattr(global_graph, "propagate_js_call_facts"):
			tainted_arg_indexes: set[int] = set()
			for idx, argument in enumerate(call.arguments):
				argument_trace = trace_for_expr(argument, taint_traces, line=line) or request_object_trace(argument, line=line)
				if argument_trace:
					tainted_arg_indexes.add(idx)
			try:
				_, _, ret_hit, return_trace = global_graph.propagate_js_call_facts(
					caller_file=file_path,
					callee_file=resolved_file,
					callee_name=function_def.lookup_key or function_def.name,
					tainted_arg_indexes=tainted_arg_indexes,
					call_line=line,
					call_string=(),
					call_string_k=_DEFAULT_IFDS_CALL_STRING_K,
				)
				if ret_hit and return_trace:
					trace = append_trace(return_trace, "helper", f"through `{call.callee}()`", line=line)
					traces.append(trace)
					# Determine which specific arg indexes GlobalGraph handled so
					# we can delegate return-flow authority to it for those args.
					try:
						gs = global_graph.get_function_summary(
							resolved_file,
							function_def.lookup_key or function_def.name,
						)
						if gs is not None:
							globally_handled_arg_indexes = tainted_arg_indexes & set(gs.args_to_return)
					except Exception:
						pass
			except Exception:
				pass
		for return_effect in summary.return_effects:
			if return_effect.param_index in globally_handled_arg_indexes:
				# GlobalGraph IFDS already emitted an authoritative trace for
				# this arg — skip local analysis to prevent a duplicate trace.
				continue
			if return_effect.param_index >= len(call.arguments):
				continue
			argument = call.arguments[return_effect.param_index]
			argument_trace = trace_for_expr(argument, taint_traces, line=line)
			if not argument_trace:
				argument_trace = _effect_source_trace(argument, return_effect, line=line)
			if not argument_trace:
				argument_trace = request_object_trace(argument, line=line)
			if not argument_trace:
				continue
			trace = append_trace(argument_trace, "helper", f"through `{call.callee}()`", line=line)
			for helper_label in return_effect.helper_chain:
				trace = append_trace(trace, "helper", helper_label, line=line)
			for sanitizer_label in return_effect.sanitizer_labels:
				trace = append_trace(trace, "sanitizer", sanitizer_label, line=line)
			if expr.strip() != call.raw.strip():
				trace = append_trace(trace, "propagator", f"via `{expr[:80]}`", line=line)
			traces.append(trace)
	return merge_traces(*traces)


def _effect_source_trace(argument: str, return_effect: ReturnEffect, *, line: int) -> tuple[TraceFrame, ...]:
	if not return_effect.source_suffix:
		return ()
	candidate = argument.strip()
	if not _SIMPLE_NAME_RE.fullmatch(candidate):
		return ()
	return (TraceFrame(kind="source", label=f"source `{candidate}{return_effect.source_suffix}`", line=line),)


def propagate_helper_return_traces(
	project: JsProjectIndex | None,
	file_path: str,
	code: str,
	taint_traces: dict[str, tuple[TraceFrame, ...]],
	*,
	line_offset: int = 0,
	global_graph: object | None = None,
) -> dict[str, tuple[TraceFrame, ...]]:
	if not project or not file_path:
		return taint_traces

	propagated = dict(taint_traces)
	for _ in range(4):
		changed = False
		for lineno, line in enumerate(code.splitlines(), 1 + line_offset):
			stripped = strip_comments(line).strip()
			if not stripped or COMMENT_LINE_RE.match(stripped):
				continue
			match = _ASSIGNMENT_RE.match(stripped)
			if not match:
				continue
			target, expr = match.groups()
			if target in propagated:
				continue
			trace = _trace_helper_return_expression(
				project,
				file_path,
				expr,
				propagated,
				line=lineno,
				global_graph=global_graph,
			)
			if not trace:
				continue
			trace = append_trace(trace, "propagator", f"assign to `{target}`", line=lineno)
			propagated[target] = trace
			changed = True
		if not changed:
			break
	return propagated


def _direct_effects_for_param(
	function_def: JsFunctionDef,
	param_index: int,
	taint_traces: dict[str, tuple[TraceFrame, ...]],
	*,
	file_code: str = "",
	file_path: str = "",
) -> list[HelperEffect]:
	# Auto-load full file code if not provided but file_path is known
	# This ensures file-level destructured imports (const { open } = require('fs'))
	# are visible to is_fs_callee even when the project index is unavailable.
	if not file_code and file_path:
		try:
			file_code = Path(file_path).read_text(encoding="utf-8", errors="replace")
		except Exception:
			pass

	effects: list[HelperEffect] = []
	resource_aliases: set[str] = set()
	base_line = function_def.line - 1

	for call in collect_calls(function_def.body):
		call_line = base_line + call.line
		arg0 = call.arguments[0] if call.arguments else ""
		short_name = call.callee.split(".")[-1]
		arg0_trace = trace_for_expr(arg0, taint_traces, line=call_line) if arg0 else ()

		if call.callee in {"res.redirect", "reply.redirect"} and arg0_trace and not trace_has_sanitizer(arg0_trace, "redirect"):
			sink_label = "sink `reply.redirect()`" if call.callee == "reply.redirect" else "sink `res.redirect()`"
			effects.append(HelperEffect("redirect", param_index, sink_label))

		# ── Ambiguous callee guard for open/openSync ──────────────
		# These match XMLHttpRequest.open(), modals.open(), etc.
		if short_name in {"open", "openSync"}:
			if is_fs_callee(call.callee, code=file_code or function_def.body) and arg0_trace and not trace_has_sanitizer(arg0_trace, "path"):
				effects.append(HelperEffect("path", param_index, "sink `fs/path operation`"))
		elif short_name in PATH_CALLEE_PARTS and arg0_trace and not trace_has_sanitizer(arg0_trace, "path"):
			effects.append(HelperEffect("path", param_index, "sink `fs/path operation`"))

		if call.callee in SSRF_CALLEES or short_name in {item.split(".")[-1] for item in SSRF_CALLEES}:
			if arg0_trace and not trace_has_sanitizer(arg0_trace, "ssrf"):
				effects.append(HelperEffect("ssrf", param_index, "sink `HTTP client call`"))

		if short_name in LOOKUP_CALLEE_PARTS and arg0_trace:
			effects.append(HelperEffect("lookup", param_index, f"resource lookup `{call.raw[:80]}`"))
			lhs_match = re.match(r"\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", call.raw)
			if lhs_match:
				resource_aliases.add(lhs_match.group(1))

		if short_name in MUTATION_CALLEE_PARTS:
			if any(trace_for_expr(argument, taint_traces, line=call_line) for argument in call.arguments):
				effects.append(HelperEffect("mutation", param_index, f"mutation `{call.raw[:80]}`"))
			instance_name = call.callee.split(".", 1)[0]
			if instance_name in resource_aliases or instance_name in taint_traces:
				effects.append(HelperEffect("mutation", param_index, f"mutation `{call.raw[:80]}`"))

	return effects


def _body_has_privilege_guard(body: str) -> bool:
	aliases = _extract_principal_aliases(body)
	return any(_line_has_privilege_guard(line, aliases) for line in body.splitlines())


def _body_has_ownership_guard(body: str) -> bool:
	aliases = _extract_principal_aliases(body)
	return any(_line_has_owner_guard(line, aliases) for line in body.splitlines())


def _extract_principal_aliases(code: str) -> set[str]:
	aliases: set[str] = set()
	assignment_re = re.compile(r"(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$")
	for line in code.splitlines():
		match = assignment_re.match(line.strip())
		if not match:
			continue
		target, expr = match.groups()
		if PRINCIPAL_REF_RE.search(expr):
			aliases.add(target)
	return aliases


def _line_has_privilege_guard(line: str, principal_aliases: set[str]) -> bool:
	stripped = line.strip()
	if not stripped or not PRIVILEGE_KEY_RE.search(stripped):
		return False
	has_principal = bool(PRINCIPAL_REF_RE.search(stripped))
	if not has_principal:
		has_principal = any(re.search(rf"\b{re.escape(alias)}\b", stripped) for alias in principal_aliases)
	if not has_principal:
		return False
	return bool(re.search(r"\bif\b|403|forbid|throw|return\b", stripped, re.IGNORECASE) or any(op in stripped for op in ("===", "!==", "==", "!=")))


def _line_has_owner_guard(line: str, principal_aliases: set[str]) -> bool:
	stripped = line.strip()
	if not stripped or not OWNERSHIP_KEY_RE.search(stripped):
		return False
	has_principal = bool(PRINCIPAL_REF_RE.search(stripped))
	if not has_principal:
		has_principal = any(re.search(rf"\b{re.escape(alias)}\b", stripped) for alias in principal_aliases)
	if not has_principal:
		return False
	return bool(re.search(r"\bif\b|where\s*:|filter|findOne|findUnique|findFirst|403|forbid|throw", stripped, re.IGNORECASE) or any(op in stripped for op in ("===", "!==", "==", "!=")))


def _dedup_effects(effects: list[HelperEffect]) -> tuple[HelperEffect, ...]:
	seen: set[tuple[str, int, str, tuple[str, ...]]] = set()
	unique: list[HelperEffect] = []
	for effect in effects:
		key = (effect.kind, effect.param_index, effect.sink_label, effect.helper_chain)
		if key in seen:
			continue
		seen.add(key)
		unique.append(effect)
	return tuple(unique)


def _dedup_return_effects(effects: list[ReturnEffect]) -> tuple[ReturnEffect, ...]:
	seen: set[tuple[int, str, tuple[str, ...], tuple[str, ...]]] = set()
	unique: list[ReturnEffect] = []
	for effect in effects:
		key = (effect.param_index, effect.source_suffix, effect.helper_chain, effect.sanitizer_labels)
		if key in seen:
			continue
		seen.add(key)
		unique.append(effect)
	return tuple(unique)


def request_object_trace(argument: str, *, line: int) -> tuple[TraceFrame, ...]:
	candidate = argument.strip()
	if not REQUEST_OBJECT_ARG_RE.match(candidate):
		return ()
	return (TraceFrame(kind="source", label=f"request object `{candidate}`", line=line),)
