from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ansede_static._types import Finding, Severity, TraceFrame
from ansede_static.js_engine.common import COMMENT_LINE_RE, strip_comments
from ansede_static.js_engine.project import (
    build_js_project_index,
    propagate_helper_return_traces,
    request_object_trace,
    resolve_js_function,
    summarize_js_function,
)
from ansede_static.js_engine.structure import collect_calls, mask_js_text, parse_object_literal, split_top_level_args
from ansede_static.js_engine.taint import append_trace, extract_taint_traces, merge_traces, trace_for_expr

_DIRECT_ROUTE_METHODS = {
    "get": "get",
    "post": "post",
    "put": "put",
    "patch": "patch",
    "delete": "delete",
    "del": "delete",
    "all": "all",
    "head": "head",
    "options": "options",
}
_NEST_ROUTE_DECORATORS = {
    "Get": "get",
    "Post": "post",
    "Put": "put",
    "Patch": "patch",
    "Delete": "delete",
    "All": "all",
    "Head": "head",
    "Options": "options",
}
_NEXT_ROUTE_METHOD_RE = r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_ROUTE_PARAM_RE = re.compile(r':([A-Za-z_$][\w$]*)')
_RESOURCE_PARAM_RE = re.compile(r'(?:^|_)(?:id|uid|pk|slug)$|(?:Id|Uid|Pk|Slug)$', re.IGNORECASE)
_AUTH_MIDDLEWARE_RE = re.compile(
    r'requireAuth|authMiddleware|isAuthenticated|isLoggedIn|passport\.authenticate|'
    r'verifyToken|checkAuth|ensureAuth|jwtAuth|requireLogin|'
    r'request\.jwtVerify|jwtVerify|fastify\.authenticate|koaJwt|koa-jwt|ctx\.isAuthenticated|'
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'requireRole|hasRole|checkRole|requirePermission|checkPermission|hasPermission|'
    r'AuthGuard|JwtAuthGuard|SessionGuard|UseGuards|withAuth|requireSession|requireUser|getServerSession',
    re.IGNORECASE,
)
_PRIVILEGE_MIDDLEWARE_RE = re.compile(
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'superuserOnly|rootOnly|requireRole|hasRole|checkRole|requirePermission|'
    r'checkPermission|hasPermission|authorizeRole|permissionMiddleware|'
    r'RolesGuard|PermissionsGuard|ScopesGuard|RoleGuard|PermissionGuard|Roles\s*\(|Permissions\s*\(',
    re.IGNORECASE,
)
_OWNERSHIP_KEY_RE = re.compile(
    r'ownerId|userId|accountId|tenantId|authorId|createdBy|organizationId|orgId',
    re.IGNORECASE,
)
_PRINCIPAL_REF_RE = re.compile(
    r'(?:req|request)\.(?:user|auth)|res\.locals\.user|reply\.locals\.user|currentUser|session\.user|'
    r'(?:req|request)\.session\.(?:user|auth)|(?:req|request)\.session\[\s*["\']user(?:Id)?["\']\s*\]|'
    r'ctx\.state\.user|context\.state\.user|event\.locals\.user|locals\.user|c\.get\(\s*["\']user["\']\s*\)',
    re.IGNORECASE,
)
_LOOKUP_SINK_RE = re.compile(
    r'findByPk\s*\(|findById\s*\(|findOne\s*\(|findUnique\s*\(|findFirst\s*\(|'
    r'select\s+.+\bwhere\b',
    re.IGNORECASE,
)
_DIRECT_MUTATION_SINK_RE = re.compile(
    r'destroy\s*\(|update\s*\(|deleteOne\s*\(|remove\s*\(|'
    r'findByIdAndUpdate\s*\(|findByIdAndDelete\s*\(|findOneAndUpdate\s*\(|'
    r'findOneAndDelete\s*\(|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b',
    re.IGNORECASE,
)
_INSTANCE_MUTATION_RE = re.compile(r'\b([A-Za-z_$][\w$]*)\s*\.\s*(destroy|save|remove|update)\s*\(', re.IGNORECASE)
_PUBLIC_ROUTE_RE = re.compile(
    r'/(?:login|signin|sign-in|signup|sign-up|register|authenticate|forgot|reset|callback|'
    r'logout|health|ping|status|healthz|ready|readiness|liveness|docs|swagger|openapi|'
    r'public|home|about|terms|privacy|favicon|robots|version)(?:/|$)',
    re.IGNORECASE,
)
_ADMIN_ROUTE_RE = re.compile(r'/(?:admin|internal|staff|superuser|root)(?:/|$)', re.IGNORECASE)
_PRIVILEGE_KEY_RE = re.compile(r'admin|staff|superuser|root|role|permission|scope|acl|rbac', re.IGNORECASE)
_CREDENTIAL_NAME_RE = re.compile(
    r'authoriz|auth|token|jwt|session|cookie|bearer|api[_-]?key|apikey|credential',
    re.IGNORECASE,
)
_CREDENTIAL_SOURCE_RE = re.compile(
    r'\b(?:req|request)\.(?:headers|cookies|query|body)\b|request\.headers\.get\s*\([^)]*\)|ctx\.request\.(?:headers|body)',
    re.IGNORECASE,
)
_VERIFICATION_CALL_RE = re.compile(
    r'jwt\.verify|verifyToken|checkAuth|validateToken|decodeToken|passport\.authenticate|'
    r'loadUser|findByToken|authenticate|authorize|requireRole|checkPermission|hasPermission|hasRole|'
    r'request\.jwtVerify|ctx\.isAuthenticated|ctx\.state\.user|'
    r'getServerSession|verifyIdToken|validateSession|lucia\.validateSession|supabase\.auth\.getUser|'
    r'auth\s*\(|requireSession|requireUser',
    re.IGNORECASE,
)
_DISABLED_AUTH_RE = re.compile(r'^\s*(?:false|null|undefined|0)\s*$', re.IGNORECASE)
_ROLEISH_OPTION_RE = re.compile(r'role|permission|scope|admin|staff|root|superuser', re.IGNORECASE)
_ROUTE_OPTION_FIELDS = (
    'preHandler',
    'preValidation',
    'onRequest',
    'beforeHandler',
    'middleware',
    'middlewares',
    'auth',
    'role',
    'permission',
    'scope',
    'options',
    'config',
    'pre',
    'guards',
)
_SIMPLE_IDENTIFIER_RE = re.compile(r'^\s*[A-Za-z_$][\w$]*\s*$')

_NEST_CLASS_RE = re.compile(
    r'(?P<decorators>(?:\s*@[^\n]+\n)*)\s*(?:export\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)\s*\{',
    re.MULTILINE,
)
_NEST_METHOD_RE = re.compile(
    r'(?P<decorators>(?:\s*@[^\n]+\n)*)\s*(?:(?:public|private|protected|static|readonly|async)\s+)*'
    r'(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*\{',
    re.MULTILINE,
)
_NEXT_FUNCTION_ROUTE_RE = re.compile(
    rf'export\s+(?:async\s+)?function\s+(?P<method>{_NEXT_ROUTE_METHOD_RE})\s*\((?P<params>[^)]*)\)\s*\{{',
    re.MULTILINE,
)
_NEXT_ARROW_ROUTE_RE = re.compile(
    rf'export\s+const\s+(?P<method>{_NEXT_ROUTE_METHOD_RE})\s*=\s*(?:async\s*)?(?P<params>\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{{',
    re.MULTILINE,
)
_FASTIFY_REGISTER_RE = re.compile(
    r'(?P<instance>[A-Za-z_$][\w$]*)\.register\s*\(\s*(?:async\s*)?(?:function\s*\([^)]*\)|\((?P<params>[^)]*)\)\s*=>)\s*\{',
    re.MULTILINE,
)


@dataclass(frozen=True)
class RouteBlock:
    method: str
    path: str
    start_line: int
    end_line: int
    invocation: str
    invocation_parts: tuple[str, ...]
    body: str
    source_kind: str
    class_name: str = ''


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



def _string_literal_value(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return None



def _normalize_method(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    literal = _string_literal_value(text)
    if literal:
        return literal.lower()
    if text.startswith('[') and text.endswith(']'):
        match = re.search(r'["\']([A-Za-z]+)["\']', text)
        if match:
            return match.group(1).lower()
    bare = re.match(r'^[A-Za-z]+$', text)
    if bare:
        return bare.group(0).lower()
    return None


def _normalize_direct_method(value: str) -> str | None:
    return _DIRECT_ROUTE_METHODS.get(value.lower())


def _join_route_path(prefix: str | None, suffix: str | None) -> str:
    def _clean(part: str | None) -> str:
        if part is None:
            return ''
        literal = _string_literal_value(part) or part.strip()
        if literal in {'', '/'}:
            return ''
        return literal.strip('/')

    parts = [_clean(prefix), _clean(suffix)]
    segments = [part for part in parts if part]
    return '/' + '/'.join(segments) if segments else '/'


def _ambient_route_parts(
    code: str,
    *,
    router_prefixes: dict[str, tuple[str, ...]] | None = None,
) -> tuple[tuple[str | None, tuple[str, ...]], ...]:
    entries: list[tuple[str | None, tuple[str, ...]]] = []
    router_prefixes = router_prefixes or {}
    for call in collect_calls(code):
        if call.callee.split('.')[-1].lower() != 'use' or not call.arguments:
            continue
        prefix = _string_literal_value(call.arguments[0])
        if prefix and prefix.startswith('/'):
            invocation_parts = tuple(argument for argument in call.arguments[1:] if argument.strip())
            receiver = call.callee.rsplit('.', 1)[0].strip() if '.' in call.callee else ''
            base_prefixes = router_prefixes.get(receiver, ('',)) if receiver else ('',)
            for base_prefix in base_prefixes:
                entries.append((_join_route_path(base_prefix, prefix), invocation_parts))
        else:
            prefix = None
            invocation_parts = tuple(argument for argument in call.arguments if argument.strip())
            if invocation_parts:
                entries.append((prefix, invocation_parts))
    return tuple(entries)


def _ambient_invocation_parts(path: str, ambient_parts: tuple[tuple[str | None, tuple[str, ...]], ...]) -> tuple[str, ...]:
    labels: list[str] = []
    for prefix, invocation_parts in ambient_parts:
        if prefix is None:
            labels.extend(invocation_parts)
            continue
        normalized_prefix = prefix.rstrip('/') or '/'
        if path == normalized_prefix or path.startswith(normalized_prefix + '/'):
            labels.extend(invocation_parts)
    return tuple(labels)


def _decorator_lines(text: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in text.splitlines() if line.strip().startswith('@'))


def _controller_prefix_from_decorators(text: str) -> str:
    match = re.search(r'@Controller\s*(?:\((?P<arg>[^)]*)\))?', text)
    if not match:
        return ''
    raw = (match.group('arg') or '').strip()
    if not raw:
        return ''
    literal = _string_literal_value(raw)
    return literal if literal is not None else raw


def _nest_route_from_decorators(text: str) -> tuple[str | None, str]:
    for decorator_name, method in _NEST_ROUTE_DECORATORS.items():
        match = re.search(rf'@{decorator_name}\s*(?:\((?P<arg>[^)]*)\))?', text)
        if not match:
            continue
        raw = (match.group('arg') or '').strip()
        if not raw:
            return method, ''
        literal = _string_literal_value(raw)
        return method, literal if literal is not None else raw
    return None, ''


def _normalize_next_segment(segment: str) -> str:
    if segment.startswith('[[...') and segment.endswith(']]'):
        return ':' + segment[5:-2]
    if segment.startswith('[...') and segment.endswith(']'):
        return ':' + segment[4:-1]
    if segment.startswith('[') and segment.endswith(']'):
        return ':' + segment[1:-1]
    return segment


def _next_route_path_from_filename(filename: str) -> str | None:
    if not filename:
        return None
    file_path = Path(filename)
    parts = list(file_path.parts)
    lowered_parts = [part.lower() for part in parts]

    if file_path.stem == 'route' and 'app' in lowered_parts:
        root_index = lowered_parts.index('app')
        route_parts = parts[root_index + 1:-1]
    elif 'pages' in lowered_parts:
        root_index = lowered_parts.index('pages')
        if root_index + 1 >= len(parts) or lowered_parts[root_index + 1] != 'api':
            return None
        route_parts = parts[root_index + 1:]
        if route_parts:
            stem = Path(route_parts[-1]).stem
            route_parts[-1] = '' if stem == 'index' else stem
    else:
        return None

    segments = [
        _normalize_next_segment(part)
        for part in route_parts
        if part and not (part.startswith('(') and part.endswith(')')) and not part.startswith('@')
    ]
    cleaned = [segment for segment in segments if segment]
    return '/' + '/'.join(cleaned) if cleaned else '/'


def _build_next_route_blocks(code: str, *, filename: str) -> list[RouteBlock]:
    route_path = _next_route_path_from_filename(filename)
    if not route_path:
        return []

    blocks: list[RouteBlock] = []
    for pattern in (_NEXT_FUNCTION_ROUTE_RE, _NEXT_ARROW_ROUTE_RE):
        for match in pattern.finditer(code):
            method = match.group('method').lower()
            brace_index = code.find('{', match.end() - 1)
            if brace_index < 0:
                continue
            close_brace = _consume_balanced_segment(code, brace_index, '{', '}')
            if close_brace is None:
                continue
            start_line = code.count('\n', 0, match.start()) + 1
            blocks.append(RouteBlock(
                method=method,
                path=route_path,
                start_line=start_line,
                end_line=start_line + code[match.start():close_brace + 1].count('\n'),
                invocation=f"next file route `{route_path}` method `{method.upper()}`",
                invocation_parts=(f"next file route `{route_path}`",),
                body=code[brace_index + 1:close_brace],
                source_kind='next-file-route',
                class_name='',
            ))
    return blocks


def _build_nest_route_blocks(code: str) -> list[RouteBlock]:
    blocks: list[RouteBlock] = []
    for class_match in _NEST_CLASS_RE.finditer(code):
        class_name = class_match.group('name')
        class_decorators = class_match.group('decorators') or ''
        class_brace_index = code.find('{', class_match.end() - 1)
        if class_brace_index < 0:
            continue
        class_close = _consume_balanced_segment(code, class_brace_index, '{', '}')
        if class_close is None:
            continue
        class_body = code[class_brace_index + 1:class_close]
        controller_prefix = _controller_prefix_from_decorators(class_decorators)
        class_invocation_parts = _decorator_lines(class_decorators)

        for method_match in _NEST_METHOD_RE.finditer(class_body):
            method_decorators = method_match.group('decorators') or ''
            method, method_path = _nest_route_from_decorators(method_decorators)
            if not method:
                continue
            absolute_brace = class_brace_index + 1 + method_match.end() - 1
            method_close = _consume_balanced_segment(code, absolute_brace, '{', '}')
            if method_close is None:
                continue
            start_index = class_brace_index + 1 + method_match.start()
            start_line = code.count('\n', 0, start_index) + 1
            invocation_parts = class_invocation_parts + _decorator_lines(method_decorators)
            path = _join_route_path(controller_prefix, method_path)
            blocks.append(RouteBlock(
                method=method,
                path=path,
                start_line=start_line,
                end_line=start_line + code[start_index:method_close + 1].count('\n'),
                invocation='\n'.join(invocation_parts),
                invocation_parts=invocation_parts,
                body=code[absolute_brace + 1:method_close],
                source_kind='nest-decorator-route',
                class_name=class_name,
            ))
    return blocks


def _build_fastify_prefixed_route_blocks(code: str) -> list[RouteBlock]:
    blocks: list[RouteBlock] = []
    for match in _FASTIFY_REGISTER_RE.finditer(code):
        body_open = code.find('{', match.end() - 1)
        if body_open < 0:
            continue
        body_close = _consume_balanced_segment(code, body_open, '{', '}')
        if body_close is None:
            continue

        after_body = code[body_close + 1:]
        options_match = re.match(r'\s*,\s*\{(?P<opts>[^}]*)\}', after_body)
        prefix = ''
        if options_match:
            opts = options_match.group('opts')
            prefix_match = re.search(r'\bprefix\s*:\s*(?P<val>["\'][^"\']+["\'])', opts)
            if prefix_match:
                literal = _string_literal_value(prefix_match.group('val'))
                if literal:
                    prefix = literal

        register_body = code[body_open + 1:body_close]
        instance = match.group('instance')
        params = (match.group('params') or '').strip()
        instance_alias = params.split(',')[0].strip() if params else ''
        if not instance_alias:
            instance_alias = instance

        for call in collect_calls(register_body):
            callee = call.callee
            if not callee.startswith(instance_alias + '.'):
                continue
            method = _normalize_direct_method(callee.split('.')[-1])
            if not method or not call.arguments:
                continue
            local_path = _string_literal_value(call.arguments[0])
            if not local_path:
                continue
            route_path = _join_route_path(prefix, local_path)
            start_line = code.count('\n', 0, body_open + 1) + call.line
            invocation_parts = tuple(arg for arg in call.arguments[1:-1] if arg.strip())
            blocks.append(RouteBlock(
                method=method,
                path=route_path,
                start_line=start_line,
                end_line=start_line + call.raw.count('\n'),
                invocation='\n'.join(invocation_parts),
                invocation_parts=invocation_parts,
                body=_handler_text_from_args(call.arguments[1:]) or call.raw,
                source_kind='fastify-register-route',
                class_name='',
            ))
    return blocks



def _handler_text_from_args(args: tuple[str, ...]) -> str:
    if not args:
        return ''
    candidate = args[-1].strip()
    if '=>' in candidate or candidate.startswith('function') or candidate.startswith('async ') or '{' in candidate:
        return candidate
    return candidate



def _flatten_route_parts(route_props: dict[str, str]) -> tuple[str, ...]:
    parts: list[str] = []
    for field in _ROUTE_OPTION_FIELDS:
        value = route_props.get(field)
        if value:
            parts.append(f"{field}: {value}")
            if field in {'options', 'config'}:
                try:
                    nested = parse_object_literal(value)
                except Exception:  # noqa: BLE001
                    nested = {}
                for nested_field in ('auth', 'pre', 'scope', 'role', 'roles', 'permission', 'permissions', 'middleware', 'middlewares', 'guards'):
                    nested_value = nested.get(nested_field)
                    if nested_value:
                        parts.append(f"{nested_field}: {nested_value}")
    return tuple(parts)



def _simple_helper_name(expr: str) -> str | None:
    candidate = expr.strip()
    if _SIMPLE_IDENTIFIER_RE.fullmatch(candidate):
        return candidate
    calls = collect_calls(candidate)
    if calls and calls[0].raw.strip() == candidate:
        return calls[0].callee
    return None


def _callee_receiver(callee: str) -> str | None:
    if '.' not in callee:
        return None
    return callee.rsplit('.', 1)[0].strip() or None


def _mount_target_identifiers(args: tuple[str, ...]) -> tuple[str, ...]:
    names: list[str] = []
    if len(args) < 2:
        return ()
    for arg in args[1:]:
        helper_name = _simple_helper_name(arg)
        if helper_name:
            names.append(helper_name)
            continue
        text = arg.strip()
        if text.startswith('[') and text.endswith(']'):
            for item in split_top_level_args(text[1:-1]):
                item_name = _simple_helper_name(item)
                if item_name:
                    names.append(item_name)
    return tuple(dict.fromkeys(names))


def _router_mount_prefixes(code: str) -> dict[str, tuple[str, ...]]:
    """Infer mount prefixes for router variables from `.use('/prefix', router)` calls."""
    prefixes: dict[str, tuple[str, ...]] = {}
    changed = True
    while changed:
        changed = False
        for call in collect_calls(code):
            if call.callee.split('.')[-1].lower() != 'use' or not call.arguments:
                continue
            mount_prefix = _string_literal_value(call.arguments[0])
            if not mount_prefix or not mount_prefix.startswith('/'):
                continue

            receiver = _callee_receiver(call.callee)
            receiver_prefixes = prefixes.get(receiver, ('',)) if receiver else ('',)
            targets = _mount_target_identifiers(call.arguments)
            if not targets:
                continue

            for target in targets:
                combined: set[str] = set(prefixes.get(target, ()))
                for base_prefix in receiver_prefixes:
                    combined.add(_join_route_path(base_prefix, mount_prefix))
                normalized = tuple(sorted(prefix for prefix in combined if prefix))
                if normalized != prefixes.get(target, ()): 
                    prefixes[target] = normalized
                    changed = True
    return prefixes



def _helper_candidates_from_part(expr: str) -> tuple[str, ...]:
    candidate = expr.strip()
    if ':' in candidate:
        candidate = candidate.split(':', 1)[1].strip()
    if candidate.startswith('[') and candidate.endswith(']'):
        names: list[str] = []
        for item in split_top_level_args(candidate[1:-1]):
            helper_name = _simple_helper_name(item)
            if helper_name:
                names.append(helper_name)
        return tuple(names)
    helper_name = _simple_helper_name(candidate)
    return (helper_name,) if helper_name else ()



def _block_helper_entries(
    block: RouteBlock,
    *,
    filename: str,
    project,
) -> list[tuple[str, object, int]]:
    if not project or not filename:
        return []
    entries: list[tuple[str, object, int]] = []
    seen: set[tuple[str, int]] = set()

    for part in block.invocation_parts:
        for helper_name in _helper_candidates_from_part(part):
            resolved = resolve_js_function(project, filename, helper_name, context_class=block.class_name or None)
            if not resolved:
                continue
            resolved_file, function_def = resolved
            summary = summarize_js_function(project, resolved_file, function_def.lookup_key or function_def.name)
            key = (helper_name, block.start_line)
            if key in seen:
                continue
            seen.add(key)
            entries.append((helper_name, summary, block.start_line))

    for call in collect_calls(block.body):
        helper_name = call.callee
        resolved = resolve_js_function(project, filename, helper_name, context_class=block.class_name or None)
        if not resolved:
            continue
        resolved_file, function_def = resolved
        summary = summarize_js_function(project, resolved_file, function_def.lookup_key or function_def.name)
        line = block.start_line + call.line - 1
        key = (helper_name, line)
        if key in seen:
            continue
        seen.add(key)
        entries.append((helper_name, summary, line))

    helper_name = _simple_helper_name(block.body)
    if helper_name:
        resolved = resolve_js_function(project, filename, helper_name, context_class=block.class_name or None)
        if resolved:
            resolved_file, function_def = resolved
            summary = summarize_js_function(project, resolved_file, function_def.lookup_key or function_def.name)
            key = (helper_name, block.start_line)
            if key not in seen:
                entries.append((helper_name, summary, block.start_line))

    return entries



def _route_helper_labels(
    block: RouteBlock,
    *,
    filename: str,
    project,
    attr: str,
    prefix: str,
) -> tuple[str, ...]:
    labels: list[str] = []
    for helper_name, summary, _ in _block_helper_entries(block, filename=filename, project=project):
        if getattr(summary, attr, False):
            labels.append(f"{prefix} `{helper_name}`")
    return tuple(dict.fromkeys(labels))



def _helper_request_param_trace(argument: str, *, resource_params: set[str], route_line: int, line_no: int) -> tuple[TraceFrame, ...] | None:
    candidate = argument.strip()
    if candidate not in {'req', 'request'}:
        return None
    trace: tuple[TraceFrame, ...] = request_object_trace(candidate, line=line_no)
    for param in sorted(resource_params):
        trace = append_trace(trace, 'source', f"resource parameter `{param}`", line=route_line)
    return trace



def _helper_route_effect_traces(
    block: RouteBlock,
    *,
    filename: str,
    project,
    resource_params: set[str],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    effect_kind: str,
) -> list[tuple[int, str, tuple[TraceFrame, ...], tuple[str, ...], str]]:
    if not project or not filename:
        return []
    helper_hits: list[tuple[int, str, tuple[TraceFrame, ...], tuple[str, ...], str]] = []

    candidate_calls = collect_calls(block.body)
    helper_name = _simple_helper_name(block.body)
    if helper_name:
        synthetic_calls = collect_calls(f"{helper_name}(request, reply)")
        if synthetic_calls:
            candidate_calls.extend(synthetic_calls)

    for call in candidate_calls:
        helper_line = block.start_line + call.line - 1
        resolved = resolve_js_function(project, filename, call.callee, context_class=block.class_name or None)
        if not resolved:
            continue
        resolved_file, function_def = resolved
        summary = summarize_js_function(project, resolved_file, function_def.lookup_key or function_def.name)
        for effect in summary.effects:
            if effect.kind != effect_kind or effect.param_index >= len(call.arguments):
                continue
            argument = call.arguments[effect.param_index]
            trace = trace_for_expr(argument, taint_traces, line=helper_line)
            if not trace:
                ref = _find_route_resource_reference(
                    argument,
                    resource_params=resource_params,
                    taint_traces=taint_traces,
                    line_no=helper_line,
                    route_line=block.start_line,
                )
                if ref:
                    trace = ref[1]
            if not trace:
                trace = _helper_request_param_trace(
                    argument,
                    resource_params=resource_params,
                    route_line=block.start_line,
                    line_no=helper_line,
                )
            if not trace:
                continue
            helper_hits.append((helper_line, call.callee, trace, effect.helper_chain, effect.sink_label))
    return helper_hits

def _build_route_blocks(code: str, *, filename: str = '') -> list[RouteBlock]:
    blocks: list[RouteBlock] = []
    router_prefixes = _router_mount_prefixes(code)
    ambient_parts = _ambient_route_parts(code, router_prefixes=router_prefixes)
    for call in collect_calls(code):
        short = call.callee.split('.')[-1].lower()
        direct_method = _normalize_direct_method(short)
        if direct_method and call.arguments:
            path = _string_literal_value(call.arguments[0])
            if not path:
                continue
            invocation_args = call.arguments[:-1] if len(call.arguments) > 1 else call.arguments
            receiver = _callee_receiver(call.callee)
            effective_paths = (
                tuple(_join_route_path(prefix, path) for prefix in router_prefixes.get(receiver, ()))
                if receiver and receiver in router_prefixes
                else (path,)
            )
            for effective_path in effective_paths:
                blocks.append(RouteBlock(
                    method=direct_method,
                    path=effective_path,
                    start_line=call.line,
                    end_line=call.line + call.raw.count('\n'),
                    invocation='\n'.join(invocation_args),
                    invocation_parts=_ambient_invocation_parts(effective_path, ambient_parts) + tuple(call.arguments[1:-1]),
                    body=_handler_text_from_args(call.arguments[1:]) or call.raw,
                    source_kind='call-route',
                    class_name='',
                ))
            continue

        if short != 'route' or not call.arguments:
            continue
        route_object = call.arguments[0].strip()
        if not route_object.startswith('{'):
            continue
        props = parse_object_literal(route_object)
        method = _normalize_method(props.get('method') or props.get('methods'))
        path = _string_literal_value(props.get('url') or props.get('path') or props.get('route'))
        if not method or not path:
            continue
        invocation_parts = _ambient_invocation_parts(path, ambient_parts) + _flatten_route_parts(props)
        invocation_lines = [f"part: {value}" for value in invocation_parts]
        handler_text = props.get('handler') or props.get('action') or props.get('controller') or route_object
        blocks.append(RouteBlock(
            method=method,
            path=path,
            start_line=call.line,
            end_line=call.line + call.raw.count('\n'),
            invocation='\n'.join(invocation_lines) or route_object,
            invocation_parts=invocation_parts,
            body=handler_text,
            source_kind='object-route',
            class_name='',
        ))
    blocks.extend(_build_nest_route_blocks(code))
    blocks.extend(_build_fastify_prefixed_route_blocks(code))
    if filename:
        blocks.extend(_build_next_route_blocks(code, filename=filename))
    return blocks



def _route_resource_params(path: str) -> set[str]:
    return {name for name in _ROUTE_PARAM_RE.findall(path) if _RESOURCE_PARAM_RE.search(name)}



def _auth_option_enabled(text: str) -> bool:
    match = re.search(r'\bauth\s*:\s*([^,\n}]+|\{[^}]*\})', text, re.IGNORECASE | re.DOTALL)
    if not match:
        return False
    value = match.group(1).strip()
    return not _DISABLED_AUTH_RE.match(value)



def _option_labels(text: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    labels: list[str] = []
    for match in pattern.finditer(text):
        label = match.group(0)
        if label not in labels:
            labels.append(label)
    return tuple(labels)


def _body_verification_labels(block: RouteBlock) -> tuple[str, ...]:
    labels: list[str] = []
    for match in _VERIFICATION_CALL_RE.finditer(block.body):
        label = f"handler verification `{match.group(0)}`"
        if label not in labels:
            labels.append(label)
    return tuple(labels)


def _route_invocation_text(block: RouteBlock) -> str:
    parts = list(block.invocation_parts)
    if block.invocation:
        parts.append(block.invocation)
    return '\n'.join(parts)



def _route_auth_labels(block: RouteBlock, *, filename: str = '', project=None) -> tuple[str, ...]:
    invocation_text = _route_invocation_text(block)
    labels = list(_option_labels(invocation_text, _AUTH_MIDDLEWARE_RE))
    if _auth_option_enabled(invocation_text) and 'auth option `auth`' not in labels:
        labels.append('auth option `auth`')
    labels.extend(_body_verification_labels(block))
    labels.extend(_route_helper_labels(block, filename=filename, project=project, attr='verifies_auth', prefix='auth helper'))
    return tuple(dict.fromkeys(labels))



def _route_privilege_labels(block: RouteBlock, *, filename: str = '', project=None) -> tuple[str, ...]:
    invocation_text = _route_invocation_text(block)
    labels = list(_option_labels(invocation_text, _PRIVILEGE_MIDDLEWARE_RE))
    if _ROLEISH_OPTION_RE.search(invocation_text) and _auth_option_enabled(invocation_text):
        labels.append('auth option `role`')
    labels.extend(_route_helper_labels(block, filename=filename, project=project, attr='privilege_guard', prefix='privilege helper'))
    return tuple(dict.fromkeys(labels))



def _is_public_route(path: str) -> bool:
    return bool(_PUBLIC_ROUTE_RE.search(path))



def _is_admin_route(path: str) -> bool:
    return bool(_ADMIN_ROUTE_RE.search(path))



def _route_base_trace(block: RouteBlock, resource_params: set[str], auth_labels: tuple[str, ...]) -> tuple[TraceFrame, ...]:
    trace: tuple[TraceFrame, ...] = ()
    trace = append_trace(trace, 'source', f"route `{block.path}` method `{block.method.upper()}`", line=block.start_line)
    for param in sorted(resource_params):
        trace = append_trace(trace, 'source', f"resource parameter `{param}`", line=block.start_line)
    for label in auth_labels:
        trace = append_trace(trace, 'check', f"auth middleware `{label}`", line=block.start_line)
    return trace



def _extract_principal_aliases(code: str) -> set[str]:
    aliases: set[str] = set()
    assignment_re = re.compile(r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$')
    for line in code.splitlines():
        stripped = strip_comments(line).strip()
        match = assignment_re.match(stripped)
        if not match:
            continue
        target, expr = match.groups()
        if _PRINCIPAL_REF_RE.search(expr):
            aliases.add(target)
    return aliases



def _line_has_owner_guard(line: str, principal_aliases: set[str]) -> bool:
    stripped = strip_comments(line).strip()
    if not stripped or not _OWNERSHIP_KEY_RE.search(stripped):
        return False
    has_principal = bool(_PRINCIPAL_REF_RE.search(stripped))
    if not has_principal:
        has_principal = any(re.search(rf'\b{re.escape(alias)}\b', stripped) for alias in principal_aliases)
    if not has_principal:
        return False
    has_structure = bool(re.search(r'\bif\b|where\s*:|filter|findOne|findUnique|findFirst|403|forbid|throw', stripped, re.IGNORECASE))
    has_compare = any(op in stripped for op in ('===', '!==', '==', '!='))
    return has_structure or has_compare



def _block_has_ownership_guard(block: RouteBlock, *, filename: str = '', project=None) -> bool:
    aliases = _extract_principal_aliases(block.body)
    if any(_line_has_owner_guard(line, aliases) for line in block.body.splitlines()):
        return True
    return any(summary.ownership_guard for _, summary, _ in _block_helper_entries(block, filename=filename, project=project))



def _line_has_privilege_guard(line: str, principal_aliases: set[str]) -> bool:
    stripped = strip_comments(line).strip()
    if not stripped or not _PRIVILEGE_KEY_RE.search(stripped):
        return False
    if _PRIVILEGE_MIDDLEWARE_RE.search(stripped):
        return True
    has_principal = bool(_PRINCIPAL_REF_RE.search(stripped))
    if not has_principal:
        has_principal = any(re.search(rf'\b{re.escape(alias)}\b', stripped) for alias in principal_aliases)
    if not has_principal:
        return False
    has_structure = bool(re.search(r'\bif\b|403|forbid|throw|return\b', stripped, re.IGNORECASE))
    has_compare = any(op in stripped for op in ('===', '!==', '==', '!='))
    return has_structure or has_compare



def _block_has_privilege_guard(block: RouteBlock, *, filename: str = '', project=None) -> bool:
    aliases = _extract_principal_aliases(block.body)
    if any(_line_has_privilege_guard(line, aliases) for line in block.body.splitlines()):
        return True
    return any(summary.privilege_guard for _, summary, _ in _block_helper_entries(block, filename=filename, project=project))



def _route_looks_sensitive(block: RouteBlock, resource_params: set[str]) -> bool:
    if _is_admin_route(block.path) or block.method in {'post', 'put', 'patch', 'delete'} or resource_params:
        return True
    for line in block.body.splitlines():
        stripped = strip_comments(line).strip()
        if not stripped:
            continue
        if _LOOKUP_SINK_RE.search(stripped) or _DIRECT_MUTATION_SINK_RE.search(stripped):
            return True
    return False



def _extract_credential_traces(block: RouteBlock) -> dict[str, tuple[TraceFrame, ...]]:
    traces: dict[str, tuple[TraceFrame, ...]] = {}
    assignment_re = re.compile(r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$')
    lines = block.body.splitlines()
    for _ in range(3):
        changed = False
        for lineno, line in enumerate(lines, block.start_line):
            stripped = strip_comments(line).strip()
            if not stripped or COMMENT_LINE_RE.match(stripped):
                continue
            match = assignment_re.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if target in traces:
                continue
            if _CREDENTIAL_SOURCE_RE.search(expr) and _CREDENTIAL_NAME_RE.search(expr + ' ' + target):
                traces[target] = (
                    TraceFrame(kind='source', label=f"credential source `{expr[:80]}`", line=lineno),
                    TraceFrame(kind='propagator', label=f"assign to `{target}`", line=lineno),
                )
                changed = True
                continue
            if not _CREDENTIAL_NAME_RE.search(target):
                continue
            referenced = [name for name in traces if re.search(rf'\b{re.escape(name)}\b', expr)]
            if not referenced:
                continue
            trace = traces[referenced[0]]
            if re.search(r'\b\w+\s*\(', expr):
                trace = append_trace(trace, 'helper', f"through `{expr[:80]}`", line=lineno)
            else:
                trace = append_trace(trace, 'propagator', f"via `{expr[:80]}`", line=lineno)
            trace = append_trace(trace, 'propagator', f"assign to `{target}`", line=lineno)
            traces[target] = trace
            changed = True
        if not changed:
            break
    return traces



def _presence_only_gate(
    line: str,
    *,
    line_no: int,
    credential_traces: dict[str, tuple[TraceFrame, ...]],
) -> tuple[str, tuple[TraceFrame, ...]] | None:
    stripped = strip_comments(line).strip()
    if not stripped or not stripped.startswith('if'):
        return None
    alias_match = re.search(r'\bif\s*\(\s*(!?\s*([A-Za-z_$][\w$]*))\s*\)', stripped)
    if alias_match:
        alias = alias_match.group(2)
        if alias in credential_traces:
            return (f"if ({alias_match.group(1).strip()})", credential_traces[alias])
    direct_match = re.search(
        r'\bif\s*\(\s*(!?\s*((?:req|request)\.(?:headers|cookies|query|body)(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])))\s*\)',
        stripped,
        re.IGNORECASE,
    )
    if direct_match and _CREDENTIAL_NAME_RE.search(direct_match.group(2)):
        trace = (TraceFrame(kind='source', label=f"credential source `{direct_match.group(2)[:80]}`", line=line_no),)
        return (f"if ({direct_match.group(1).strip()})", trace)
    return None



def _first_presence_only_gate(block: RouteBlock) -> tuple[int, str, tuple[TraceFrame, ...]] | None:
    credential_traces = _extract_credential_traces(block)
    for lineno, line in enumerate(block.body.splitlines(), block.start_line):
        gate = _presence_only_gate(line, line_no=lineno, credential_traces=credential_traces)
        if gate:
            return (lineno, gate[0], gate[1])
    return None



def _block_has_verification(block: RouteBlock, *, filename: str = '', project=None) -> bool:
    if _VERIFICATION_CALL_RE.search(block.body):
        return True
    return any(summary.verifies_auth for _, summary, _ in _block_helper_entries(block, filename=filename, project=project))



def _trace_mentions_route_param(trace: tuple[TraceFrame, ...], resource_params: set[str]) -> bool:
    labels = ' '.join(frame.label.lower() for frame in trace)
    if 'req.params.' in labels or 'request.params.' in labels:
        return True
    return any(param.lower() in labels for param in resource_params)



def _find_route_resource_reference(
    line: str,
    *,
    resource_params: set[str],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    line_no: int,
    route_line: int,
) -> tuple[str, tuple[TraceFrame, ...]] | None:
    for param in sorted(resource_params):
        for prefix in ('req', 'request'):
            for source in ('params', 'query', 'body'):
                ref = f'{prefix}.{source}.{param}'
                if ref in line:
                    return (
                        ref,
                        (
                            TraceFrame(kind='source', label=f"resource parameter `{param}`", line=route_line),
                            TraceFrame(kind='propagator', label=f"direct use `{ref}`", line=line_no),
                        ),
                    )
        for ref in (f'params.{param}', f'context.params.{param}', f'ctx.params.{param}'):
            if ref in line:
                return (
                    ref,
                    (
                        TraceFrame(kind='source', label=f"resource parameter `{param}`", line=route_line),
                        TraceFrame(kind='propagator', label=f"direct use `{ref}`", line=line_no),
                    ),
                )
    for var, trace in taint_traces.items():
        if re.search(rf'\b{re.escape(var)}\b', line) and _trace_mentions_route_param(trace, resource_params):
            return (var, trace)
    return None



def _make_route_finding(
    *,
    severity: Severity,
    title: str,
    description: str,
    line: int,
    suggestion: str,
    cwe: str,
    rule_id: str,
    confidence: float,
    trace: tuple[TraceFrame, ...],
    agent: str,
    analysis_kind: str,
) -> Finding:
    return Finding(
        category='security',
        severity=severity,
        title=title,
        description=description,
        line=line,
        suggestion=suggestion,
        cwe=cwe,
        rule_id=rule_id,
        agent=agent,
        confidence=confidence,
        analysis_kind=analysis_kind,
        trace=trace,
    )



def _check_route_idor(code: str, *, agent: str, analysis_kind: str, filename: str = '', project=None) -> list[Finding]:
    findings: list[Finding] = []
    for block in _build_route_blocks(code, filename=filename):
        resource_params = _route_resource_params(block.path)
        if not resource_params:
            continue
        auth_labels = _route_auth_labels(block, filename=filename, project=project)
        has_auth = bool(auth_labels)
        if _block_has_ownership_guard(block, filename=filename, project=project):
            continue
        taint_traces = extract_taint_traces(block.body, line_offset=block.start_line - 1)
        if project and filename:
            taint_traces = propagate_helper_return_traces(
                project,
                filename,
                block.body,
                taint_traces,
                line_offset=block.start_line - 1,
            )
        base_trace = _route_base_trace(block, resource_params, auth_labels)

        for lineno, line in enumerate(block.body.splitlines(), block.start_line):
            stripped = strip_comments(line).strip()
            if not stripped or COMMENT_LINE_RE.match(stripped):
                continue
            if not _LOOKUP_SINK_RE.search(stripped):
                continue
            ref = _find_route_resource_reference(
                stripped,
                resource_params=resource_params,
                taint_traces=taint_traces,
                line_no=lineno,
                route_line=block.start_line,
            )
            if not ref:
                continue
            _, ref_trace = ref
            trace = merge_traces(base_trace, ref_trace)
            if not has_auth:
                trace = append_trace(trace, 'gap', 'no auth middleware detected', line=block.start_line)
            trace = append_trace(trace, 'gap', 'no ownership guard detected', line=block.start_line)
            trace = append_trace(trace, 'sink', f"resource lookup `{stripped[:80]}`", line=lineno)
            findings.append(_make_route_finding(
                severity=Severity.CRITICAL if not has_auth else Severity.HIGH,
                title=(
                    'CWE-639: Public IDOR via route parameter'
                    if not has_auth else
                    'CWE-639: IDOR via route parameter with no ownership check'
                ) + f' at line {lineno}',
                description=(
                    f"Route `{block.path}` performs a resource lookup at L{lineno} using a user-controlled route identifier without "
                    + ('authentication or ' if not has_auth else '')
                    + 'ownership scoping. An attacker can access another user\'s record by changing the ID.'
                ),
                line=lineno,
                suggestion=(
                    "Scope lookups by owner/tenant as well as resource ID, for example `where: { id: postId, ownerId: request.user.id }`, "
                    "and protect the route with auth middleware."
                ),
                cwe='CWE-639',
                rule_id='JS-033',
                confidence=0.92,
                trace=trace,
                agent=agent,
                analysis_kind=analysis_kind,
            ))
            break
        else:
            for helper_line, helper_name, helper_trace, helper_chain, sink_label in _helper_route_effect_traces(
                block,
                filename=filename,
                project=project,
                resource_params=resource_params,
                taint_traces=taint_traces,
                effect_kind='lookup',
            ):
                trace = merge_traces(base_trace, helper_trace)
                if not has_auth:
                    trace = append_trace(trace, 'gap', 'no auth middleware detected', line=block.start_line)
                trace = append_trace(trace, 'gap', 'no ownership guard detected', line=block.start_line)
                trace = append_trace(trace, 'helper', f"through `{helper_name}()`", line=helper_line)
                for helper_label in helper_chain:
                    trace = append_trace(trace, 'helper', helper_label, line=helper_line)
                trace = append_trace(trace, 'sink', sink_label, line=helper_line)
                findings.append(_make_route_finding(
                    severity=Severity.CRITICAL if not has_auth else Severity.HIGH,
                    title=(
                        'CWE-639: Public IDOR via route parameter'
                        if not has_auth else
                        'CWE-639: IDOR via route parameter with no ownership check'
                    ) + f' at line {helper_line}',
                    description=(
                        f"Route `{block.path}` reaches a helper-driven resource lookup at L{helper_line} using a user-controlled route identifier without "
                        + ('authentication or ' if not has_auth else '')
                        + 'ownership scoping. An attacker can access another user\'s record by changing the ID.'
                    ),
                    line=helper_line,
                    suggestion=(
                        "Scope lookups by owner/tenant as well as resource ID, for example `where: { id: postId, ownerId: request.user.id }`, "
                        "and protect the route with auth middleware."
                    ),
                    cwe='CWE-639',
                    rule_id='JS-033',
                    confidence=0.91,
                    trace=trace,
                    agent=agent,
                    analysis_kind=analysis_kind,
                ))
                break
    return findings



def _check_route_missing_auth(code: str, *, agent: str, analysis_kind: str, filename: str = '', project=None) -> list[Finding]:
    findings: list[Finding] = []
    for block in _build_route_blocks(code, filename=filename):
        resource_params = _route_resource_params(block.path)
        if _is_public_route(block.path):
            continue
        if _route_auth_labels(block, filename=filename, project=project):
            continue
        if _block_has_verification(block, filename=filename, project=project) or _first_presence_only_gate(block):
            continue
        if not _route_looks_sensitive(block, resource_params):
            continue

        trace = _route_base_trace(block, resource_params, ())
        trace = append_trace(trace, 'gap', 'no auth middleware detected', line=block.start_line)
        if _is_admin_route(block.path):
            severity = Severity.CRITICAL
            sink_label = 'admin route reachable without auth'
            title = f'CWE-862: Missing auth on admin route at line {block.start_line}'
            description = (
                f"Admin route `{block.path}` is reachable without authentication. Any unauthenticated caller can invoke this privileged endpoint."
            )
        elif block.method in {'post', 'put', 'patch', 'delete'}:
            severity = Severity.HIGH
            sink_label = f"mutating route `{block.method.upper()}` reachable without auth"
            title = f'CWE-862: Missing auth on mutating route at line {block.start_line}'
            description = (
                f"Route `{block.path}` uses HTTP {block.method.upper()} with no authentication middleware. State-changing endpoints should require an authenticated caller."
            )
        else:
            severity = Severity.HIGH
            sink_label = 'resource route reachable without auth'
            title = f'CWE-862: Missing auth on resource route at line {block.start_line}'
            description = (
                f"Route `{block.path}` accesses a resource identifier without authentication middleware. An attacker can reach this resource-specific endpoint anonymously."
            )
        trace = append_trace(trace, 'sink', sink_label, line=block.start_line)
        findings.append(_make_route_finding(
            severity=severity,
            title=title,
            description=description,
            line=block.start_line,
            suggestion=(
                "Protect this route with auth middleware such as `requireAuth`, `passport.authenticate(...)`, `preHandler: [requireAuth]`, "
                "or a verified JWT/session guard before the handler executes."
            ),
            cwe='CWE-862',
            rule_id='JS-034',
            confidence=0.95,
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))
    return findings



def _check_admin_broken_access_control(code: str, *, agent: str, analysis_kind: str, filename: str = '', project=None) -> list[Finding]:
    findings: list[Finding] = []
    for block in _build_route_blocks(code, filename=filename):
        if not _is_admin_route(block.path):
            continue
        auth_labels = _route_auth_labels(block, filename=filename, project=project)
        if not auth_labels:
            continue
        privilege_labels = _route_privilege_labels(block, filename=filename, project=project)
        if privilege_labels or _block_has_privilege_guard(block, filename=filename, project=project):
            continue
        trace = _route_base_trace(block, _route_resource_params(block.path), auth_labels)
        trace = append_trace(trace, 'gap', 'no privilege guard detected', line=block.start_line)
        trace = append_trace(trace, 'sink', 'admin route reachable after auth only', line=block.start_line)
        findings.append(_make_route_finding(
            severity=Severity.CRITICAL,
            title=f'CWE-285: Broken access control on admin route at line {block.start_line}',
            description=(
                f"Admin route `{block.path}` authenticates the caller but never checks for an admin/role/permission guard. "
                f"Any authenticated user may be able to reach privileged functionality."
            ),
            line=block.start_line,
            suggestion=(
                "Add a privilege middleware such as `requireAdmin`, `requireRole('admin')`, `preHandler: [requireAdmin]`, or an explicit role/permission check."
            ),
            cwe='CWE-285',
            rule_id='JS-035',
            confidence=0.9,
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))
    return findings



def _check_route_auth_bypass(code: str, *, agent: str, analysis_kind: str, filename: str = '', project=None) -> list[Finding]:
    findings: list[Finding] = []
    for block in _build_route_blocks(code, filename=filename):
        resource_params = _route_resource_params(block.path)
        if _is_public_route(block.path):
            continue
        if _route_auth_labels(block, filename=filename, project=project):
            continue
        if _block_has_verification(block, filename=filename, project=project):
            continue
        if not _route_looks_sensitive(block, resource_params):
            continue
        gate = _first_presence_only_gate(block)
        if not gate:
            continue
        gate_line, gate_label, credential_trace = gate
        trace = merge_traces(_route_base_trace(block, resource_params, ()), credential_trace)
        trace = append_trace(trace, 'gap', 'credential never verified', line=gate_line)
        trace = append_trace(trace, 'sink', f"presence-only gate `{gate_label}`", line=gate_line)
        findings.append(_make_route_finding(
            severity=Severity.CRITICAL if _is_admin_route(block.path) else Severity.HIGH,
            title=f'CWE-287: Auth bypass via presence-only credential check at line {gate_line}',
            description=(
                f"Route `{block.path}` checks only whether a credential-like value exists before allowing access. "
                f"Any non-empty header/cookie/query value can satisfy this gate if the token is never verified."
            ),
            line=gate_line,
            suggestion=(
                "Verify the credential cryptographically (for example `jwt.verify(token, secret)` or a dedicated `verifyToken` helper) "
                "and gate access on the verified principal, not raw token presence."
            ),
            cwe='CWE-287',
            rule_id='JS-036',
            confidence=0.9,
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))
    return findings



def _check_route_missing_ownership_mutation(code: str, *, agent: str, analysis_kind: str, filename: str = '', project=None) -> list[Finding]:
    findings: list[Finding] = []
    assignment_re = re.compile(r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$')
    for block in _build_route_blocks(code, filename=filename):
        resource_params = _route_resource_params(block.path)
        if not resource_params or block.method not in {'post', 'put', 'patch', 'delete'}:
            continue
        auth_labels = _route_auth_labels(block, filename=filename, project=project)
        if not auth_labels or _block_has_ownership_guard(block, filename=filename, project=project):
            continue

        taint_traces = extract_taint_traces(block.body, line_offset=block.start_line - 1)
        if project and filename:
            taint_traces = propagate_helper_return_traces(
                project,
                filename,
                block.body,
                taint_traces,
                line_offset=block.start_line - 1,
            )
        base_trace = _route_base_trace(block, resource_params, auth_labels)
        resource_vars: dict[str, tuple[int, str, tuple[TraceFrame, ...]]] = {}

        for lineno, line in enumerate(block.body.splitlines(), block.start_line):
            stripped = strip_comments(line).strip()
            if not stripped:
                continue
            match = assignment_re.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if not _LOOKUP_SINK_RE.search(expr):
                continue
            ref = _find_route_resource_reference(
                expr,
                resource_params=resource_params,
                taint_traces=taint_traces,
                line_no=lineno,
                route_line=block.start_line,
            )
            if not ref:
                continue
            _, ref_trace = ref
            lookup_trace = merge_traces(ref_trace, (TraceFrame(kind='check', label=f"loaded resource `{expr[:80]}`", line=lineno),))
            resource_vars[target] = (lineno, expr[:80], lookup_trace)

        for lineno, line in enumerate(block.body.splitlines(), block.start_line):
            stripped = strip_comments(line).strip()
            if not stripped or COMMENT_LINE_RE.match(stripped):
                continue
            if not _DIRECT_MUTATION_SINK_RE.search(stripped):
                continue
            ref_trace: tuple[TraceFrame, ...] = ()
            mutation_label = stripped[:80]
            inst_match = _INSTANCE_MUTATION_RE.search(stripped)
            if inst_match:
                resource_var = inst_match.group(1)
                if resource_var not in resource_vars:
                    continue
                _, _, lookup_trace = resource_vars[resource_var]
                ref_trace = lookup_trace
                mutation_label = f"{resource_var}.{inst_match.group(2)}()"
            else:
                ref = _find_route_resource_reference(
                    stripped,
                    resource_params=resource_params,
                    taint_traces=taint_traces,
                    line_no=lineno,
                    route_line=block.start_line,
                )
                if not ref:
                    continue
                _, ref_trace = ref

            trace = merge_traces(base_trace, ref_trace)
            trace = append_trace(trace, 'gap', 'no ownership guard detected before mutation', line=block.start_line)
            trace = append_trace(trace, 'sink', f"mutation `{mutation_label}`", line=lineno)
            findings.append(_make_route_finding(
                severity=Severity.HIGH,
                title=f'CWE-285: Missing ownership check before mutation at line {lineno}',
                description=(
                    f"Authenticated route `{block.path}` mutates a resource at L{lineno} using a user-controlled route identifier without verifying the caller owns that resource."
                ),
                line=lineno,
                suggestion=(
                    "Load the record with an owner/tenant filter before mutating it, for example `where: { id: postId, ownerId: request.user.id }`, "
                    "or block with a 403 ownership check."
                ),
                cwe='CWE-285',
                rule_id='JS-037',
                confidence=0.91,
                trace=trace,
                agent=agent,
                analysis_kind=analysis_kind,
            ))
            break
        else:
            for helper_line, helper_name, helper_trace, helper_chain, sink_label in _helper_route_effect_traces(
                block,
                filename=filename,
                project=project,
                resource_params=resource_params,
                taint_traces=taint_traces,
                effect_kind='mutation',
            ):
                trace = merge_traces(base_trace, helper_trace)
                trace = append_trace(trace, 'gap', 'no ownership guard detected before mutation', line=block.start_line)
                trace = append_trace(trace, 'helper', f"through `{helper_name}()`", line=helper_line)
                for helper_label in helper_chain:
                    trace = append_trace(trace, 'helper', helper_label, line=helper_line)
                trace = append_trace(trace, 'sink', sink_label, line=helper_line)
                findings.append(_make_route_finding(
                    severity=Severity.HIGH,
                    title=f'CWE-285: Missing ownership check before mutation at line {helper_line}',
                    description=(
                        f"Authenticated route `{block.path}` mutates a resource through helper logic at L{helper_line} using a user-controlled route identifier without verifying ownership."
                    ),
                    line=helper_line,
                    suggestion=(
                        "Load the record with an owner/tenant filter before mutating it, for example `where: { id: postId, ownerId: request.user.id }`, "
                        "or block with a 403 ownership check."
                    ),
                    cwe='CWE-285',
                    rule_id='JS-037',
                    confidence=0.9,
                    trace=trace,
                    agent=agent,
                    analysis_kind=analysis_kind,
                ))
                break
    return findings



def run_route_checks(
    code: str,
    *,
    agent: str = 'js-analyzer',
    analysis_kind: str = 'route-heuristic',
    filename: str = '',
    project=None,
) -> list[Finding]:
    active_project = project or (build_js_project_index(filename, code) if filename else None)
    findings: list[Finding] = []
    for checker in (
        _check_route_missing_auth,
        _check_admin_broken_access_control,
        _check_route_auth_bypass,
        _check_route_idor,
        _check_route_missing_ownership_mutation,
    ):
        findings.extend(checker(code, agent=agent, analysis_kind=analysis_kind, filename=filename, project=active_project))
    return findings
