"""
guardmarly._stdio
─────────────────
Console-encoding hardening shared by every command-line entry point.

Why this exists
---------------
Windows consoles default to a legacy code page (cp1252, cp437, ...) that cannot
encode the emoji used in progress, triage and licence messages. Python raises
``UnicodeEncodeError`` on the first such write, which aborts the process
mid-scan — before any report is written. The same failure hits piped output on
any platform when ``PYTHONIOENCODING`` names a narrow codec.

Call :func:`harden_stdio_encoding` once, as the first statement of an entry
point, before anything writes to stdout/stderr.
"""
from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import Any

__all__ = ["harden_stdio_encoding", "never_fail_stream"]


def _reconfigure_streams(streams: Iterable[Any], **kwargs: Any) -> None:
    """Best-effort ``reconfigure`` for the given streams (no-op if unsupported)."""
    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(**kwargs)
        except (AttributeError, ValueError, OSError):
            continue


def _stdio_streams() -> tuple[Any, ...]:
    return (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__)


def _enable_windows_utf8_console() -> bool:
    """Switch the Windows console code page to UTF-8. True when it worked."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        output_ok = bool(kernel32.SetConsoleOutputCP(65001))
        input_ok = bool(kernel32.SetConsoleCP(65001))
        return output_ok or input_ok
    except Exception:  # pragma: no cover - platform dependent
        return False


class _NeverFailStream:
    """Proxy stream whose ``write`` cannot raise on encoding.

    Stream reconfiguration is not sufficient on its own: Rich's legacy-Windows
    renderer writes through ``file.write`` using the stream's own codec, and a
    console that cannot encode an emoji raised ``UnicodeEncodeError`` mid-scan
    -- aborting the process before any report was written.  Anything that
    writes to a terminal (progress, triage, licence messages) goes through this
    proxy so an unencodable character is substituted instead of fatal.
    """

    __slots__ = ("_stream",)

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except UnicodeEncodeError:
            encoding = getattr(self._stream, "encoding", None) or "ascii"
            try:
                safe = text.encode(encoding, "replace").decode(encoding, "replace")
            except (LookupError, UnicodeError):  # pragma: no cover - exotic codecs
                safe = text.encode("ascii", "replace").decode("ascii")
            try:
                return self._stream.write(safe)
            except Exception:  # noqa: BLE001 - never propagate from a console write
                return len(safe)
        except Exception:  # noqa: BLE001 - a console write must never abort a scan
            return len(text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def isatty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except Exception:  # noqa: BLE001
            return False


_NEVER_FAIL_CACHE: dict[int, _NeverFailStream] = {}


def never_fail_stream(stream: Any) -> Any:
    """Wrap *stream* so writing an unencodable character substitutes it.

    Idempotent: wrapping an already-wrapped stream returns the same proxy, so
    repeated calls (or a reconfigured stream) cannot build a chain.
    """
    if stream is None or isinstance(stream, _NeverFailStream):
        return stream
    key = id(stream)
    cached = _NEVER_FAIL_CACHE.get(key)
    if cached is not None and cached._stream is stream:
        return cached
    proxy = _NeverFailStream(stream)
    _NEVER_FAIL_CACHE[key] = proxy
    return proxy


def harden_stdio_encoding() -> None:
    """Make console output crash-proof on legacy (non-UTF-8) code pages.

    Streams are reconfigured with ``errors="replace"`` so an unencodable
    character becomes ``?`` instead of raising. Where the host console supports
    it, the code page is upgraded to UTF-8 as well so the characters render
    correctly rather than being substituted.
    """
    _reconfigure_streams(_stdio_streams(), errors="replace")

    if sys.platform == "win32" and _enable_windows_utf8_console():
        _reconfigure_streams(_stdio_streams(), encoding="utf-8", errors="replace")
