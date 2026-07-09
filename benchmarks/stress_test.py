"""stress_test.py — edge-case robustness across all 5 languages."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_code

EDGE = []

def add(name, lang, code):
    EDGE.append((name, lang, code))

# ── EMPTY / WHITESPACE ──
add("empty", "python", "")
add("whitespace", "python", "   \n\n   \t  ")
add("comment-only-py", "python", "# just a comment\n# another")
add("comment-only-js", "javascript", "// just a comment")
add("semicolons", "javascript", ";;;;;")
add("just-imports", "python", "import os\nimport sys\nimport json")
add("just-requires", "javascript", "const fs = require('fs');\nconst path = require('path');")
add("just-package", "java", "package com.example;")
add("just-using", "csharp", "using System;\nusing System.Linq;")
add("just-pkg-main", "go", "package main")

# ── UNICODE / SPECIAL CHARS ──
add("unicode-str", "python", 'x = "\u2764\ufe0f hello world"')
add("emoji-fn", "python", "# def snake(): pass\nx = 1")
add("rtl-text", "python", 'x = "hello\u202eworld"')
add("null-byte", "python", 'x = "hello\\x00world"')

# ── HUGE / NESTED ──
add("long-line", "python", "x = " + '"' + "A" * 5000 + '"')
add("deep-nest", "python", "def a():\n" + "\n".join(" " * (i*2) + f"def f{i}(): pass" for i in range(60)))
add("big-literal", "python", "x = (" + ",".join(str(i) for i in range(2000)) + ")")

# ── MINIFIED / OBFUSCATED JS ──
add("minified-js", "javascript", "var a=1,b=2,c=3;function d(e){return e?d(e-1)+e:0};console.log(d(10))")
add("webpack-ish", "javascript", "!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}n.m=e}([function(e,t){e.exports=function(e){return e+1}}])")

# ── TRICKY SYNTAX ──
add("raw-string", "python", 'r"\n\t\r\\\\"')
add("triple-quote", "python", '"""\nmultiline\nstring\n"""')
add("walrus-op", "python", "if (x := get_value()):\n    print(x)")
add("match-stmt", "python", "match x:\n    case 1: pass\n    case _: pass")
add("async-await", "python", "async def fetch():\n    async with session.get(url) as resp:\n        return await resp.json()")
add("template-lit", "javascript", "const x = `hello ${name}, your id is ${id}`;")
add("spread-js", "javascript", "const merged = {...a, ...b, [key]: val};")
add("optional-chain", "javascript", "const x = obj?.nested?.deep?.value ?? 'default';")

# ── LANGUAGE-SPECIFIC ──
add("java-generic", "java", "public class Box<T> { private T value; public T get() { return value; } }")
add("java-hello", "java", "public class Hello { public static void main(String[] args) { System.out.println(\"hi\"); } }")
add("csharp-linq", "csharp", "var result = items.Where(x => x.Active).Select(x => x.Name).ToList();")
add("csharp-async", "csharp", "public async Task<string> FetchAsync() { using var http = new HttpClient(); return await http.GetStringAsync(\"https://example.com\"); }")
add("go-goroutine", "go", "package main; func main() { go func() { println(\"hi\") }() }")
add("go-interface", "go", "package main; type Reader interface { Read(p []byte) (n int, err error) }")

# ── RUN ──
passes = 0
errors = 0
for name, lang, code in EDGE:
    try:
        result = scan_code(code, language=lang, filename=f"{name}.txt")
        count = len(result.findings)
        passes += 1
        if count > 0:
            cwes = {f.cwe for f in result.findings if f.cwe}
            print(f"  [{name:20s}] {lang:10s} {count:2d} findings, CWEs={sorted(cwes)}")
    except Exception as e:
        errors += 1
        print(f"  ERROR [{name:20s}] {lang}: {type(e).__name__}: {str(e)[:80]}")

print(f"\nEdge cases: {passes} passed, {errors} errors out of {len(EDGE)}")
print("ALL PASS" if errors == 0 else "SOME ERRORS")
