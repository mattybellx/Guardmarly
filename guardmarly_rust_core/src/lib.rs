use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNode {
    pub id: usize,
    pub kind: String,
    pub text: String,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub children: Vec<ParsedNode>,
}

use std::panic;

/// Maximum AST recursion depth to prevent stack overflow on deeply nested code.
const MAX_PARSE_DEPTH: usize = 500;

fn parse_with_language(code: &str, lang: &str) -> Result<Vec<ParsedNode>, String> {
    let result: std::thread::Result<Result<Vec<ParsedNode>, String>> = panic::catch_unwind(|| {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = match lang {
            "python" => tree_sitter_python::LANGUAGE.into(),
            "javascript" | "typescript" | "js" | "ts" => tree_sitter_javascript::LANGUAGE.into(),
            "java" | "jv" => tree_sitter_java::LANGUAGE.into(),
            "go" | "golang" => tree_sitter_go::LANGUAGE.into(),
            "csharp" | "c#" | "cs" => tree_sitter_c_sharp::LANGUAGE.into(),
            "php" => tree_sitter_php::LANGUAGE_PHP.into(),
            "ruby" | "rb" => tree_sitter_ruby::LANGUAGE.into(),
            "rust" | "rs" => tree_sitter_rust::LANGUAGE.into(),
            "c" => tree_sitter_c::LANGUAGE.into(),
            "cpp" | "c++" | "cxx" => tree_sitter_cpp::LANGUAGE.into(),
            _ => return Err(format!("Unsupported language: {}", lang)),
        };
        parser.set_language(&language).map_err(|e| format!("set_language: {}", e))?;
        let tree = parser.parse(code, None).ok_or("parse failed")?;
        Ok(walk_node(&tree.root_node(), code, 0))
    });

    match result {
        Ok(inner) => inner,
        Err(_panic) => Err("parse panicked (likely stack overflow from deeply nested code — "
            .to_string() + "try reducing nesting depth below " + &MAX_PARSE_DEPTH.to_string() + " levels)"),
    }
}

fn walk_node(node: &tree_sitter::Node, source: &str, depth: usize) -> Vec<ParsedNode> {
    if depth > MAX_PARSE_DEPTH {
        return vec![ParsedNode {
            id: node.id(),
            kind: node.kind().to_string(),
            text: "[truncated: max depth exceeded]".to_string(),
            start_line: node.start_position().row + 1,
            start_col: node.start_position().column,
            end_line: node.end_position().row + 1,
            end_col: node.end_position().column,
            children: vec![],
        }];
    }

    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.extend(walk_node(&child, source, depth + 1));
    }
    let text = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    vec![ParsedNode {
        id: node.id(),
        kind: node.kind().to_string(),
        text,
        start_line: node.start_position().row + 1,
        start_col: node.start_position().column,
        end_line: node.end_position().row + 1,
        end_col: node.end_position().column,
        children,
    }]
}

#[pyfunction]
fn parse_code(code: &str, language: &str, _filename: &str) -> PyResult<String> {
    let nodes = parse_with_language(code, language)
        .map_err(|e| PyValueError::new_err(e))?;
    serde_json::to_string(&nodes)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize: {}", e)))
}

#[pyfunction]
fn parse_code_dict(py: Python, code: &str, language: &str, _filename: &str) -> PyResult<PyObject> {
    let nodes = parse_with_language(code, language)
        .map_err(|e| PyValueError::new_err(e))?;
    let dict = PyDict::new(py);
    dict.set_item("language", language)?;
    dict.set_item("lines_scanned", code.lines().count())?;
    let node_list: Vec<PyObject> = nodes.into_iter()
        .map(|n| node_to_py(py, n))
        .collect::<Result<Vec<_>, _>>()?;
    dict.set_item("nodes", node_list)?;
    Ok(dict.into())
}

fn node_to_py(py: Python, node: ParsedNode) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("id", node.id)?;
    dict.set_item("kind", &node.kind)?;
    dict.set_item("text", &node.text)?;
    dict.set_item("start_line", node.start_line)?;
    dict.set_item("start_col", node.start_col)?;
    dict.set_item("end_line", node.end_line)?;
    dict.set_item("end_col", node.end_col)?;
    let child_list: Vec<PyObject> = node.children.into_iter()
        .map(|c| node_to_py(py, c))
        .collect::<Result<Vec<_>, _>>()?;
    dict.set_item("children", child_list)?;
    Ok(dict.into())
}

/// Parse code and return a flat node table with parent references.
/// Each entry: {id, kind, text, start_line, start_col, end_line, end_col,
///              parent_id, depth, node_type: "root"|"internal"|"leaf"}
/// This avoids recursive tree walking on the Python side.
#[pyfunction]
fn parse_flat_table(py: Python, code: &str, language: &str, _filename: &str) -> PyResult<PyObject> {
    let nodes = parse_with_language(code, language)
        .map_err(|e| PyValueError::new_err(e))?;

    let mut flat: Vec<PyObject> = Vec::new();
    flatten_node(py, &nodes, 0, 0, &mut flat);

    let dict = PyDict::new(py);
    dict.set_item("language", language)?;
    dict.set_item("lines_scanned", code.lines().count())?;
    dict.set_item("node_count", flat.len())?;
    dict.set_item("nodes", flat)?;
    Ok(dict.into())
}

fn flatten_node(py: Python, nodes: &[ParsedNode], parent_id: usize, depth: usize, out: &mut Vec<PyObject>) {
    for node in nodes {
        let entry = PyDict::new(py);
        entry.set_item("id", node.id).ok();
        entry.set_item("kind", &node.kind).ok();
        entry.set_item("text", &node.text).ok();
        entry.set_item("start_line", node.start_line).ok();
        entry.set_item("start_col", node.start_col).ok();
        entry.set_item("end_line", node.end_line).ok();
        entry.set_item("end_col", node.end_col).ok();
        entry.set_item("parent_id", parent_id).ok();
        entry.set_item("depth", depth).ok();
        let node_type = if depth == 0 { "root" } else if node.children.is_empty() { "leaf" } else { "internal" };
        entry.set_item("node_type", node_type).ok();
        out.push(entry.into());
        flatten_node(py, &node.children, node.id, depth + 1, out);
    }
}

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

// ── Fast pattern matching engine ───────────────────────────────────────────

/// Compiled rule for fast line-by-line scanning.
struct CompiledRule {
    rule_id: String,
    cwe: String,
    title_tmpl: String,
    desc_tmpl: String,
    severity: String,
    pattern: Regex,
    context_confirm: Option<Regex>,
    negate_context: bool,
    context_lines: usize,
}

/// Run compiled regex rules against source code, returning findings as JSON.
#[pyfunction]
fn fast_pattern_rules(py: Python, code: &str, rules_json: &str) -> PyResult<PyObject> {
    let rules: Vec<serde_json::Value> = serde_json::from_str(rules_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid rules JSON: {}", e)))?;

    let mut compiled: Vec<CompiledRule> = Vec::new();
    let mut skipped: usize = 0;
    for r in &rules {
        let pattern_str = r["pattern"].as_str().unwrap_or("");
        let pattern = match Regex::new(pattern_str) {
            Ok(re) => re,
            Err(_) => { skipped += 1; continue; }
        };
        let context_confirm = r.get("context_confirm").and_then(|v| v.as_str()).and_then(|s| Regex::new(s).ok());
        compiled.push(CompiledRule {
            rule_id: r["rule_id"].as_str().unwrap_or("?").to_string(),
            cwe: r["cwe"].as_str().unwrap_or("").to_string(),
            title_tmpl: r["title_tmpl"].as_str().unwrap_or("").to_string(),
            desc_tmpl: r["desc_tmpl"].as_str().unwrap_or("").to_string(),
            severity: r["severity"].as_str().unwrap_or("medium").to_string(),
            pattern,
            context_confirm,
            negate_context: r.get("negate_context").and_then(|v| v.as_bool()).unwrap_or(false),
            context_lines: r.get("context_lines").and_then(|v| v.as_u64()).unwrap_or(1) as usize,
        });
    }

    let comment_re = Regex::new(r"^\s*(#|//|/\*|\*|<!--)").ok();
    let lines: Vec<&str> = code.lines().collect();
    let mut findings: Vec<PyObject> = Vec::new();

    for (lineno, line) in lines.iter().enumerate() {
        let lineno1 = lineno + 1;
        let stripped = line.trim();

        // Skip comment lines
        if let Some(ref cre) = comment_re {
            if cre.is_match(stripped) { continue; }
        }

        for rule in &compiled {
            if !rule.pattern.is_match(line) { continue; }

            // Context check
            if let Some(ref ctx_re) = rule.context_confirm {
                let ctx_start = lineno.saturating_sub(rule.context_lines);
                let ctx_end = (lineno + rule.context_lines + 1).min(lines.len());
                let ctx: String = lines[ctx_start..ctx_end].join("\n");
                let found = ctx_re.is_match(&ctx);
                if rule.negate_context && found { continue; }
                if !rule.negate_context && !found { continue; }
            }

            let snippet = if line.len() > 90 { &line[..90] } else { line };
            let title = rule.title_tmpl.replace("{line}", &lineno1.to_string());
            let desc = rule.desc_tmpl
                .replace("{line}", &lineno1.to_string())
                .replace("{snippet}", snippet);

            let finding = PyDict::new(py);
            finding.set_item("rule_id", &rule.rule_id)?;
            finding.set_item("cwe", &rule.cwe)?;
            finding.set_item("title", &title)?;
            finding.set_item("description", &desc)?;
            finding.set_item("line", lineno1)?;
            finding.set_item("severity", &rule.severity)?;
            finding.set_item("agent", "rust-fast-path")?;
            finding.set_item("analysis_kind", "pattern-rust")?;

            findings.push(finding.into());
        }
    }

    let result = PyDict::new(py);
    result.set_item("findings", findings)?;
    result.set_item("lines_scanned", lines.len())?;
    Ok(result.into())
}


#[pyfunction]
fn supported_languages() -> Vec<&'static str> {
    vec!["python", "javascript", "typescript", "java", "go", "csharp", "ruby", "php", "rust", "kotlin", "swift", "dart", "lua", "elixir", "scala", "clojure", "haskell", "shell", "dockerfile", "terraform"]
}

#[pyfunction]
fn version_info() -> String {
    format!("guardmarly_rust_core v{} (ts {})",
        env!("CARGO_PKG_VERSION"),
        tree_sitter::LANGUAGE_VERSION)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_code, m)?)?;
    m.add_function(wrap_pyfunction!(parse_code_dict, m)?)?;
    m.add_function(wrap_pyfunction!(parse_flat_table, m)?)?;
    m.add_function(wrap_pyfunction!(supported_languages, m)?)?;
    m.add_function(wrap_pyfunction!(version_info, m)?)?;
    m.add_function(wrap_pyfunction!(fast_pattern_rules, m)?)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_python() {
        let result = parse_with_language("x = 1", "python");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_unsupported_language() {
        let result = parse_with_language("x = 1", "ruby");
        assert!(result.is_err());
    }
}
