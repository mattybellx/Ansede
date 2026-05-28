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

fn parse_with_language(code: &str, lang: &str) -> Result<Vec<ParsedNode>, String> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = match lang {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" | "typescript" | "js" | "ts" => tree_sitter_javascript::LANGUAGE.into(),
        "java" | "jv" => tree_sitter_java::LANGUAGE.into(),
        "go" | "golang" => tree_sitter_go::LANGUAGE.into(),
        "csharp" | "c#" | "cs" => tree_sitter_c_sharp::LANGUAGE.into(),
        _ => return Err(format!("Unsupported language: {}", lang)),
    };
    parser.set_language(&language).map_err(|e| format!("set_language: {}", e))?;
    let tree = parser.parse(code, None).ok_or("parse failed")?;
    Ok(walk_node(&tree.root_node(), code))
}

fn walk_node(node: &tree_sitter::Node, source: &str) -> Vec<ParsedNode> {
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.extend(walk_node(&child, source));
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

#[pyfunction]
fn supported_languages() -> Vec<&'static str> {
    vec!["python", "javascript", "typescript", "java", "go", "csharp"]
}

#[pyfunction]
fn version_info() -> String {
    format!("ansede_rust_core v{} (ts {})",
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
    Ok(())
}
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
