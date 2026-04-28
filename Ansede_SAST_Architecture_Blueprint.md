# 🚀 The Ansede Blueprint: Enterprise-Grade, Zero-Dependency SAST Architecture

**Target Audience:** AI Development Assistant / LLM
**Goal:** Implement a 100/100, state-aware, zero-dependency Static Application Security Testing (SAST) engine in pure Python.

---

## 📌 Executive Summary
This document outlines the architectural blueprint for upgrading `ansede-static` into an elite SAST engine. The constraint is strict: **Zero External Dependencies** (pure Python standard library). 

To achieve parity with enterprise tools (CodeQL, Semgrep Pro), the engine must evolve from an Abstract Syntax Tree (AST) pattern-matcher to a state-aware code simulator. This involves building an in-memory Code Property Graph (CPG), implementing path-sensitive taint tracking, and utilizing standard library tools like `sqlite3` and `hashlib` for caching and scalability.

---

## 🏗️ Phase 1: The Zero-Dependency Code Property Graph (CPG)
You must build an in-memory graph structure that fuses the AST, Control Flow Graph (CFG), and Program Dependence Graph (PDG).

### Implementation Requirements:
* **The Parser:** Use Python's built-in `ast` module.
* **The Data Structure:** Implement the CPG as an **Adjacency List** using pure Python dictionaries.
  * `nodes = { node_id: {"type": "Call", "lineno": 12, "value": "execute"} }`
  * `edges = { node_id: {"AST_CHILD": [id2, id3], "CFG_NEXT": [id4], "DATA_DEPENDENCY": [id1]} }`
* **CFG Generation:** Write a visitor class (`ast.NodeVisitor`) that walks the AST. Split `CFG_NEXT` edges into branches on control flow nodes (`ast.If`, `ast.For`, `ast.While`).
* **PDG Generation (Data Flow):** Track variable assignments in a scoped dictionary. If `line 5` assigns `x = user_input` and `line 10` reads `x`, draw a `DATA_DEPENDENCY` edge from the node at line 5 to line 10.
* **[100/100 ADDITION] Exception Handling Flow:** AST visitors notoriously miss `try/except/finally` blocks. You must map `CFG_NEXT` edges from *any* throwing node inside the `try` block to the `except` block. Failure to do this results in bypassed taint tracking if an attacker triggers an exception.

---

## 🕵️ Phase 2: The Taint Tracking & Dataflow Engine
Traverse the CPG to find vulnerabilities (source-to-sink paths).

### Implementation Requirements:
* **Context-Sensitivity (The Call Stack):** Maintain a `call_stack` tuple: `(caller_node_id, current_node_id)` during traversal. Cache taint results *under that specific call stack context* to prevent false positives when safe and dangerous functions call the same helper method.
* **Heap & Object Field Modeling (Alias Analysis):** Create a synthetic "Memory Layout" dictionary.
  * Variables -> Addresses: `{"user": "addr_0x1"}`
  * Addresses -> State: `{"addr_0x1": {"fields": {"name": "TAINTED"}}}`
  * Handle assignments (`x = user`). Both point to `addr_0x1`.
* **Zero-Dependency Type Inference:** 1. Parse `ast.AnnAssign` and `ast.FunctionDef.returns` nodes.
  2. Implement **Duck Typing Heuristics**: If an object calls `.execute()` and `.fetchall()`, tag it internally as `Type::DatabaseCursor`.
* **[100/100 ADDITION] Collection/Iterable Taint:** If `tainted_val` is appended to `my_list`, then `my_list` becomes tainted. If `x = my_list[0]`, `x` inherits the taint. Track collections in your Memory Layout.
* **[100/100 ADDITION] String Operations:** Intercept `ast.JoinedStr` (f-strings), `ast.BinOp` (using `%`), and `.format()` calls. If any component string is tainted, the resulting string must inherit the taint.

---

## 🛡️ Phase 3: Sanitizer & Specification Modeling
A vulnerability only exists if a source hits a sink *without* passing through a sanitizer.

### Implementation Requirements:
* **The Taint State Machine:** Variables carry a state object: `{"tags": ["user_controlled"], "sanitized_by": []}`.
* **State Transitions:** If it passes through `html.escape()`, update to `{"tags": ["user_controlled"], "sanitized_by": ["HTML_ENCODE"]}`.
* **Sink Resolution:** An XSS sink checks tags and fires *only* if `HTML_ENCODE` is missing.
* **Pre-computed Specifications:** Do not hardcode rules in Python logic. Define sources, sinks, and sanitizers in a `taint_specs.json` file shipped with the package. Use `json` to load them at runtime.
* **[100/100 ADDITION] Implicit Sanitization:** Recognize built-in type casting as sanitizers. E.g., `int(user_input)` completely sanitizes a string against SQL injection. Map standard library type casts in your `taint_specs.json`.

---

## ⚡ Phase 4: Scalability (Summaries & Incremental Scans)
Enterprise codebases require aggressive caching to scan quickly in CI/CD pipelines.

### Implementation Requirements:
* **Summary-Based Inter-procedural Analysis:** When finishing a function analysis, compute a summary (e.g., *"If Arg 1 is tainted, Return Value is safe"*). Store this in a hidden local SQLite database (`.ansede/cache.db`) using Python's `sqlite3`. Query this cache instead of re-traversing on subsequent calls.
* **Incremental Analysis:** Use Python's `hashlib` to SHA-256 hash `.py` file contents. Store hashes in SQLite. On the next run, only re-parse files whose hashes changed (and files that import them).

---

## 🌟 Phase 5: Additional 100/100 Capabilities
To make this project truly world-class, implement the following advanced features:

* **Dynamic Dispatch Resolution:** Handle `getattr(obj, "method_name")()` by cross-referencing string values with known object methods in the CPG. 
* **Universal AST (U-AST) Architecture:** If expanding back to JavaScript/TypeScript, do not write a separate analysis engine. Map the JS AST and Python AST into a single, unified "Ansede-Node" structure. Write your Taint Engine to traverse Ansede-Nodes. This allows `taint_specs.json` rules to work across multiple languages.
* **SARIF Output Integration:** Output results natively in standard SARIF format (Static Analysis Results Interchange Format) using the `json` library, allowing instant integration into GitHub Advanced Security (GHAS) dashboards.

---
Addtional implementations in full for after or during, whatevers best:

Based on the provided documentation for Ansede, the developers have already outlined several known limitations and "non-goals" they do not intend to implement, such as dynamic analysis (DAST), dependency scanning, and full symbolic execution
. They also acknowledge the need to eventually improve cross-file taint analysis and template engine support (like Jinja2)
.
However, evaluating the tool's current features, the biggest improvements it could benefit from that are not currently spoken about in the provided text include:
(Please note: The following improvements are external insights drawn from analyzing the gaps in your provided source material, as the sources do not explicitly discuss these as future roadmap items).
Broader Programming Language Support: Ansede is currently built specifically for Python (which makes up 99.9% of its codebase) and JavaScript/TypeScript
. The biggest unspoken improvement would be expanding its AST-level scanning to other major enterprise languages like Java, C#, Go, or C++. Competitors listed in Ansede's own matrix, such as Semgrep and CodeQL, already support a much wider variety of languages
.
Expansion to Other Major IDEs: The documentation heavily promotes its dedicated Visual Studio Code extension for real-time inline security scanning
. However, there is no mention of supporting JetBrains IDEs (like PyCharm, IntelliJ, or WebStorm) or providing a standard Language Server Protocol (LSP) for editors like Neovim. Building these would vastly increase developer adoption.
Vulnerability Detection for Non-Web Frameworks: Ansede's detection heuristics are heavily optimized for common web server frameworks such as Flask, FastAPI, Django, Express, Koa, and Nest
. An unspoken but highly valuable improvement would be creating rulesets tailored to data science/engineering pipelines (e.g., unsafe data loading in Pandas or PySpark) or mobile app frameworks like React Native.
Native Plugins for Enterprise CI/CD Platforms: The project currently offers a seamless, one-line GitHub Action for CI integration
 and briefly mentions that it can run in GitLab CI or any shell
. It does not, however, discuss offering native integrations, extensions, or pre-configured templates for other massive enterprise CI/CD environments like Jenkins, Azure DevOps, or AWS CodePipeline.
Adding these capabilities would help Ansede scale from a specialized web-backend tool into a comprehensive, enterprise-grade static analysis platform.


## 🤖 Instructions for AI Implementation (Read Carefully)
As the LLM tasked with building this codebase, execute the following steps in order:

1. **Scaffold the Data Structures:** Begin by defining the `CPGNode` and `CPGEdge` classes. Define the `MemoryLayout` dictionary structure.
2. **Build the CPG Generator:** Write the `ast.NodeVisitor` that builds the Adjacency List. *Stop and verify* that CFG branching (if/else) works correctly before moving to taint tracking.
3. **Write the Taint Engine:** Implement the traversal algorithm. Ensure it passes the `call_stack` down the recursive traversal to maintain context-sensitivity.
4. **Implement SQLite Caching:** Add the database layer for function summaries last, as an optimization wrapper around the Taint Engine.
5. **JSON Rule Engine:** Do not hardcode specific vulnerabilities (like SQLi or XSS) into the traversal logic. Build a loader that parses `rules.json` and feeds it to the engine.

*End of Document*
