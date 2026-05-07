from __future__ import annotations

from ansede_static.cli import _apply_auto_fixes
from ansede_static import scan_code, scan_file


JAVA_MISSING_AUTH = """
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    @GetMapping("/admin/users")
    public String listUsers() {
        return "[]";
    }
}
"""


JAVA_SQLI = """
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserController {
    public void search(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
"""


CSHARP_MISSING_AUTH = """
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult Users()
    {
        return Ok(new[] { "alice" });
    }
}
"""


CSHARP_SQLI = """
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
[Route("users")]
public class UsersController : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search(string id)
    {
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = '{id}'");
        return Ok();
    }
}
"""


CSHARP_SECRET = """
public class Settings
{
    private string connection = "Server=db;Password=SuperSecret123;User Id=sa;";
}
"""


GO_MISSING_AUTH = """
package main

import "net/http"

func main() {
    http.HandleFunc("/admin/users", adminHandler)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}
"""


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings if finding.rule_id}


def test_scan_code_supports_java_rules():
    auth_result = scan_code(JAVA_MISSING_AUTH, language="java", filename="AdminController.java")
    sqli_result = scan_code(JAVA_SQLI, language="java", filename="UserController.java")

    assert "JV-001" in _rule_ids(auth_result)
    assert "JV-004" in _rule_ids(sqli_result)


def test_scan_code_supports_csharp_rules_and_alias():
    auth_result = scan_code(CSHARP_MISSING_AUTH, language="csharp", filename="AdminController.cs")
    sqli_result = scan_code(CSHARP_SQLI, language="cs", filename="UsersController.cs")

    assert "CS-001" in _rule_ids(auth_result)
    assert "CS-004" in _rule_ids(sqli_result)


def test_scan_file_detects_java_and_csharp(tmp_path):
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "UsersController.cs"
    java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_SECRET, encoding="utf-8")

    java_result = scan_file(java_file)
    cs_result = scan_file(cs_file)

    assert java_result.language == "java"
    assert "JV-001" in _rule_ids(java_result)
    assert cs_result.language == "csharp"
    assert "CS-006" in _rule_ids(cs_result)


def test_java_csharp_go_findings_include_safe_inline_auto_fixes(tmp_path):
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "AdminController.cs"
    go_file = tmp_path / "main.go"
    java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_MISSING_AUTH, encoding="utf-8")
    go_file.write_text(GO_MISSING_AUTH, encoding="utf-8")

    java_result = scan_file(java_file)
    cs_result = scan_file(cs_file)
    go_result = scan_file(go_file)

    java_fix = next(f.auto_fix for f in java_result.findings if f.rule_id == "JV-001")
    cs_fix = next(f.auto_fix for f in cs_result.findings if f.rule_id == "CS-001")
    go_fix = next(f.auto_fix for f in go_result.findings if f.rule_id == "GO-862")

    assert "@PreAuthorize" in java_fix
    assert "[Authorize]" in cs_fix
    assert "RequireAuth(adminHandler)" in go_fix


def test_apply_fixes_updates_java_csharp_and_go_sources(tmp_path):
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "AdminController.cs"
    go_file = tmp_path / "main.go"
    java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_MISSING_AUTH, encoding="utf-8")
    go_file.write_text(GO_MISSING_AUTH, encoding="utf-8")

    results = [scan_file(java_file), scan_file(cs_file), scan_file(go_file)]

    applied, skipped = _apply_auto_fixes(results)

    assert applied == 3
    assert skipped == 0
    assert "@PreAuthorize(\"isAuthenticated()\") public String listUsers()" in java_file.read_text(encoding="utf-8")
    assert "[Authorize] public IActionResult Users()" in cs_file.read_text(encoding="utf-8")
    assert "RequireAuth(adminHandler)" in go_file.read_text(encoding="utf-8")
