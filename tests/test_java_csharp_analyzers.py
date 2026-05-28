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


CSHARP_CLASS_LEVEL_AUTHORIZE_NEXT_LINE_BRACE = """
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Authorize] // class-level auth should still be recognized
[Route("manage")]
public class ManageController : ControllerBase
{
    [HttpGet("account")]
    public IActionResult MyAccount()
    {
        return Ok();
    }
}
"""


CSHARP_AUTHORIZE_ADMIN = """
using Microsoft.AspNetCore.Mvc;

[Area(AreaNames.ADMIN)]
[AuthorizeAdmin]
public class OrdersAdminController : Controller
{
    [HttpPost]
    public IActionResult Reindex()
    {
        return Ok();
    }
}
"""


CSHARP_PERMISSION_HELPER_GUARD = """
using Microsoft.AspNetCore.Mvc;

public class RfqCustomerController : BasePublicController
{
    [HttpPost]
    public async Task<IActionResult> CustomerQuote()
    {
        var result = await CheckCustomerPermissionAsync();
        if (result != null)
            return result;

        return Ok();
    }
}
"""


CSHARP_PUBLIC_STORE_MARKER = """
using Microsoft.AspNetCore.Mvc;

[CheckAccessPublicStore]
public class CatalogController : Controller
{
    [HttpGet]
    public IActionResult GetCategoryProducts()
    {
        return Ok();
    }
}
"""


CSHARP_BASE_ADMIN_CONTROLLER = """
using Microsoft.AspNetCore.Mvc;

public class DashboardController : BaseAdminController
{
    [HttpPost]
    public IActionResult ToggleWidget()
    {
        return Ok();
    }
}
"""


CSHARP_CUSTOMER_OWNERSHIP_GUARD = """
using Microsoft.AspNetCore.Mvc;

public class PrivateMessagesController : Controller
{
    [HttpPost]
    public async Task<IActionResult> DeleteInboxPM(int id)
    {
        var pm = await _customerService.GetPrivateMessageByIdAsync(id);
        var customer = await _workContext.GetCurrentCustomerAsync();
        if (pm != null && pm.ToCustomerId == customer.Id)
            await _customerService.UpdatePrivateMessageAsync(pm);
        return Ok();
    }
}
"""


CSHARP_ADMIN_DERIVED_CONTROLLER = """
using Microsoft.AspNetCore.Mvc;
using Nop.Web.Areas.Admin.Controllers;

public class AvalaraTaxController : TaxController
{
    [HttpPost]
    public IActionResult TaxCategoryUpdate(object model)
    {
        return Ok();
    }
}
"""


CSHARP_PUBLIC_UTILITY_ACTION = """
using Microsoft.AspNetCore.Mvc;

public class CustomerController : Controller
{
    [HttpPost]
    public IActionResult SendOtp(string phone)
    {
        return Ok();
    }
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


GO_ESCAPED_CHAR_LITERALS = r"""
package middleware

var (
    nBlack = []byte{'\033', '[', '3', '0', 'm'}
    bBlue  = []byte{'\x1b', '[', '3', '4', ';', '1', 'm'}
)
"""


GO_FMT_SAFE = """
package main

import "fmt"

func describe(method string) string {
    return fmt.Sprintf("method=%s", method)
}
"""


GO_FMT_SQLI = """
package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    sqlQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", query)
    db.Query(sqlQuery)
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


def test_scan_code_respects_class_level_authorize_when_brace_is_next_line():
    auth_result = scan_code(
        CSHARP_CLASS_LEVEL_AUTHORIZE_NEXT_LINE_BRACE,
        language="csharp",
        filename="ManageController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_authorize_admin_as_auth():
    auth_result = scan_code(
        CSHARP_AUTHORIZE_ADMIN,
        language="csharp",
        filename="OrdersAdminController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_permission_helper_guard_as_auth_check():
    auth_result = scan_code(
        CSHARP_PERMISSION_HELPER_GUARD,
        language="csharp",
        filename="RfqCustomerController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_public_store_marker_for_public_route():
    auth_result = scan_code(
        CSHARP_PUBLIC_STORE_MARKER,
        language="csharp",
        filename="CatalogController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_base_admin_controller_auth_boundary():
    auth_result = scan_code(
        CSHARP_BASE_ADMIN_CONTROLLER,
        language="csharp",
        filename="DashboardController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_current_customer_ownership_guard_as_auth():
    auth_result = scan_code(
        CSHARP_CUSTOMER_OWNERSHIP_GUARD,
        language="csharp",
        filename="PrivateMessagesController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_admin_namespace_derived_controller_auth_boundary():
    auth_result = scan_code(
        CSHARP_ADMIN_DERIVED_CONTROLLER,
        language="csharp",
        filename="AvalaraTaxController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_public_utility_action_name():
    auth_result = scan_code(
        CSHARP_PUBLIC_UTILITY_ACTION,
        language="csharp",
        filename="CustomerController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


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


def test_scan_code_supports_go_escaped_char_literals_without_hanging():
    result = scan_code(
        GO_ESCAPED_CHAR_LITERALS,
        language="go",
        filename="terminal.go",
    )

    assert result.language == "go"
    assert isinstance(result.findings, list)


def test_scan_code_does_not_flag_plain_fmt_sprintf_as_go_sqli():
    result = scan_code(GO_FMT_SAFE, language="go", filename="fmt_safe.go")

    assert "GO-89" not in _rule_ids(result)


def test_scan_code_still_flags_go_sqli_when_formatted_query_reaches_db_sink():
    result = scan_code(GO_FMT_SQLI, language="go", filename="search.go")

    assert "GO-89" in _rule_ids(result)


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
