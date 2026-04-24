# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Current |
| < 1.0   | ❌ No longer supported |

## Reporting a Vulnerability

If you discover a security vulnerability in ansede-static, **please do not open a public issue**.

Instead, use **GitHub private vulnerability reporting**:

- https://github.com/ansede/ansede-static/security/advisories/new

When reporting, please include:

1. A description of the vulnerability
2. Steps to reproduce
3. Impact assessment (if known)

We aim to acknowledge reports within **48 hours** and provide a fix within **7 days** for critical issues.

## Scope

ansede-static is a static analysis tool — it reads source code but never executes it. Security concerns include:

- **False negatives** — missing a real vulnerability in scanned code
- **ReDoS** — a crafted input causing the regex engine to hang
- **Path traversal** — if directory scanning follows symlinks outside the intended scope

## Responsible Disclosure

We follow coordinated disclosure. If you report a vulnerability, we will:

1. Confirm receipt and begin investigation
2. Develop and test a fix
3. Release a patched version
4. Credit you in the release notes (unless you prefer anonymity)
