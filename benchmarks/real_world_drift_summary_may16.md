# Real-world Corpus Drift Summary (refresh vs offline)

- Refresh score: 100.0
- Offline score: 100.0
- Drift cases: 0

## Language hotspots (offline)

| Language | Cases | Findings | Noise / kLOC |
|---|---:|---:|---:|
| javascript | 10 | 72 | 17.7384 |
| python | 2 | 10 | 7.2098 |
| java | 1 | 87 | 4.3719 |

## Per-case hotspots (offline)

| Case | Language | Findings | Noise / kLOC |
|---|---|---:|---:|
| nodegoat-hardcoded-zap-api-key | javascript | 1 | 125.0 |
| nodegoat-hardcoded-cookie-and-crypto-secrets | javascript | 1 | 71.4286 |
| nodegoat-login-bruteforce | javascript | 6 | 70.5882 |
| nodegoat-signup-bruteforce | javascript | 6 | 70.5882 |
| nodegoat-open-redirect-learn-link | javascript | 6 | 70.5882 |
| nodegoat-index-missing-csrf-protection | javascript | 6 | 70.5882 |
| dvna-full-repo | javascript | 22 | 28.5344 |
| django-i18n-open-redirect | python | 4 | 15.8103 |
| nodegoat-eval-code-injection | javascript | 1 | 12.5 |
| nodegoat-redos-validation | javascript | 1 | 9.009 |
| nodegoat-full-repo | javascript | 22 | 8.0439 |
| flask-login-full-repo | python | 6 | 5.291 |
| webgoat-full-repo | java | 87 | 4.3719 |

## Top recurring CWEs (offline findings)

| CWE | Count |
|---|---:|
| CWE-862 | 78 |
| CWE-352 | 26 |
| CWE-798 | 11 |
| CWE-601 | 10 |
| CWE-1333 | 7 |
| CWE-307 | 7 |
| CWE-502 | 4 |
| CWE-22 | 3 |
| CWE-79 | 3 |
| CWE-338 | 3 |
