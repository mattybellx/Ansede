from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import external_corpus
from benchmarks.external_corpus import OfflineCacheMissError, run_external_corpus


_DEF_HEAD = "0123456789abcdef0123456789abcdef01234567"


def _manifest_payload(repo: str, ref: str = _DEF_HEAD) -> dict[str, object]:
    return {
        "entries": [{
            "case_id": "offline-python-admin-vuln",
            "source": {
                "kind": "git",
                "repo": repo,
                "ref": ref,
                "subdir": "sample",
            },
            "language": "python",
            "expected_cwes": ["CWE-862"],
            "expected_rule_ids": ["PY-020"],
        }]
    }


def _write_manifest(tmp_path: Path, repo: str, ref: str = _DEF_HEAD) -> Path:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_manifest_payload(repo, ref), indent=2), encoding="utf-8")
    return manifest_path


def _populate_cached_repo(cache_dir: Path, repo: str, ref: str = _DEF_HEAD) -> Path:
    source = external_corpus.ExternalCorpusSource(kind="git", repo=repo, ref=ref, subdir="sample")
    checkout_dir = cache_dir / external_corpus._git_cache_key(source)
    (checkout_dir / ".git").mkdir(parents=True, exist_ok=True)
    sample_dir = checkout_dir / "sample"
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "app.py").write_text(
        """
from flask import Flask

app = Flask(__name__)

@app.route('/admin/users')
def list_users():
    return []
""".strip() + "\n",
        encoding="utf-8",
    )
    return checkout_dir


def test_offline_raises_offline_cache_miss_without_network(monkeypatch, tmp_path):
    manifest_path = _write_manifest(tmp_path, "https://github.com/example/missing.git")

    def _unexpected_git(args, *, cwd=None):
        raise AssertionError(f"git should not be called in offline cache-miss path: {args}")

    monkeypatch.setattr(external_corpus, "_run_git", _unexpected_git)

    with pytest.raises(OfflineCacheMissError):
        run_external_corpus(manifest_path, cache_dir=tmp_path / "cache", offline=True, quiet=True)


def test_offline_uses_cached_repo_without_clone_or_fetch(monkeypatch, tmp_path):
    repo = "https://github.com/example/cached.git"
    manifest_path = _write_manifest(tmp_path, repo)
    cache_dir = tmp_path / "cache"
    _populate_cached_repo(cache_dir, repo)
    calls: list[list[str]] = []

    def _fake_run_git(args, *, cwd=None):
        calls.append(list(args))
        if args[:2] == ["rev-parse", "HEAD"]:
            return _DEF_HEAD
        if args[:2] == ["checkout", "--quiet"]:
            return ""
        raise AssertionError(f"unexpected git command in offline mode: {args}")

    monkeypatch.setattr(external_corpus, "_run_git", _fake_run_git)

    report = run_external_corpus(manifest_path, cache_dir=cache_dir, offline=True, quiet=True)

    assert report["summary"]["score_pct"] == 100.0
    assert all(call[0] not in {"clone", "fetch"} for call in calls)


def test_refresh_forces_reclone_when_cache_exists(monkeypatch, tmp_path):
    repo = "https://github.com/example/refresh.git"
    manifest_path = _write_manifest(tmp_path, repo)
    cache_dir = tmp_path / "cache"
    _populate_cached_repo(cache_dir, repo)
    calls: list[list[str]] = []

    def _fake_run_git(args, *, cwd=None):
        calls.append(list(args))
        if args[0] == "clone":
            target = Path(args[-1])
            (target / ".git").mkdir(parents=True, exist_ok=True)
            sample_dir = target / "sample"
            sample_dir.mkdir(parents=True, exist_ok=True)
            (sample_dir / "app.py").write_text(
                """
from flask import Flask

app = Flask(__name__)

@app.route('/admin/users')
def list_users():
    return []
""".strip() + "\n",
                encoding="utf-8",
            )
            return ""
        if args[:2] == ["checkout", "--quiet"]:
            return ""
        if args[:2] == ["rev-parse", "HEAD"]:
            return _DEF_HEAD
        raise AssertionError(f"unexpected git command during refresh: {args}")

    monkeypatch.setattr(external_corpus, "_run_git", _fake_run_git)

    report = run_external_corpus(manifest_path, cache_dir=cache_dir, refresh=True, quiet=True)

    assert report["summary"]["score_pct"] == 100.0
    assert any(call[0] == "clone" for call in calls)
