from pathlib import Path

from secara.cli import _is_suppressed
from secara.output.formatter import filter_by_confidence
from secara.output.models import Finding
from secara.quality.history import append_history, read_history
from secara.scanner.baseline import (
    filter_new_findings,
    load_baseline_fingerprints,
    write_baseline,
)
from secara.scanner.incremental import collect_changed_files


def _finding(rule_id: str, confidence: str, file_path: str = "a.py", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=rule_id,
        severity="HIGH",
        file_path=file_path,
        line_number=line,
        snippet="x",
        description="d",
        fix="f",
        language="python",
        confidence=confidence,
    )


def test_filter_by_confidence():
    findings = [
        _finding("A", "HIGH"),
        _finding("B", "MEDIUM"),
        _finding("C", "LOW"),
    ]
    out = filter_by_confidence(findings, "MEDIUM")
    assert {f.rule_id for f in out} == {"A", "B"}


def test_baseline_roundtrip_and_filter(tmp_path: Path):
    f1 = _finding("R1", "HIGH", file_path=str(tmp_path / "a.py"), line=1)
    f2 = _finding("R2", "HIGH", file_path=str(tmp_path / "b.py"), line=2)
    baseline_path = tmp_path / "baseline.json"
    write_baseline([f1], baseline_path)
    fps = load_baseline_fingerprints(baseline_path)
    filtered = filter_new_findings([f1, f2], fps)
    assert [f.rule_id for f in filtered] == ["R2"]


def test_changed_only_collects_untracked_files(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitignore").write_text("", encoding="utf-8")
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")

    import subprocess
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)

    files = collect_changed_files(repo)
    names = {p.name for p in files}
    assert "app.py" in names


def test_ignore_metadata_enforced_and_expired():
    active = "# secara: ignore[SQL001] reason=ticket until=2099-01-01"
    expired = "# secara: ignore[SQL001] reason=ticket until=2000-01-01"
    no_meta = "# secara: ignore[SQL001]"

    assert _is_suppressed(active, "SQL001", enforce_metadata=True)
    assert not _is_suppressed(expired, "SQL001", enforce_metadata=False)
    assert not _is_suppressed(no_meta, "SQL001", enforce_metadata=True)


def test_ignore_metadata_invalid_or_malformed_values():
    invalid_date = "# secara: ignore[SQL001] reason=ticket until=2099-99-99"
    malformed_reason = "# secara: ignore[SQL001] reason until=2099-01-01"

    assert not _is_suppressed(invalid_date, "SQL001", enforce_metadata=False)
    assert not _is_suppressed(malformed_reason, "SQL001", enforce_metadata=True)


def test_history_append_and_read(tmp_path: Path):
    hist = tmp_path / "history.jsonl"
    append_history({"files_scanned": 3, "findings_shown": 1}, path=hist)
    rows = read_history(hist)
    assert len(rows) == 1
    assert rows[0]["files_scanned"] == 3
