# Changelog

All notable changes to this project are documented in this file.

This changelog is based on repository history starting from the initial commit on 2026-03-21.

## [Unreleased]

## [0.6.1] - 2026-03-25

### Added
- Quality benchmark framework for detector evaluation (`secara.quality`).
- CI quality-gate workflow to run tests and enforce benchmark thresholds.
- Benchmark corpus plus dedicated false-positive regression tests.

### Changed
- Expanded directory file discovery coverage to include configured Tier-2 language extensions (Go, Java/Kotlin, PHP, Ruby families).
- Reduced SQL false positives by tightening Python dynamic-string handling for plain variable names.
- Reduced secret false positives for environment/reference-style assignment patterns.
- Updated project metadata/version references for v0.6.1.

### Fixed
- Alignment issue where scanner extension discovery lagged behind language analyzer support.

## [0.6.0] - 2026-03-22

### Added
- Ruby language rule updates and related analyzer iteration.
- Additional language and detector improvements from the v0.5 stream carried into v0.6.0.

### Changed
- Major scanner update culminating in `v0.6.0` tag.
- Ongoing detector/rule tuning across multiple commits.

## [0.5.0] - 2026-03-22

### Added
- Expanded language support for PHP, Java, and Ruby.
- Broader detector capabilities via generic analyzer updates.

### Changed
- Major platform update (`[v0.5] Major Update`).
- Release update pass for v0.5.0.

## [0.3.0] - 2026-03-21

### Added
- Custom YAML rule engine.
- Rules YAML support files (`secrets.yaml`) and utility tooling (`dump_yaml.py`).
- Early Go sample/test assets and initial Go support groundwork.

### Changed
- Multiple Python analyzer bugfix and tuning passes.
- CLI and formatter improvements.
- Documentation and packaging metadata updates.

### Fixed
- General bug and issue fixes included in post-v0.3.0 commits.

## [0.2.1] - 2026-03-21

### Added
- `CONTRIBUTING.md` with contributor workflow and architecture notes.
- Tier-2 Go support direction (`T2: Go support`).
- Mass Assignment detection feature.

### Changed
- OAuth token detection logic updates.
- Python analyzer and secrets detector refinement.

## [0.2.0] - 2026-03-21

### Added
- Versioned release checkpoint for v0.2.0.

### Changed
- Initial rounds of scanner behavior and project metadata updates.

## [0.1.0] - 2026-03-21

### Added
- Initial project commit and repository bootstrap.
- Core scanner structure, baseline detectors, CLI wiring, and foundational docs/licenses.

---

## Notes

- Some historical commit messages are generic (for example `update`, `fix`, `Edit`). Entries above normalize those commits into release-level summaries.
- Future releases should append a new version section and move completed items from `Unreleased`.
