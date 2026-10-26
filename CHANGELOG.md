# Changelog

Earlier history has not been reconstructed in this changelog.

## [Unreleased]

### Fixed

- Detect mixed-case tracked root `CLAUDE.md` filenames, including when a
  correctly named file is also tracked, without combining multiple paths into
  one diagnostic filename.
- Exit 3 from `public_github_secrets` when it scanned nothing (no GitHub
  token, a requested scanner missing from PATH, or zero repos selected),
  regardless of `fail_on_errors`. The report lists these under
  `coverage_errors`, and `scope.repos_scanned_count` now counts only repos a
  scanner actually ran on (`scope.repos_discovered_count` keeps the total).
- Use ASCII quotes for `owners` and `engines` in
  `devguard.spec.example.yaml`; the curly quotes selected zero repos.
- Include `credential_file_audit` and `mcp_security_audit` findings in SARIF
  output; both were previously dropped.
- Apply `sweep --dev-root` to every sweep that scans a dev root, not only
  `local_dev`; it takes precedence over each sweep's spec `dev_root`.

## Source history (unversioned)

These entries identify source changes without assigning a package release.

- Reject unknown sweep selectors before repository or scanner work.
  ([226be52](https://github.com/arclabs561/devguard/commit/226be521ea520d224cbd2f6f08c469778b1050a9))
- Keep discovery JSON stdout parseable by sending diagnostics to stderr.
  ([3022364](https://github.com/arclabs561/devguard/commit/30223647b5fce52eea0407bcab215a8e3b2f8b5f))
- Preserve sanitized Git inspection errors in repository hygiene reports.
  ([9d173cc](https://github.com/arclabs561/devguard/commit/9d173cc284fa7e797ab38d6eeda3b2d7de695f2a))
