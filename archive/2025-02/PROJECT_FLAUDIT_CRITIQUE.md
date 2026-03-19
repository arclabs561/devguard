# Project Flaudit: Critique and Results Review

## 1. Implementation Critique

### What We Built

- **Files-to-prompt**: Aggregates README, implementation files (py/rs/ts/js/etc.), tests, and optional `.cursor/rules` into a single prompt per project.
- **Selection**: k most recently edited git repos (by last commit time) under dev_root.
- **LLM**: OpenRouter + Gemini 2.5 Flash; system prompt asks for JSON findings in categories: `readme_impl_drift`, `readme_tests_mismatch`, `rules_violation`, `other`.
- **Output**: JSON report with findings per repo.

### Gaps vs Research

| Research finding | Our implementation | Gap |
|------------------|--------------------|-----|
| **Simon Willison files-to-prompt**: clear file boundaries, `--cxml` for Claude, `--markdown` for fenced blocks | We use `## Section: path` + `---` separators | No XML/cxml; no markdown fenced blocks. Adequate for Gemini. |
| **aider-style eviction**: drop files when near context limit | We truncate the whole prompt at 120k chars | Blunt; could drop least-relevant files first. |
| **sync-docs patterns**: version mismatch, removed exports, outdated examples | We rely on LLM to infer | No AST/export extraction; no version comparison. |
| **Structured outputs**: `response_format` / `structured_outputs` for Gemini | We ask for JSON in prompt | Could use Gemini's native structured output for reliability. |
| **Retry on parse failure**: JSON repair, retry | We parse once, swallow errors | Silent failures; no retry. |
| **Model ID**: `google/gemini-2.0-flash-exp` deprecated (404) | Switched to `google/gemini-2.5-flash` | Fixed. |

### Concrete Improvements

1. **Add `openai` to pyproject.toml** – Done. Required for OpenRouter client.
2. **Model fallback**: Try `gemini-2.5-flash` first; fall back to `gemini-2.0-flash-001` if 404.
3. **Structured output**: Use `response_format={"type": "json_object"}` or Gemini `response_mime_type` when supported.
4. **Parse retry**: On JSON parse failure, try stripping markdown fences and retry once.
5. **Rules from workspace root**: When scanning a sub-repo, also include parent `.cursor/rules` (e.g. dev/.cursor/rules) for workspace-level invariants.
6. **Diff-based scope**: Add `--scope=recent` to only include files changed in last N commits (research suggestion).

---

## 2. Run Configuration

- **Spec**: `guardian.spec.yaml` – `project_flaudit.enabled: true`, `model_id: google/gemini-2.5-flash`
- **Env**: `OPENROUTER_API_KEY` from `dev/.env` (loaded via `env_file=("../.env")` when running from guardian/)
- **Fixed**: guardian.spec.yaml YAML syntax (missing newline between `deny_globs: []` and `public_github_secrets:`)
- **Fixed**: `google/gemini-2.0-flash-exp` → `google/gemini-2.5-flash` (404 on OpenRouter)

---

## 3. Results Validation (Manual Review)

**Run**: 2026-02-24, 5 projects, 41 findings total.

### tiny-icf (14 findings)

| Finding | Severity | Manual verdict |
|---------|----------|----------------|
| `auto_start_file_trigger.py` command injection risk | critical | **Partially valid**. Scripts are template-generated; `pod_id` in `runpodctl send` could be user-controlled. Severity inflated – more "medium" (review input sources). |
| `uv run` not in README setup | medium | **Valid**. README says `uv sync` but scripts use `uv run`; minor doc gap. |
| ICF thresholds 0.2/0.8 not in README | medium | **Valid**. Implementation detail worth documenting. |
| `sys.path.insert` in scripts | medium | **Valid**. Common pattern; suggestion to use `uv pip install -e .` is reasonable. |
| `TODO: Review` comments in CombinedLoss | medium | **Valid**. Technical debt. |
| Convolution `out_len` logic | low | **Unverified**. Would need to trace the math. |
| DataLoader reproducibility | medium | **Valid**. PyTorch best practice. |

### anno (12 findings)

| Finding | Severity | Manual verdict |
|---------|----------|----------------|
| gliner2 RelationCapable / export_graph mismatch | high | **Partially valid**. README vs implementation nuance; would need to trace enhance.rs. |
| tplinker not in compare.rs ModelBackend | medium | **Valid**. README lists tplinker; compare command may not support it. |
| Empty cache/mod.rs | medium (rules_violation) | **Weak**. "Empty module" is a stretch for rules_violation. |
| Hardcoded backends in analyze | medium | **Valid**. Flexibility improvement. |
| onnx feature not in README | low | **Valid**. Doc gap. |

### subsume (9 findings)

| Finding | Severity | Manual verdict |
|---------|----------|----------------|
| `overlap_prob_fast` vs `overlap_prob` | medium | **False positive**. Box trait defines `overlap_prob_fast` with default impl forwarding to `overlap_prob`. |
| Missing gumbel-box-volume.pdf | medium | **Valid**. Doc reference to missing file. |
| Generic vs backend-specific distance | medium | **Valid**. README could clarify. |
| KaTeX delimiters $$ vs \( | low | **Valid**. Config mismatch. |
| CandleBox::dim product() | low | **Unverified**. Implementation detail. |

### lexir (6 findings)

| Finding | Severity | Manual verdict |
|---------|----------|----------------|
| textprep in README but not used in code | medium | **Valid**. textprep is cli dep but no `use textprep` in src. |
| fuzzy tests not in integration tests | medium | **Valid**. Test coverage gap. |
| Duplicated k=0/sort logic in query_likelihood/tfidf | low | **Valid**. Refactor suggestion. |

### hypha (0 findings)

- No findings. Either clean or prompt truncated / model missed issues.

---

## 4. Summary

- **True positive rate**: ~70–80% of sampled findings are valid or partially valid.
- **False positives**: subsume `overlap_prob_fast` (trait does define it).
- **Over-severity**: tiny-icf "critical" for script execution – more like medium (depends on input trust).
- **Useful catches**: README/impl drift (uv run, ICF thresholds, textprep), test gaps (fuzzy), doc references (missing PDF), reproducibility (DataLoader seed).
- **Noise**: "Empty module" as rules_violation; some low-severity refactor suggestions are accurate but low priority.

---

## 5. Recommendations

1. **Human review**: Treat findings as triage input, not auto-fail. Critical/high need manual verification.
2. **Severity calibration**: Add prompt guidance: "Reserve critical for security issues with clear exploit path."
3. **Structured output**: Use Gemini structured output to reduce parse failures.
4. **Workspace rules**: Include `dev/.cursor/rules` when scanning sub-repos for rules_violation.
5. **Model**: Keep `google/gemini-2.5-flash`; consider `google/gemini-2.5-pro` for harder reasoning on complex codebases.

---

## 6. Deeper Critique (Post-Fix Run)

### 6.1 False Positive Patterns (New)

| Pattern | Example | Root cause |
|---------|--------|------------|
| **Entry points not in prompt** | tiny-icf: "tiny-icf-train / tiny-icf-predict don't exist" | `pyproject.toml` / `Cargo.toml` not included in `files_to_prompt`; LLM infers from README + impl only. |
| **Trait default impl** | subsume: `overlap_prob_fast` "not defined" | LLM doesn't trace trait default impls; sees only call site. |
| **Feature-gated code** | lexir: "textprep not used" | `textprep` is `cli` feature dep; LLM may not see `Cargo.toml` features. |
| **Truncation** | Findings on files not in prompt | Blunt truncation at 120k chars; LLM may hallucinate about files it never saw. |

**Mitigation**: Always include `pyproject.toml` and `Cargo.toml` (or equivalent) in the prompt; add `[project.scripts]` / `[[bin]]` to the prompt header so the LLM knows entry points exist.

### 6.2 Severity Over-Inflation

- **Critical**: Command injection risk in `auto_start_file_trigger.py` — severity inflated; input trust is project-internal. Calibration: "critical = security with **external** user-controlled input."
- **High**: "README vs impl mismatch" — often medium; reserve high for correctness bugs that affect runtime behavior.

**Prompt improvement**: Add explicit negative examples: "Do NOT use critical for: internal scripts, trusted inputs, or theoretical risks without exploit path."

### 6.3 File Inclusion Heuristics

**Current**: `files_to_prompt` uses `_git_ls_files` + `_is_impl_file` / `_is_readme` / `_is_test_file`. Impl files are capped at 20.

**Gaps**:
- `pyproject.toml`, `Cargo.toml`, `package.json` are not explicitly prioritized; they may be excluded if they don't match impl patterns.
- `_is_impl_file` excludes `.toml` (not in IMPL_EXTENSIONS). So config files are never included.

**Fix**: Add a "manifest" section: always include `pyproject.toml`, `Cargo.toml`, `package.json` (first 4k chars each) before impl files.

### 6.4 Repo-Type Detection

**Problem**: Workspace rules (e.g. `user-core.mdc`, `hygiene.mdc`) may be Python-specific. A Rust-only repo gets irrelevant rules.

**Suggestion**: Detect repo type: if only `.rs` files, skip Python-specific rules; if only `.py`, skip Rust-specific rules. Or: add `workspace_rules_include` per-repo override in config.

### 6.5 Parse Retry and Structured Output

**Current**: `_parse_llm_findings` strips markdown fences, parses once. On failure, returns `[]` silently.

**Improvements**:
1. **Retry**: On `JSONDecodeError`, try stripping `"findings":` and trailing comma; retry once.
2. **Structured output**: OpenRouter/Gemini support `response_format={"type": "json_object"}` or `response_mime_type: application/json`. Use that to reduce parse failures.
3. **Log**: On parse failure, log the raw response (truncated) for debugging.

### 6.6 Diff-Based Scope (Future)

**Research**: Simon Willison / aider-style: only include files changed in last N commits (e.g. `--scope=recent`).

**Benefit**: Smaller prompts, faster, more focused. Fewer false positives from stale code.

**Trade-off**: Misses drift in unchanged files. Best as opt-in mode.

### 6.7 Prioritized Implementation Roadmap

1. **Manifest inclusion** (high impact, low effort): Add `pyproject.toml` / `Cargo.toml` to prompt.
2. **Parse retry** (medium): Strip markdown + retry once; log on failure.
3. **Gemini structured output** (medium): Verify OpenRouter supports `response_format` for Gemini; enable if supported.
4. **Severity negative examples** (low): Add "Do NOT use critical for..." to the prompt.
5. **Repo-type rules** (low): Optional; defer until noise from irrelevant rules is high.

---

## 7. Post-Implementation Validation (2026-02-24)

### Manifest inclusion

- **tiny-icf**: 0 findings (was 10+); manifest inclusion eliminated "tiny-icf-train doesn't exist" false positive.
- **lexir**: 4 findings (was 7); manifest + README fixes reduced noise.

### Unit tests

- `guardian/tests/test_project_flaudit.py`: 5 tests for `files_to_prompt` manifest inclusion and `_parse_llm_findings` (valid JSON, trailing-comma retry, markdown fence, invalid → empty).

### README example validation (lexir)

- `examples/readme_examples.rs`: compile-and-run check for BM25, TF-IDF, Query Likelihood examples. TF-IDF requires multiple docs for non-zero IDF; README updated with 2-doc example.

---

## 8. Parse Failure Critique

### 8.1 Observed failure rate

**Run 2026-02-24 (post-manifest)**: 3 of 5 projects had parse failures (anno, subsume, lexir). Warnings showed truncated JSON — `max_tokens=4000` cut responses mid-object when projects had many findings.

### 8.2 Root causes

| Cause | Fix |
|-------|-----|
| **Token truncation** | `max_tokens` 4000 → 8000 |
| **Markdown fences** | Parser strips `\`\`\`json`; some responses still fail if JSON is malformed inside |
| **Trailing comma** | Retry with `, ]` → `]` repair |
| **Truncated mid-object** | Best-effort: find last complete `{...}` in findings array, close with `]}` |

### 8.3 Implemented mitigations

1. **max_tokens 8000** — reduces truncation for large projects
2. **response_format json_object** — OpenRouter/Gemini; fallback if unsupported
3. **Truncation repair** — brace-matching to recover complete findings from truncated JSON (string-aware)
4. **Parse-failure logging** — truncated raw response logged for debugging

### 8.4 Remaining gaps

- **Structured output**: Not all OpenRouter models support `response_format`; fallback is plain text
- **Partial recovery**: Truncation repair only works when at least one complete finding exists; fully truncated `{"findings": [{"severity":` returns `[]`
- **No retry on API**: On parse failure we don't re-call the LLM with "return fewer findings" or "be more concise"

---

## 9. Prompt and Cost Critique

### 9.1 Prompt efficiency

- **Section order**: Manifest → README → Impl → Tests → Rules. LLM may overweight early sections.
- **No explicit cap on findings**: We ask for "flaws" but don't say "at most 15" — encourages long lists, increases truncation risk.
- **Redundancy**: Workspace rules (15k chars) repeated for every project; could be summarized once.

### 9.2 Cost and latency

- **~70s per run** (5 projects, sequential)
- **Token budget**: ~120k input + ~4–8k output per project → ~600k+ input tokens per run
- **Parallelization**: Projects are analyzed sequentially; could parallelize with rate limiting

### 9.3 Prompt improvements (not yet implemented)

1. **Cap findings**: "Return at most 12 findings, prioritized by severity."
2. **One-sentence descriptions**: "Keep each description to one sentence."
3. **Skip empty**: "If no flaws found, return {\"findings\": []} and do not elaborate."

---

## 10. Severity and Category Critique

### 10.1 Severity drift

- **Low overuse**: Many "low" findings are style/refactor suggestions; useful but noisy
- **High inflation**: "README vs impl" often labeled high; should be medium unless correctness is affected
- **Critical**: Now calibrated ("external user-controlled input"); still need human review

### 10.2 Category overlap

- **readme_impl_drift** vs **readme_tests_mismatch**: Clear
- **rules_violation**: Requires `rule_ref`; sometimes LLM omits it
- **other**: Catch-all; could split into `test_gap`, `doc_gap`, `refactor`, `security`

### 10.3 Suggested prompt addition

```
Prioritize: critical > high > medium > low. For "other", prefer medium only when actionable; use low for minor refactors or style.
```

---

## 11. Post-Mitigation Run (2026-02-24, 14:36)

**Changes applied**: max_tokens 8000, response_format json_object, truncation repair, "at most 12 findings" + "one sentence" in prompt.

**Result**: 0 parse failures (was 3/5). 52 findings across 5 projects. Run time ~53s (was ~72s; JSON mode may reduce token count).

**Evidence**: No `flaudit parse failed` warnings in stdout; all 5 projects returned parsed findings.

---

## 12. Latest Improvements (2026-02-24)

### Rules integration

- **docs.mdc**: Added project flaudit to Automation section; `cd guardian && uv run guardian sweep --only project_flaudit`
- **hygiene.mdc**: Added README/impl drift section; run flaudit when touching READMEs/impl across repos
- **RULES_INDEX.mdc**: Added task routing for README/impl drift

### Diff-based scope

- **scope_recent_commits** (spec): When set (e.g. 5), only include files changed in last N commits, plus manifests + README
- Reduces prompt size; focuses on recent changes; opt-in via `scope_recent_commits: 5` in guardian.spec.yaml

### Smart eviction

- **max_total_chars** in `files_to_prompt`: Stop adding sections when near limit
- Eviction order: tests first, then impl, then rules; manifest + README always included
- Avoids blunt truncation mid-file

### Prompt refinement

- "Prioritized by severity (critical > high > medium > low)" added to system prompt
