# Copilot / AI Assistant Instructions

Use this file as a stable reference when asking an AI assistant to modify `Analyze-GitHubPackages.ps1`.

## Single Prompt (Copy/Paste)
```
You are updating a PowerShell 5.1 compatible script `Analyze-GitHubPackages.ps1` that scans GitHub (user or org) and local repos for packages listed in `list_npm_package.txt`. 
Rules:
- Do NOT break existing parameters or defaults.
- Add new behavior only via new switches (e.g. -Recursive, -ShowNonMatches).
- Keep counting logic consistent: summary totals must equal exported *_matches files.
- Package list parsing lives ONLY in Parse-PackageListLine; version logic in Test-VersionSpec.
- Comma-separated versions = OR semantics.
- Support existing: package presence, optional version match, require-one-side, require-both.
- Maintain caching, rate limit handling, and no extra API calls unless the user enables a new switch.
- PowerShell 5.1 friendly: avoid LINQ-style instance methods (no .ToArray() or [string]::IIF).
- Minimal logging unless -VerboseMode; use Write-Line for persisted log lines.
- Provide clear, focused diff with smallest safe change.
Goal: <PUT YOUR FEATURE REQUEST HERE>
Return ONLY the modified function(s) or added code blocks.
```

## Guidelines (Detailed)
1. **Scope**: Implement one cohesive feature per change.
2. **Parameters**: New switches belong in the main `param()` block; name them in PascalCase without abbreviations.
3. **Compatibility**: Script must run under Windows PowerShell 5.1 and PowerShell Core.
4. **Parsing**: Extend only `Parse-PackageListLine` for new input formats; document regex intent.
5. **Version Specs**: Preserve OR semantics for comma lists. New operators (hyphen ranges, x-wildcards) must be additive and tested.
6. **Matching Logic**: Do not change meaning of `-RequireVersionMatch` or `-RequireBothVersionMatch`.
7. **Performance**: Re-use caching; avoid per-repo extra network calls unless explicitly requested via new switch.
8. **Output Consistency**: Summary totals must be derived from `matchedEntries` to avoid drift.
9. **New Outputs**: Suffix any extra exports (`_nonmatches.csv`, `_ranges.json`). Never rename existing ones.
10. **Logging**: Use `Write-DebugLine` for verbose internals; keep `Write-Line` for user-visible & stored log.
11. **Error Handling**: Fail fast on invalid inputs with `Write-Error` + non-zero exit code.
12. **Rate Limits**: Honor existing backoff pattern; do not shorten delays.
13. **Local Scanning**: If adding recursion, guard behind `-Recursive` and limit depth (default sensible like 4) unless user overrides.
14. **Testing Hooks**: Optional debug switches should not alter core logic order.
15. **No Global State**: Only reuse existing `$Global:` caches; introduce no new global variables unless unavoidable.
16. **Diff Minimalism**: Avoid reformatting unrelated lines; keep patches reviewable.
17. **Security**: Never execute remote code; treat fetched content as text only.
18. **Examples**: If adding a feature, update README with one usage example.

## Good Feature Ideas
- `-Recursive` local scan for nested workspaces.
- `-ShowNonMatches` exporting failed version matches for diagnostics.
- Range spec support: `>=1.2.0 <2.0.0`.
- Wildcard support: `1.2.x` (interpreted as `>=1.2.0 <1.3.0`).

## Bad / Disallowed Changes
- Renaming existing columns or output files.
- Replacing custom semver logic with a heavy external module.
- Broad refactors without a functional benefit.

## Verification Checklist (Pre-Commit)
- [ ] New switch documented.
- [ ] Script runs without syntax errors in PS 5.1.
- [ ] Summary total == length of `_matches.json` array.
- [ ] No unintended increase in API calls (spot-check with `-VerboseMode`).
- [ ] Added logic covered by inline comment (one concise line).

---
Keeping these rules ensures safe, incremental evolution with AI assistance.
