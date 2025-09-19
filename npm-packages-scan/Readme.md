## GitHub Repository & Local Folder Package Analyzer

### Features:
- Remote scan: GitHub REST (unauth) or GraphQL (with token)
- Local scan: top-level folders under -LocalReposRoot (no recursion)
- Parses: package.json, package-lock.json, pnpm-lock.yaml, yarn.lock
- Package list lines: name   OR   name (versionSpec)
- Version operators: exact, =, ==, >, >=, <, <=, ^, ~, *
- Declared vs Resolved evaluation with DeclaredMatch / ResolvedMatch / MatchSource
- Modes:
  * Default: presence only (version optional)
  * -RequireVersionMatch: at least one side (Declared or Resolved) satisfies spec
  * -RequireBothVersionMatch: both Declared AND Resolved exist and satisfy spec
- Local + remote combined
- Output:
  * Standard mode: text log + repo summary CSV + matched packages CSV/JSON
  * -MatchesOnly: only matched packages CSV/JSON (no repo summary CSV, minimal log)
- Matched packages exported to: <OutputFile basename>_matches.csv / .json

Usage examples: Scan only local:
```powershell
.\Analyze-GitHubPackages.ps1 -LocalReposRoot 'D:\clones' -LocalOnly -PackageListFile '.\list_npm_package.txt'  -MaxRepos 150
```
Combine GitHub + local:
```powershell
.\Analyze-GitHubPackages.ps1 -GitHubUser gitHubUser -GitHubToken YOUR_TOKEN -LocalReposRoot 'D:\clones' -IncludeForks -IncludeArchived  -MaxRepos 150
```
Other
```powershell
.\Analyze-GitHubPackages.ps1 -LocalReposRoot 'D:\works' -GitHubOrg gitHubOrganization -GitHubToken 'YOUR_TOKEN_with_organization_permissions' -MaxRepos 150 -IncludeForks -IncludeArchived -PackageListFile '.\list_npm_package.txt' -MatchesOnly
```

### Copilot Instructions

See `COPILOT_INSTRUCTIONS.md` for full AI / Copilot contribution guidelines and a ready-to-copy prompt.