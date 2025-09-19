<#
GitHub Repository & Local Folder Package Analyzer

Features:
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
.\Analyze-GitHubPackages.ps1 -LocalReposRoot 'D:\clones' -LocalOnly -PackageListFile '.\list_npm_package.txt'  -MaxRepos 150
Combine GitHub + local:
.\Analyze-GitHubPackages.ps1 -GitHubUser gitHubUser -GitHubToken YOUR_TOKEN -LocalReposRoot 'D:\clones' -IncludeForks -IncludeArchived  -MaxRepos 150 -MatchesOnly
wITH GitHubOrg:
.\Analyze-GitHubPackages.ps1 -GitHubOrg gitHubOrg -GitHubToken YOUR_TOKEN -IncludeForks -IncludeArchived  -MaxRepos 150 -MatchesOnly
#>

param(
  [string]$GitHubUser = 'gitHubUser',
  [string]$GitHubOrg = $null,
  [string]$PackageListFile = '.\list_npm_package.txt',
  [string]$OutputFile = '.\package_analysis_results.txt',
  [string]$GitHubToken = $null,
  [int]$MaxRepos = 0,
  [switch]$IncludeForks,
  [switch]$IncludeArchived,
  [switch]$VerboseMode,
  [switch]$RequireVersionMatch,
  [switch]$RequireBothVersionMatch,
  [string]$LocalReposRoot = $null,
  [switch]$LocalOnly,
  [switch]$MatchesOnly
)

$ErrorActionPreference = 'Stop'
$Global:__ETagCache    = @{}
$Global:__ContentCache = @{}
$Global:__LastRateInfo = $null

function Write-Line { param([string]$Text) Write-Host $Text; Add-Content -Path $OutputFile -Value $Text }
function Write-DebugLine { param([string]$Msg) if ($VerboseMode) { Write-Host "[DBG] $Msg" -ForegroundColor DarkGray } }

function Wait-For-RateLimit {
  param($Headers)
  if (-not $Headers) { return }
  [int]$remain=0; [long]$reset=0
  [int]::TryParse(($Headers['X-RateLimit-Remaining']|Select-Object -First 1),[ref]$remain)|Out-Null
  [long]::TryParse(($Headers['X-RateLimit-Reset']|Select-Object -First 1),[ref]$reset)|Out-Null
  if ($remain -le 1 -and $reset -gt 0) {
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $delay=($reset - $now)+2
    if ($delay -gt 0 -and $delay -lt 900) {
      Write-Host "Rate limit near exhaustion. Sleeping $delay s..." -ForegroundColor Yellow
      Start-Sleep -Seconds $delay
    }
  }
}

function Invoke-GH {
  param([string]$Url,[int]$MaxRetry=5)
  $headers=@{ 'User-Agent'='PS-Pkg-Scan'; 'Accept'='application/vnd.github+json' }
  if ($GitHubToken){ $headers.Authorization="Bearer $GitHubToken" }
  $attempt=0
  while ($attempt -le $MaxRetry){
    try{
      Write-DebugLine "GET $Url (attempt $attempt)"
      $resp=Invoke-WebRequest -Uri $Url -Headers $headers -Method GET -ErrorAction Stop
      Wait-For-RateLimit $resp.Headers
      $Global:__LastRateInfo=@{Remaining=$resp.Headers['X-RateLimit-Remaining'];Reset=$resp.Headers['X-RateLimit-Reset']}
      if ($resp.StatusCode -eq 200 -and $resp.Content){ return ($resp.Content|ConvertFrom-Json) }
      return $null
    }catch{
      $errResp=$_.Exception.Response
      if ($errResp){
        $status=$errResp.StatusCode.value__
        $rawBody=''
        try{$rawBody=(New-Object IO.StreamReader($errResp.GetResponseStream())).ReadToEnd()}catch{}
        if ($rawBody -match '"API rate limit exceeded"'){ Write-Host "Primary rate limit reached. Cooling 30s..." -ForegroundColor Yellow; Wait-For-RateLimit $errResp.Headers; Start-Sleep 30 }
        elseif ($rawBody -match '"secondary rate limit"'){ $back=[math]::Min(300,15*[math]::Pow(2,$attempt)); Write-Host "Secondary rate limit. Backoff $back s..." -ForegroundColor Yellow; Start-Sleep $back }
        elseif ($status -eq 404){ return $null }
        elseif ($status -eq 401 -or $status -eq 403){ Write-Host "Auth/perm issue ($status). Provide a token." -ForegroundColor Red; return $null }
      }
    }
    $attempt++; Start-Sleep -Milliseconds (200*$attempt)
  }
  $null
}

function Get-File {
  param([string]$User,[string]$Repo,[string]$Path)
  $url="https://api.github.com/repos/$User/$Repo/contents/$Path"
  if ($Global:__ContentCache.ContainsKey($url)){ Write-DebugLine "Cache hit $url"; return $Global:__ContentCache[$url] }
  $headers=@{ 'User-Agent'='PS-Pkg-Scan'; 'Accept'='application/vnd.github+json' }
  if ($GitHubToken){ $headers.Authorization="Bearer $GitHubToken" }
  if ($Global:__ETagCache.ContainsKey($url)){ $headers['If-None-Match']=$Global:__ETagCache[$url] }
  try{
    $resp=Invoke-WebRequest -Uri $url -Headers $headers -Method GET -ErrorAction Stop
    Wait-For-RateLimit $resp.Headers
    if ($resp.StatusCode -eq 200){
      $json=$resp.Content|ConvertFrom-Json
      if ($resp.Headers.ETag){ $Global:__ETagCache[$url]=$resp.Headers.ETag }
      if ($json.content){
        $decoded=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($json.content))
        $Global:__ContentCache[$url]=$decoded
        return $decoded
      }
    }
  }catch{
    $we=$_.Exception.Response
    if ($we){
      $status=$we.StatusCode.value__
      if ($status -eq 304){ return $Global:__ContentCache[$url] }
      if ($status -eq 404){ return $null }
      $body=''
      try{$body=(New-Object IO.StreamReader($we.GetResponseStream())).ReadToEnd()}catch{}
      if ($body -match '"API rate limit exceeded"'){
        Write-Host "File fetch rate limit. Pause 30s..." -ForegroundColor Yellow
        Start-Sleep 30
        return Get-File @PSBoundParameters
      }
    }
    return $null
  }
  $null
}

function Get-LocalFile {
  param([string]$RepoPath,[string]$Relative)
  $full = Join-Path -Path $RepoPath -ChildPath $Relative
  if (Test-Path $full) {
    try { return [IO.File]::ReadAllText($full,[Text.Encoding]::UTF8) } catch { return $null }
  }
  $null
}

# Version helpers
function Parse-PackageListLine {
  param([string]$Line)
  if (-not $Line -or ($Line.Trim()).Length -eq 0) { return $null }

  $raw = $Line.Trim()

  # 1. Parentheses syntax: name (spec[, spec2])
  if ($raw -match '^\s*([@A-Za-z0-9._\-\/]+)\s*(?:\(([^)]+)\))?\s*$'){
    $name=$matches[1]
    $ver=$null
    if ($matches[2]) { $ver = $matches[2].Trim() }
    $name = $name.TrimEnd(',')
    return [PSCustomObject]@{ Name=$name; VersionSpec=$ver }
  }

  # Helper to clean individual version tokens
  function _CleanVer([string]$t){
    if (-not $t) { return $null }
    $c=$t.Trim().Trim(',')
    if ($c -match '^@([~^=><]*[0-9])'){ $c = $c.Substring(1) }
    if ($c -eq '') { return $null }
    return $c
  }

  # 2. name@v1, v2, @v3 (multi versions after @)
  if ($raw -match '^(?<name>[@A-Za-z0-9._\-\/]+)@(?<vers>.+)$'){
    $name=$matches['name']
    $versRaw=$matches['vers']
    # Split on commas into candidate versions
    $parts = $versRaw -split ',' | ForEach-Object { _CleanVer $_ }
    $parts = $parts | Where-Object { $_ }
    $verSpec = ($parts -join ', ')
    return [PSCustomObject]@{ Name=$name; VersionSpec=$verSpec }
  }

  # 3. name <whitespace> version(s)  (e.g. scoped name followed by single version)
  if ($raw -match '^(?<name>[@A-Za-z0-9._\-\/]+)\s+(?<vers>[~^=><]*[0-9][0-9A-Za-z+\-.]*\s*(,\s*[@~^=><]*[0-9][0-9A-Za-z+\-.]*)*)$'){
    $name=$matches['name']
    $versRaw=$matches['vers']
    $parts = $versRaw -split ',' | ForEach-Object { _CleanVer $_ }
    $parts = $parts | Where-Object { $_ }
    $verSpec = ($parts -join ', ')
    return [PSCustomObject]@{ Name=$name; VersionSpec=$verSpec }
  }

  # 4. Fallback: line is only the package name (presence only)
  if ($raw -match '^[@A-Za-z0-9._\-\/]+$') {
    return [PSCustomObject]@{ Name=$raw; VersionSpec=$null }
  }

  $null
}
function Normalize-Version {
  param([string]$v)
  if (-not $v) { return $null }
  $v=$v.Trim() -replace '^[~^=><]*',''
  if ($v -match '^\d+(\.\d+){0,2}'){
    $core=$matches[0]; $parts=$core.Split('.')
    while ($parts.Count -lt 3){ $parts+='0' }
    return ($parts[0..2] -join '.')
  }
  $null
}
function Compare-SemVer {
  param([string]$A,[string]$B)
  $na=Normalize-Version $A; $nb=Normalize-Version $B
  if (-not $na -or -not $nb){ return $null }
  $pa=$na.Split('.')|ForEach-Object{[int]$_}; $pb=$nb.Split('.')|ForEach-Object{[int]$_}
  for($i=0;$i -lt 3;$i++){ if($pa[$i] -lt $pb[$i]){return -1}; if($pa[$i] -gt $pb[$i]){return 1} }
  0
}
function Test-VersionSpec {
  param([string]$Spec,[string]$Actual)
  if (-not $Spec){ return $true }
  if (-not $Actual){ return $false }
  $Spec=$Spec.Trim()
  # Allow comma-separated list of alternative specs (logical OR)
  if ($Spec -match ',') {
    foreach($part in ($Spec -split ',')) {
      $p=$part.Trim()
      if ($p) {
        if (Test-VersionSpec -Spec $p -Actual $Actual) { return $true }
      }
    }
    return $false
  }
  if ($Spec -eq '*'){ return $true }
  if ($Spec -match '^\^(\d+)(\.(\d+))?(\.(\d+))?'){
    $base=Normalize-Version $Spec; $act=Normalize-Version $Actual
    if (-not $base -or -not $act){ return $false }
    $b=$base.Split('.'); $a=$act.Split('.')
    if ($b[0] -ne $a[0]){ return $false }
    if ((Compare-SemVer $act $base) -lt 0){ return $false }
    return $true
  }
  if ($Spec -match '^~(\d+)(\.(\d+))?(\.(\d+))?'){
    $base=Normalize-Version $Spec; $act=Normalize-Version $Actual
    if (-not $base -or -not $act){ return $false }
    $b=$base.Split('.'); $a=$act.Split('.')
    if ($b[0] -ne $a[0]){ return $false }
    if ($b[1] -ne $a[1]){ return $false }
    if ((Compare-SemVer $act $base) -lt 0){ return $false }
    return $true
  }
  if ($Spec -match '^(>=|<=|>|<|==|=)\s*(\d+(\.\d+){0,2})$'){
    $op=$matches[1]; $ver=$matches[2]; $cmp=Compare-SemVer $Actual $ver
    if ($cmp -eq $null){ return $false }
    switch($op){
      '>' { return $cmp -gt 0 }
      '<' { return $cmp -lt 0 }
      '>=' { return $cmp -ge 0 }
      '<=' { return $cmp -le 0 }
      '=' { return $cmp -eq 0 }
      '==' { return $cmp -eq 0 }
    }
  }
  (Compare-SemVer $Actual $Spec) -eq 0
}

# Parsers
function Parse-PackageJson {
  param([string]$Content)
  $map=@{}
  try{
    $j=$Content|ConvertFrom-Json
    foreach($k in 'dependencies','devDependencies','peerDependencies','optionalDependencies'){
      $block=$j.$k
      if ($block){
        $block.PSObject.Properties|ForEach-Object{
          if(-not $map.ContainsKey($_.Name)){ $map[$_.Name]=$_.Value }
        }
      }
    }
  }catch{}
  $map
}
function Parse-PlainJsonDeps {
  param([string]$Content)
  $map=@{}
  try{
    $j=$Content|ConvertFrom-Json
    if ($j.dependencies){
      foreach($p in $j.dependencies.PSObject.Properties){
        $ver=$p.Value.version
        if(-not $ver -and $p.Value -isnot [pscustomobject]){ $ver=$p.Value }
        if(-not $map.ContainsKey($p.Name)){ $map[$p.Name]=$ver }
      }
    }
  }catch{}
  $map
}
function Parse-PnpmLock {
  param([string]$Content)
  $out=@()
  foreach($l in ($Content -split "`n")){
    if ($l -match '^\s*([^:\s]+):\s*$'){
      $n=$matches[1]
      if ($n -notmatch '^(dependencies|devDependencies|specifiers|lockfileVersion|\d+\.\d+)' -and
          $n -notmatch '^/' -and $n -match '^[a-zA-Z@]'){ $out += $n }
    }
  }
  $out|Sort-Object -Unique
}
function Parse-YarnLock {
  param([string]$Content)
  $set=New-Object System.Collections.Generic.HashSet[string]
  foreach($l in ($Content -split "`n")){
    if ($l -match '^[^ #"].+@'){
      $first=$l.Split('@')[0].Trim('"'' ')
      if ($first -and $first -notmatch '^(version|resolved|integrity)$'){ $null=$set.Add($first) }
    }
  }
  # PowerShell 5.1 may not expose ToArray() directly; enumerate instead
  @($set)
}

function Get-Repositories {
  param([string]$User,[string]$Org)
  if ($LocalOnly) { return @() }
  $isOrg = -not [string]::IsNullOrEmpty($Org)
  $targetName = if ($isOrg) { $Org } else { $User }
  if (-not $GitHubToken){
    $scope = if ($isOrg) { 'org' } else { 'user' }
    Write-DebugLine "Using REST for repositories ($scope scope)"
    $list=@(); $page=1
    do{
      if ($isOrg) {
        $u="https://api.github.com/orgs/$targetName/repos?per_page=100&page=$page&type=all&sort=updated"
      } else {
        $u="https://api.github.com/users/$targetName/repos?per_page=100&page=$page&type=all&sort=updated"
      }
      $batch=Invoke-GH $u
      if ($batch){
        foreach($b in $batch){
          if(-not $IncludeForks -and $b.fork){ continue }
          if(-not $IncludeArchived -and $b.archived){ continue }
          $list+=$b
          if($MaxRepos -gt 0 -and $list.Count -ge $MaxRepos){ break }
        }
        $page++
      } else { break }
      if($MaxRepos -gt 0 -and $list.Count -ge $MaxRepos){ break }
    }while($batch.Count -eq 100)
    return $list
  }
  $scope = if ($isOrg) { 'org' } else { 'user' }
  Write-DebugLine "Using GraphQL for repositories ($scope scope)"
  $repos=@(); $cursor=$null
  while($true){
    if([string]::IsNullOrEmpty($cursor)){ $afterValue='null' } else { $afterValue='"{0}"' -f $cursor }
    if ($isOrg) {
      $q=@"
query {
  organization(login: "$targetName") {
    repositories(
      first: 100,
      after: $afterValue,
      orderBy: { field: UPDATED_AT, direction: DESC }
    ) {
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        isFork
        isArchived
        description
        url
        updatedAt
      }
    }
  }
}
"@
    } else {
      $q=@"
query {
  user(login: "$targetName") {
    repositories(
      first: 100,
      after: $afterValue,
      orderBy: { field: UPDATED_AT, direction: DESC }
    ) {
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        isFork
        isArchived
        description
        url
        updatedAt
      }
    }
  }
}
"@
    }
    $payload=@{query=$q}|ConvertTo-Json -Depth 4
    $h=@{'Authorization'="Bearer $GitHubToken";'User-Agent'='PS-Pkg-Scan';'Accept'='application/vnd.github+json'}
    try{
      $resp=Invoke-WebRequest -Uri https://api.github.com/graphql -Headers $h -Method POST -Body $payload -ContentType 'application/json'
      $json=$resp.Content|ConvertFrom-Json
      if ($isOrg) {
        if(-not $json.data.organization){ break }
        $data=$json.data.organization.repositories
      } else {
        if(-not $json.data.user){ break }
        $data=$json.data.user.repositories
      }
    }catch{ Write-Host "GraphQL request failed: $($_.Exception.Message)" -ForegroundColor Red; break }
    foreach($n in $data.nodes){
      if(-not $IncludeForks -and $n.isFork){ continue }
      if(-not $IncludeArchived -and $n.isArchived){ continue }
      $repos+=[PSCustomObject]@{
        name=$n.name; html_url=$n.url; description=$n.description
        updated_at=$n.updatedAt; fork=$n.isFork; archived=$n.isArchived; IsLocal=$false
      }
      if($MaxRepos -gt 0 -and $repos.Count -ge $MaxRepos){ break }
    }
    if($MaxRepos -gt 0 -and $repos.Count -ge $MaxRepos){ break }
    if(-not $data.pageInfo.hasNextPage){ break }
    $cursor=$data.pageInfo.endCursor
  }
  $repos
}

function Get-LocalRepos {
  param([string]$Root)
  $results=@()
  if (-not $Root) { return $results }
  if (-not (Test-Path $Root)) {
    Write-Host "Local root not found: $Root" -ForegroundColor Yellow
    return $results
  }
  Write-DebugLine "Scanning local root: $Root"
  $dirs = Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue
  foreach ($d in $dirs) {
    $hasPkg = Test-Path (Join-Path $d.FullName 'package.json')
    $hasLock = Test-Path (Join-Path $d.FullName 'package-lock.json')
    $hasPnpm = Test-Path (Join-Path $d.FullName 'pnpm-lock.yaml')
    $hasYarn = Test-Path (Join-Path $d.FullName 'yarn.lock')
    if ($hasPkg -or $hasLock -or $hasPnpm -or $hasYarn) {
      $results += [PSCustomObject]@{
        name = $d.Name
        html_url = "file://$($d.FullName)"
        description = "Local repo"
        updated_at = $d.LastWriteTimeUtc
        fork = $false
        archived = $false
        IsLocal = $true
        LocalPath = $d.FullName
      }
    }
  }
  $results
}

# ----- Start -----
Write-Host "=== GitHub + Local Package Scan ===" -ForegroundColor Green
if ($GitHubOrg -and $GitHubUser -and $GitHubUser -ne 'gitHubUser') {
  Write-Error "Specify either -GitHubUser or -GitHubOrg, not both."; exit 1
}
if ($GitHubOrg) { $GitHubUser = $null }
if ($LocalOnly) {
  Write-Host "Mode: Local only" -ForegroundColor Cyan
} else {
    if ($GitHubOrg) { Write-Host "Target: Organization '$GitHubOrg'" -ForegroundColor Cyan } else { Write-Host "Target: User '$GitHubUser'" -ForegroundColor Cyan }
    if (-not $GitHubToken){ Write-Host "No token provided (remote limited to 60 req/hr)." -ForegroundColor Yellow } else { Write-Host "Token detected for remote scan." -ForegroundColor Green }
}

if (Test-Path $OutputFile){ Remove-Item $OutputFile -Force }

if (-not (Test-Path $PackageListFile)){ Write-Error "Package list file not found: $PackageListFile"; exit 1 }
$rawLines=Get-Content $PackageListFile | Where-Object { $_.Trim() -ne '' }
$targetObjs=@()
foreach($ln in $rawLines){
  $obj=Parse-PackageListLine $ln
  if($obj){ $targetObjs+=$obj }
}
if (-not $targetObjs -or $targetObjs.Count -eq 0){ Write-Error "No valid entries in package list."; exit 1 }

Write-Line "=== Package Scan ==="
if ($GitHubOrg) {
  Write-Line "GitHub Organization: $GitHubOrg"
} elseif ($GitHubUser) {
  Write-Line "GitHub User: $GitHubUser"
}
if ($LocalReposRoot) { Write-Line "Local Root: $LocalReposRoot" }
Write-Line "Entries: $($targetObjs.Count)"
foreach($o in $targetObjs){
  if ($o.VersionSpec){ Write-Line "- $($o.Name) ($($o.VersionSpec))" } else { Write-Line "- $($o.Name)" }
}
if ($RequireBothVersionMatch){
  Write-Line "Mode: Require BOTH Declared & Resolved to satisfy spec"
} elseif ($RequireVersionMatch){
  Write-Line "Mode: Require at least one side to satisfy spec"
} else {
  Write-Line "Mode: Version optional"
}
if ($MatchesOnly){ Write-Line "Output mode: MatchesOnly (only successful matches exported)" }
Write-Line ""

$remoteRepos = @()
if (-not $LocalOnly) {
  $owner = if ($GitHubOrg) { $GitHubOrg } else { $GitHubUser }
  $remoteRepos = Get-Repositories -User $GitHubUser -Org $GitHubOrg
  Write-Line "Remote repositories fetched: $($remoteRepos.Count) (owner=$owner)"
} else {
  Write-Line "Remote repositories skipped (LocalOnly)."
}

$localRepos = @()
if ($LocalReposRoot) {
  $localRepos = Get-LocalRepos -Root $LocalReposRoot
  Write-Line "Local repositories detected: $($localRepos.Count)"
}
Write-Line ""

$allRepos = @()
$allRepos += $remoteRepos
$allRepos += $localRepos

if (-not $allRepos -or $allRepos.Count -eq 0){
  Write-Line "No repositories to scan."
  exit 0
}

Write-Line "Total repositories to scan: $($allRepos.Count)"
Write-Line ""

$hits=@(); $totalMatches=0; $repoIndex=0
$matchedEntries=@()

foreach($r in $allRepos){
  $repoIndex++
  $origin = if ($r.PSObject.Properties.Name -contains 'IsLocal' -and $r.IsLocal) { 'LOCAL' } else { 'REMOTE' }
  Write-Host "[$repoIndex/$($allRepos.Count)] Repo: $($r.name) ($origin)" -ForegroundColor Cyan
  $repoName=$r.name

  $pkgMap=@{}
  $lockMap=@{}
  $allNames=New-Object System.Collections.Generic.HashSet[string]

  $pkgJson=$null; $packageLock=$null; $pnpmLock=$null; $yarnLock=$null

  if ($origin -eq 'LOCAL') {
    $pkgJson     = Get-LocalFile -RepoPath $r.LocalPath -Relative 'package.json'
    $packageLock = Get-LocalFile -RepoPath $r.LocalPath -Relative 'package-lock.json'
    $pnpmLock    = Get-LocalFile -RepoPath $r.LocalPath -Relative 'pnpm-lock.yaml'
    $yarnLock    = Get-LocalFile -RepoPath $r.LocalPath -Relative 'yarn.lock'
  } else {
    $owner = if ($GitHubOrg) { $GitHubOrg } else { $GitHubUser }
    $pkgJson     = Get-File $owner $repoName 'package.json'
    $packageLock = Get-File $owner $repoName 'package-lock.json'
    $pnpmLock    = Get-File $owner $repoName 'pnpm-lock.yaml'
    $yarnLock    = Get-File $owner $repoName 'yarn.lock'
  }

  if ($pkgJson){
    $pkgMap=Parse-PackageJson $pkgJson
    foreach($k in $pkgMap.Keys){ $null=$allNames.Add($k) }
  }
  if ($packageLock){
    $lockMap=Parse-PlainJsonDeps $packageLock
    foreach($k in $lockMap.Keys){ $null=$allNames.Add($k) }
  }
  if ($pnpmLock){
    foreach($n in (Parse-PnpmLock $pnpmLock)){ $null=$allNames.Add($n) }
  }
  if ($yarnLock){
    foreach($n in (Parse-YarnLock $yarnLock)){ $null=$allNames.Add($n) }
  }

  if ($allNames.Count -eq 0){ continue }

  $repoMatches=@()
  foreach($spec in $targetObjs){
    if ($allNames.Contains($spec.Name)){
      $declared=$null
      if ($pkgMap.ContainsKey($spec.Name)) { $declared=$pkgMap[$spec.Name] }
      $resolved=$null
      if ($lockMap.ContainsKey($spec.Name)) { $resolved=$lockMap[$spec.Name] }

      $declaredMatch=$false
      if ($declared) {
        $declaredMatch=Test-VersionSpec -Spec $spec.VersionSpec -Actual $declared
      } elseif (-not $spec.VersionSpec) {
        $declaredMatch=$true
      }

      $resolvedMatch=$false
      if ($resolved) {
        $resolvedMatch=Test-VersionSpec -Spec $spec.VersionSpec -Actual $resolved
      } elseif (-not $spec.VersionSpec) {
        $resolvedMatch=$true
      }

      if (-not $spec.VersionSpec){
        $versionMatch=$true
      } else {
        if ($RequireBothVersionMatch){
          $versionMatch=($declaredMatch -and $resolvedMatch -and $declared -and $resolved)
        } else {
          $versionMatch=($declaredMatch -or $resolvedMatch)
        }
      }

      if ($spec.VersionSpec -and $RequireVersionMatch -and -not $versionMatch){
        continue
      }

      if ($declaredMatch -and $resolvedMatch){ $matchSource='Both' }
      elseif ($declaredMatch){ $matchSource='Declared' }
      elseif ($resolvedMatch){ $matchSource='Resolved' }
      else { $matchSource='None' }

      $wantedValue=''
      if ($spec.VersionSpec){ $wantedValue=$spec.VersionSpec }
      $declaredValue=''
      if ($declared){ $declaredValue=$declared }
      $resolvedValue=''
      if ($resolved){ $resolvedValue=$resolved }

      $repoMatches += [PSCustomObject]@{
        Name          = $spec.Name
        Wanted        = $wantedValue
        Declared      = $declaredValue
        Resolved      = $resolvedValue
        DeclaredMatch = $declaredMatch
        ResolvedMatch = $resolvedMatch
        MatchSource   = $matchSource
        VersionMatch  = $versionMatch
        Source        = $origin
      }
    }
  }

  if ($repoMatches.Count -gt 0){
    $validCount = ($repoMatches | Where-Object { $_.VersionMatch }).Count
    $totalMatches += $validCount

    # Collect successful matches globally
    $repoMatches | Where-Object { $_.VersionMatch } | ForEach-Object {
      $matchedEntries += [PSCustomObject]@{
        Repo          = $repoName
        Source        = $origin
        Url           = $r.html_url
        Package       = $_.Name
        Wanted        = $_.Wanted
        Declared      = $_.Declared
        Resolved      = $_.Resolved
        DeclaredMatch = $_.DeclaredMatch
        ResolvedMatch = $_.ResolvedMatch
        MatchSource   = $_.MatchSource
      }
    }

    if (-not $MatchesOnly) {
      Write-Line "Repository: $repoName ($origin)"
      Write-Line "Location: $($r.html_url)"
      if ($r.PSObject.Properties.Name -contains 'updated_at'){ Write-Line "Updated: $($r.updated_at)" }
      Write-Line "Matched (count): $validCount (listed: $($repoMatches.Count))"
      foreach($m in $repoMatches){
        $flag = if ($m.VersionMatch) { '+' } else { '!' }
        Write-Line ("  {0} {1} Wanted={2} Declared={3}({4}) Resolved={5}({6}) SourceMatch={7}" -f $flag,$m.Name,$m.Wanted,$m.Declared,$m.DeclaredMatch,$m.Resolved,$m.ResolvedMatch,$m.MatchSource)
      }
      Write-Line ""
    }

    if (-not $MatchesOnly) {
      $detailList=@()
      foreach($m in $repoMatches){
        $detailList += ("{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}:{8}" -f $m.Name,$m.Wanted,$m.Declared,$m.Resolved,$m.DeclaredMatch,$m.ResolvedMatch,$m.MatchSource,$m.VersionMatch,$origin)
      }
      $hits += [PSCustomObject]@{
        Name    = $repoName
        Url     = $r.html_url
        Count   = $validCount
        Details = ($detailList -join '|')
        Source  = $origin
      }
    }
  }

  if ($origin -eq 'REMOTE') {
    Start-Sleep -Milliseconds 120
  }
}

Write-Line "=== Summary ==="
Write-Line "Repos scanned (total): $($allRepos.Count)"
if ($GitHubOrg) { Write-Line "Target organization: $GitHubOrg" } elseif ($GitHubUser) { Write-Line "Target user: $GitHubUser" }
Write-Line "Remote repos: $($remoteRepos.Count)"
Write-Line "Local repos: $($localRepos.Count)"
<#
Recompute authoritative match total from matchedEntries to ensure the
summary aligns with the exported matches file even if counting logic
above changes in future (defensive consistency).
#>
$computedTotal = $matchedEntries.Count
if ($computedTotal -ne $totalMatches) {
  Write-Line "Total version-satisfied matches (packages): $computedTotal (reconciled; previous counter=$totalMatches)"
} else {
  Write-Line "Total version-satisfied matches (packages): $computedTotal"
}
if ($RequireBothVersionMatch){
  Write-Line "Version mode: BOTH required"
} elseif ($RequireVersionMatch){
  Write-Line "Version mode: At least one side"
} else {
  Write-Line "Version mode: Optional"
}
if ($MatchesOnly){ Write-Line "Output mode: MatchesOnly" }

# Repo summary CSV (only if not MatchesOnly)
if (-not $MatchesOnly -and $hits.Count -gt 0){
  $csv=[IO.Path]::ChangeExtension($OutputFile,'csv')
  try{
    $hits | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Line "Repo summary CSV exported: $csv"
  }catch{
    Write-Host "Failed to write repo CSV: $($_.Exception.Message)" -ForegroundColor Red
  }
} elseif (-not $MatchesOnly) {
  Write-Line "No repositories with target packages."
}

# Matched packages CSV & JSON
if ($matchedEntries.Count -gt 0){
  $outDir = Split-Path -Parent $OutputFile
  if (-not $outDir -or $outDir -eq '') { $outDir='.' }
  $baseName = [IO.Path]::GetFileNameWithoutExtension($OutputFile)
  $matchCsv  = Join-Path $outDir ($baseName + '_matches.csv')
  $matchJson = Join-Path $outDir ($baseName + '_matches.json')
  try{
    $matchedEntries | Export-Csv -Path $matchCsv -NoTypeInformation -Encoding UTF8
    Write-Line "Matched packages CSV: $matchCsv"
  }catch{
    Write-Host "Failed writing matches CSV: $($_.Exception.Message)" -ForegroundColor Red
  }
  try{
    $matchedEntries | ConvertTo-Json -Depth 6 | Out-File -FilePath $matchJson -Encoding utf8
    Write-Line "Matched packages JSON: $matchJson"
  }catch{
    Write-Host "Failed writing matches JSON: $($_.Exception.Message)" -ForegroundColor Red
  }
} else {
  Write-Line "No matched packages to export."
}

if ($Global:__LastRateInfo -and -not $LocalOnly){
  Write-Line ("Remaining remote API quota approx: {0}" -f $Global:__LastRateInfo.Remaining)
}

Write-Line "Completed: $(Get-Date)"
Write-Host "Done. Output base: $OutputFile" -ForegroundColor Green
# End