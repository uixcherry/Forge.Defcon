# Create Release with exe (when GitHub Actions blocked by billing)
# Usage: $env:GITHUB_TOKEN = "ghp_xxx"; .\create-release.ps1

$ErrorActionPreference = "Stop"
$repo = "uixcherry/Forge.Defcon"
$tag = "v1.0.0"
$exePath = "publish\Forge.Defcon.exe"

if (-not $env:GITHUB_TOKEN) {
  Write-Host "Set GITHUB_TOKEN: `$env:GITHUB_TOKEN = 'ghp_your_token'" -ForegroundColor Yellow
  Write-Host "Token: GitHub -> Settings -> Developer settings -> Personal access tokens (repo)" -ForegroundColor Gray
  exit 1
}

Write-Host "Building exe..." -ForegroundColor Cyan
Push-Location Forge.Defcon
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o ../publish
Pop-Location

if (-not (Test-Path $exePath)) {
  Write-Host "Error: exe not created" -ForegroundColor Red
  exit 1
}

$headers = @{
  "Authorization" = "token $env:GITHUB_TOKEN"
  "Accept"        = "application/vnd.github.v3+json"
}

$body = @{
  tag_name = $tag
  name     = $tag
  body     = "## Forge Defcon v1.0.0`n`nPC scanner for cheats, prohibited software, DMA hardware.`n`n**Requirements:** Windows 10/11 x64 (self-contained, no .NET needed)`n`n**Download:** Forge.Defcon.exe (~130 MB)"
} | ConvertTo-Json

Write-Host "Creating Release $tag..." -ForegroundColor Cyan
try {
  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases" -Headers $headers -Method Post -Body $body -ContentType "application/json; charset=utf-8"
} catch {
  if ($_.Exception.Response.StatusCode -eq 422) {
    Write-Host "Release $tag already exists. Delete it on GitHub or use another tag." -ForegroundColor Yellow
    exit 1
  }
  throw
}

$uploadUrl = $release.upload_url -replace "\{.*", "?name=Forge.Defcon.exe"
Write-Host "Uploading exe..." -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $exePath))
Invoke-RestMethod -Uri $uploadUrl -Headers $headers -Method Post -Body $bytes -ContentType "application/octet-stream" | Out-Null

Write-Host "Done: https://github.com/$repo/releases/tag/$tag" -ForegroundColor Green
