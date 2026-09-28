$ErrorActionPreference = "Stop"

$Version = "dev"
$OutDir = "dist"
$Clean = $false
$SkipTests = $false
$NoColor = $false
$NoArchives = $false
$Targets = @(
    "windows/386",
    "windows/amd64",
    "windows/arm64",
    "linux/386",
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64"
)

function Show-Usage {
    Write-Host @"
Usage: .\scripts\release.ps1 [options]

Options:
  --version VALUE      Version label used in output names. Default: dev
  --out-dir PATH       Directory for release artifacts. Default: dist
  --clean              Remove the output directory before building
  --skip-tests         Skip go test ./...
  --targets LIST       Comma-separated GOOS/GOARCH targets
  --no-archives        Build binaries without zip/tar.gz release bundles
  --no-color           Disable colored status output
  --help               Show this help

Default targets:
  windows/386, windows/amd64, windows/arm64,
  linux/386, linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64
"@
}

function Read-OptionValue {
    param(
        [string]$Name,
        [int]$Index,
        [object[]]$Arguments
    )

    if ($Index + 1 -ge $Arguments.Count) {
        throw "$Name requires a value"
    }

    $value = [string]$Arguments[$Index + 1]
    if ($value.StartsWith("--")) {
        throw "$Name requires a value"
    }

    return $value
}

for ($i = 0; $i -lt $args.Count; $i++) {
    $arg = [string]$args[$i]
    switch ($arg) {
        "--version" {
            $Version = Read-OptionValue -Name $arg -Index $i -Arguments $args
            $i++
        }
        "--out-dir" {
            $OutDir = Read-OptionValue -Name $arg -Index $i -Arguments $args
            $i++
        }
        "--clean" {
            $Clean = $true
        }
        "--skip-tests" {
            $SkipTests = $true
        }
        "--no-color" {
            $NoColor = $true
        }
        "--no-archives" {
            $NoArchives = $true
        }
        "--targets" {
            $targetValue = Read-OptionValue -Name $arg -Index $i -Arguments $args
            $Targets = @($targetValue)
            $i++
        }
        "--help" {
            Show-Usage
            exit 0
        }
        default {
            if ($arg.StartsWith("-")) {
                throw "Unknown option '$arg'. Release script options use --long-form names. Run --help for usage."
            }
            throw "Unexpected positional argument '$arg'. Run --help for usage."
        }
    }
}

function Write-ReleaseStatus {
    param(
        [string]$Kind,
        [string]$Message,
        [string]$Color = "White"
    )

    $prefix = "[$Kind]"
    if ($NoColor) {
        Write-Host "$prefix $Message"
        return
    }

    Write-Host $prefix -ForegroundColor $Color -NoNewline
    Write-Host " $Message"
}

function Write-ReleaseWarning {
    param([string]$Message)

    if ($NoColor) {
        Write-Warning $Message
        return
    }

    Write-Host "[warn]" -ForegroundColor Yellow -NoNewline
    Write-Host " $Message"
}

function Get-ArchLabel {
    param([string]$Arch)

    switch ($Arch) {
        "386" { return "x86" }
        "amd64" { return "x64" }
        default { return $Arch }
    }
}

function Assert-PathInsideRepo {
    param(
        [string]$RepoRoot,
        [string]$Path
    )

    $repoFullPath = [System.IO.Path]::GetFullPath($RepoRoot)
    $targetFullPath = [System.IO.Path]::GetFullPath($Path)

    if (-not $repoFullPath.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $repoFullPath += [System.IO.Path]::DirectorySeparatorChar
    }

    if (-not $targetFullPath.StartsWith($repoFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside repo root: $targetFullPath"
    }
}

function Get-BuildCommit {
    $commit = "unknown"
    try {
        $gitCommit = git rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitCommit)) {
            $commit = $gitCommit.Trim()
        }
    }
    catch {
        $commit = "unknown"
    }
    return $commit
}

function Get-ChecksumLine {
    param(
        [string]$Path,
        [string]$Name
    )

    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    return "$hash  $Name"
}

function Copy-ReleasePackageItem {
    param(
        [string]$RepoRoot,
        [string]$PackageRoot,
        [string]$RelativePath
    )

    $source = Join-Path $RepoRoot $RelativePath
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination $PackageRoot -Recurse -Force
    }
}

function New-ReleaseArchive {
    param(
        [string]$DistRoot,
        [string]$PackageName,
        [string]$PackageRoot,
        [string]$Goos
    )

    if ($Goos -eq "windows") {
        $archiveName = "$PackageName.zip"
        $archivePath = Join-Path $DistRoot $archiveName
        Compress-Archive -LiteralPath $PackageRoot -DestinationPath $archivePath -Force
        return $archiveName
    }

    $tarCommand = Get-Command tar -ErrorAction SilentlyContinue
    if ($null -eq $tarCommand) {
        Write-ReleaseWarning "Skipping archive for $PackageName because tar was not found"
        return ""
    }

    $archiveName = "$PackageName.tar.gz"
    $archivePath = Join-Path $DistRoot $archiveName
    & tar -czf $archivePath -C $DistRoot $PackageName
    return $archiveName
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$distRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutDir))
$targetList = @()
foreach ($target in $Targets) {
    $targetList += $target.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
}

Assert-PathInsideRepo -RepoRoot $repoRoot -Path $distRoot
Set-Location $repoRoot

if ($Clean -and (Test-Path -LiteralPath $distRoot)) {
    Remove-Item -LiteralPath $distRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null

if (-not $SkipTests) {
    Write-ReleaseStatus -Kind "test" -Message "go test ./..." -Color "Cyan"
    go test ./...
}

$supportedTargets = @{}
go tool dist list | ForEach-Object {
    $supportedTargets[$_] = $true
}

$safeVersion = $Version -replace '[^A-Za-z0-9._-]', '-'
$buildCommit = Get-BuildCommit
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$builds = @()
$checksums = @()
$oldCGO = $env:CGO_ENABLED
$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH

try {
    foreach ($target in $targetList) {
        $parts = $target.Split("/")
        if ($parts.Count -ne 2) {
            Write-ReleaseWarning "Skipping invalid target '$target'; expected GOOS/GOARCH"
            continue
        }

        $goos = $parts[0]
        $goarch = $parts[1]
        $targetName = "$goos/$goarch"

        if (-not $supportedTargets.ContainsKey($targetName)) {
            Write-ReleaseWarning "Skipping unsupported Go target: $targetName"
            continue
        }

        $archLabel = Get-ArchLabel -Arch $goarch
        $extension = ""
        if ($goos -eq "windows") {
            $extension = ".exe"
        }

        $outputName = "catsonbroadway-$safeVersion-$goos-$archLabel$extension"
        $outputPath = Join-Path $distRoot $outputName
        $packageName = "catsonbroadway-$safeVersion-$goos-$archLabel"
        $packageRoot = Join-Path $distRoot $packageName

        Write-ReleaseStatus -Kind "build" -Message "$targetName -> $outputName" -Color "Green"
        $env:CGO_ENABLED = "0"
        $env:GOOS = $goos
        $env:GOARCH = $goarch

        $ldflags = "-s -w -X main.buildVersion=$safeVersion -X main.buildCommit=$buildCommit -X main.buildDate=$buildDate -X main.buildTarget=$targetName"
        go build -trimpath -ldflags $ldflags -o $outputPath .

        $built = Get-Item -LiteralPath $outputPath
        $checksums += Get-ChecksumLine -Path $outputPath -Name $built.Name
        $archiveName = ""
        if (-not $NoArchives) {
            Write-ReleaseStatus -Kind "archive" -Message "$targetName -> $packageName" -Color "Cyan"
            if (Test-Path -LiteralPath $packageRoot) {
                Remove-Item -LiteralPath $packageRoot -Recurse -Force
            }
            New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null
            try {
                Copy-Item -LiteralPath $outputPath -Destination $packageRoot -Force
                Copy-ReleasePackageItem -RepoRoot $repoRoot -PackageRoot $packageRoot -RelativePath "README.md"
                Copy-ReleasePackageItem -RepoRoot $repoRoot -PackageRoot $packageRoot -RelativePath "cert_config.json"
                Copy-ReleasePackageItem -RepoRoot $repoRoot -PackageRoot $packageRoot -RelativePath "headers.json"
                Copy-ReleasePackageItem -RepoRoot $repoRoot -PackageRoot $packageRoot -RelativePath "stage_options"
                Copy-ReleasePackageItem -RepoRoot $repoRoot -PackageRoot $packageRoot -RelativePath "payload_options"
                $archiveName = New-ReleaseArchive -DistRoot $distRoot -PackageName $packageName -PackageRoot $packageRoot -Goos $goos
                if ($archiveName -ne "") {
                    $checksums += Get-ChecksumLine -Path (Join-Path $distRoot $archiveName) -Name $archiveName
                }
            }
            finally {
                if (Test-Path -LiteralPath $packageRoot) {
                    Remove-Item -LiteralPath $packageRoot -Recurse -Force
                }
            }
        }
        $builds += [PSCustomObject]@{
            Target  = $targetName
            File    = $built.Name
            Archive = $archiveName
            Size    = $built.Length
        }
    }
}
finally {
    $env:CGO_ENABLED = $oldCGO
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
}

if ($checksums.Count -gt 0) {
    Set-Content -LiteralPath (Join-Path $distRoot "SHA256SUMS.txt") -Value $checksums
}

Write-Host ""
Write-ReleaseStatus -Kind "done" -Message "Release artifacts written to $distRoot" -Color "Magenta"
$builds | Format-Table -AutoSize
