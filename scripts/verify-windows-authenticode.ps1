[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$ArtifactDirectory = '',

  [Parameter(Mandatory = $false)]
  [string]$PreparedApplicationDirectory = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ArtifactDirectory) -and [string]::IsNullOrWhiteSpace($PreparedApplicationDirectory)) {
  $ArtifactDirectory = 'artifacts/client-shells'
}

if (-not [string]::IsNullOrWhiteSpace($ArtifactDirectory) -and -not [string]::IsNullOrWhiteSpace($PreparedApplicationDirectory)) {
  throw 'Specify either -ArtifactDirectory or -PreparedApplicationDirectory, not both.'
}

function Assert-ValidAuthenticodeSignature {
  param(
    [Parameter(Mandatory = $true)]
    [string]$LiteralPath
  )

  $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "Authenticode verification failed for '$LiteralPath': $($signature.Status) $($signature.StatusMessage)"
  }
  if ($null -eq $signature.SignerCertificate) {
    throw "Authenticode verification returned no signer certificate for '$LiteralPath'."
  }

  Write-Host "Valid Authenticode signature: $LiteralPath"
  Write-Host "  Publisher: $($signature.SignerCertificate.Subject)"
  Write-Host "  Thumbprint: $($signature.SignerCertificate.Thumbprint)"
}

function Resolve-ExistingDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$LiteralPath
  )

  $resolved = (Resolve-Path -LiteralPath $LiteralPath).Path
  if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
    throw "Directory does not exist: $LiteralPath"
  }
  return $resolved
}

function Assert-InsideDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$Candidate
  )

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
  $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
  if (-not $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Path escapes the expected root: $Candidate"
  }
}

function Assert-PreparedApplicationSignatures {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PreparedRoot
  )

  $metadataFiles = @(Get-ChildItem -LiteralPath $PreparedRoot -Recurse -File -Filter 'windows-signing-input.json')
  if ($metadataFiles.Count -ne 1) {
    throw "Expected exactly one windows-signing-input.json under '$PreparedRoot', found $($metadataFiles.Count)."
  }

  $metadata = Get-Content -LiteralPath $metadataFiles[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($metadata.format -ne 'payloader-windows-signing-input' -or [int]$metadata.version -ne 1) {
    throw 'Windows signing metadata format is invalid.'
  }
  if (-not ([string]$metadata.appVersion -match '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')) {
    throw 'Windows signing app version is invalid.'
  }

  $targets = @($metadata.targets)
  if ($targets.Count -eq 0) {
    throw 'Windows signing metadata contains no targets.'
  }

  $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($target in $targets) {
    $targetId = [string]$target.id
    $relativePath = [string]$target.applicationPath
    $executableName = [string]$target.executable
    if ([string]::IsNullOrWhiteSpace($targetId) -or [string]::IsNullOrWhiteSpace($relativePath) -or [string]::IsNullOrWhiteSpace($executableName)) {
      throw 'Windows signing metadata target is incomplete.'
    }
    if (-not $seen.Add($targetId)) {
      throw "Duplicate Windows signing target: $targetId"
    }
    if ([System.IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
      throw "Unsafe Windows signing application path: $relativePath"
    }
    if ($executableName -ne 'Payloader.exe') {
      throw "Unexpected Windows executable name for ${targetId}: $executableName"
    }

    $nativeRelativePath = $relativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
    $applicationDirectory = Join-Path -Path $PreparedRoot -ChildPath $nativeRelativePath
    Assert-InsideDirectory -Root $PreparedRoot -Candidate $applicationDirectory
    $executablePath = Join-Path -Path $applicationDirectory -ChildPath $executableName
    Assert-InsideDirectory -Root $PreparedRoot -Candidate $executablePath
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
      throw "Prepared Windows executable is missing for ${targetId}: $executablePath"
    }
    Assert-ValidAuthenticodeSignature -LiteralPath $executablePath
  }

  Write-Host "Verified $($targets.Count) prepared Windows application executable(s)."
}

if (-not [string]::IsNullOrWhiteSpace($PreparedApplicationDirectory)) {
  $preparedRoot = Resolve-ExistingDirectory -LiteralPath $PreparedApplicationDirectory
  Assert-PreparedApplicationSignatures -PreparedRoot $preparedRoot
  return
}

$artifactRoot = Resolve-ExistingDirectory -LiteralPath $ArtifactDirectory
$installers = @(Get-ChildItem -LiteralPath $artifactRoot -File -Filter 'Payloader-Client-Setup-*.exe')
if ($installers.Count -eq 0) {
  throw "No Windows client installers were found in '$artifactRoot'."
}

foreach ($installer in $installers) {
  Assert-ValidAuthenticodeSignature -LiteralPath $installer.FullName
}

$archives = @(Get-ChildItem -LiteralPath $artifactRoot -File -Filter 'payloader-shell-windows-*.tar.gz')
if ($archives.Count -eq 0) {
  throw "No Windows client shell archives were found in '$artifactRoot'."
}

$tarCommand = Get-Command 'tar.exe' -ErrorAction Stop
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "payloader-authenticode-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

try {
  foreach ($archive in $archives) {
    $extractDirectory = Join-Path $temporaryRoot $archive.BaseName.Replace('.', '-')
    New-Item -ItemType Directory -Path $extractDirectory | Out-Null
    & $tarCommand.Source -xzf $archive.FullName -C $extractDirectory
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to extract '$($archive.FullName)' with exit code $LASTEXITCODE."
    }

    $executables = @(Get-ChildItem -LiteralPath $extractDirectory -Recurse -File -Filter '*.exe')
    if ($executables.Count -eq 0) {
      throw "No Windows executables were found in '$($archive.FullName)'."
    }
    foreach ($executable in $executables) {
      Assert-ValidAuthenticodeSignature -LiteralPath $executable.FullName
    }
  }
} finally {
  Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Verified $($installers.Count) installer(s) and $($archives.Count) Windows shell archive(s)."
