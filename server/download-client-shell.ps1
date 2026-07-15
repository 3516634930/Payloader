[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Url,

  [Parameter(Mandatory = $true)]
  [string]$Destination,

  [Parameter(Mandatory = $true)]
  [long]$ExpectedSize,

  [Parameter(Mandatory = $true)]
  [int]$TimeoutMs
)

$ErrorActionPreference = 'Stop'
$allowedHosts = @(
  'api.github.com',
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com'
)

function Assert-AllowedUri {
  param([System.Uri]$Uri)

  if (
    $null -eq $Uri `
    -or $Uri.Scheme -ne 'https' `
    -or $Uri.UserInfo `
    -or $allowedHosts -notcontains $Uri.Host.ToLowerInvariant()
  ) {
    throw 'Untrusted official client shell asset URL.'
  }
}

if ($ExpectedSize -le 0 -or $TimeoutMs -le 0) {
  throw 'Invalid official client shell download parameters.'
}

$source = [System.Uri]::new($Url)
Assert-AllowedUri -Uri $source
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$destinationDirectory = [System.IO.Path]::GetDirectoryName($destinationPath)
[System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
if ([System.IO.File]::Exists($destinationPath)) {
  throw 'Official client shell temporary file already exists.'
}

Add-Type -AssemblyName System.Net.Http
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
$client.DefaultRequestHeaders.UserAgent.ParseAdd('Payloader-Client-Shells')
$client.DefaultRequestHeaders.Accept.ParseAdd('application/octet-stream')
$token = [string]$env:PAYLOADER_CLIENT_SHELL_TOKEN
if ($null -ne $token) { $token = $token.Trim() }
$cancellation = [System.Threading.CancellationTokenSource]::new($TimeoutMs)
$response = $null
$request = $null
$inputStream = $null
$outputStream = $null
$completed = $false

try {
  $current = $source
  for ($redirectCount = 0; $redirectCount -le 5; $redirectCount += 1) {
    Assert-AllowedUri -Uri $current
    $request = [System.Net.Http.HttpRequestMessage]::new(
      [System.Net.Http.HttpMethod]::Get,
      $current
    )
    if ($current.Host.ToLowerInvariant() -eq 'api.github.com') {
      $request.Headers.Add('X-GitHub-Api-Version', '2022-11-28')
      if (-not [string]::IsNullOrWhiteSpace($token)) {
        $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
      }
    }
    $response = $client.SendAsync(
      $request,
      [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
      $cancellation.Token
    ).GetAwaiter().GetResult()
    $request.Dispose()
    $request = $null
    $statusCode = [int]$response.StatusCode
    if ($statusCode -ge 300 -and $statusCode -lt 400) {
      if ($redirectCount -eq 5 -or $null -eq $response.Headers.Location) {
        throw 'Invalid client shell download redirect.'
      }
      $next = if ($response.Headers.Location.IsAbsoluteUri) {
        $response.Headers.Location
      } else {
        [System.Uri]::new($current, $response.Headers.Location)
      }
      Assert-AllowedUri -Uri $next
      $response.Dispose()
      $response = $null
      $current = $next
      continue
    }
    break
  }

  if ($null -eq $response) {
    throw 'Official client shell download did not return a response.'
  }
  $null = $response.EnsureSuccessStatusCode()
  $declaredSize = $response.Content.Headers.ContentLength
  if ($null -ne $declaredSize -and [long]$declaredSize -ne $ExpectedSize) {
    throw 'Client shell download size mismatch.'
  }

  $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
  $outputStream = [System.IO.FileStream]::new(
    $destinationPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None,
    81920,
    [System.IO.FileOptions]::SequentialScan
  )
  $buffer = New-Object byte[] 81920
  $received = [long]0
  while ($true) {
    $read = $inputStream.ReadAsync(
      $buffer,
      0,
      $buffer.Length,
      $cancellation.Token
    ).GetAwaiter().GetResult()
    if ($read -le 0) { break }
    $received += [long]$read
    if ($received -gt $ExpectedSize) {
      throw 'Client shell download exceeded the declared size.'
    }
    $outputStream.WriteAsync(
      $buffer,
      0,
      $read,
      $cancellation.Token
    ).GetAwaiter().GetResult()
  }
  $outputStream.Flush($true)
  if ($received -ne $ExpectedSize -or $outputStream.Length -ne $ExpectedSize) {
    throw 'Client shell download size mismatch.'
  }
  $completed = $true
} finally {
  if ($null -ne $outputStream) { $outputStream.Dispose() }
  if ($null -ne $inputStream) { $inputStream.Dispose() }
  if ($null -ne $request) { $request.Dispose() }
  if ($null -ne $response) { $response.Dispose() }
  $cancellation.Dispose()
  $client.Dispose()
  $handler.Dispose()
  if (-not $completed -and [System.IO.File]::Exists($destinationPath)) {
    [System.IO.File]::Delete($destinationPath)
  }
}
