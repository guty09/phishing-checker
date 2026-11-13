# Project-local Maven launcher. Sets storage locations for this process only.
# Run backend builds through this script so the wrapper distribution and temp files stay on D:.
$ErrorActionPreference = 'Stop'

$MavenUserHome = 'D:\Cyber\Maven\home'
$TempDirectory = 'D:\Cyber\Temp'
$TmpDirProperty = "-Djava.io.tmpdir=$TempDirectory"

foreach ($directory in @($MavenUserHome, $TempDirectory)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

function Set-JavaIoTmpDir {
    param([AllowNull()][string]$Options)

    if ([string]::IsNullOrWhiteSpace($Options)) {
        return $TmpDirProperty
    }

    $pattern = '(?i)(^|\s)-Djava\.io\.tmpdir=(?:"[^"]*"|''[^'']*''|\S+)'
    $updated = [regex]::Replace($Options, $pattern, {
            param($match)
            return $match.Groups[1].Value + $TmpDirProperty
        })
    if ($updated -eq $Options) {
        return "$Options $TmpDirProperty"
    }
    return $updated
}

$savedMavenUserHome = $env:MAVEN_USER_HOME
$savedTemp = $env:TEMP
$savedTmp = $env:TMP
$savedMavenOpts = $env:MAVEN_OPTS
$exitCode = 1

try {
    $env:MAVEN_USER_HOME = $MavenUserHome
    $env:TEMP = $TempDirectory
    $env:TMP = $TempDirectory
    $env:MAVEN_OPTS = Set-JavaIoTmpDir -Options $savedMavenOpts

    & "$PSScriptRoot\mvnw.cmd" @args
    if ($null -eq $LASTEXITCODE) {
        $exitCode = 0
    } else {
        $exitCode = $LASTEXITCODE
    }
} finally {
    $env:MAVEN_USER_HOME = $savedMavenUserHome
    $env:TEMP = $savedTemp
    $env:TMP = $savedTmp
    $env:MAVEN_OPTS = $savedMavenOpts
}

if ($MyInvocation.InvocationName -eq '.') {
    $global:LASTEXITCODE = $exitCode
} else {
    exit $exitCode
}
