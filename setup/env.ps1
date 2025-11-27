param(
    [Parameter(Mandatory = $false)]
    [string]$GhidraPath
)

Write-Host "[+] Ghidra 환경 변수 설정을 시작합니다."

if (-not $GhidraPath) {
    Write-Host "[!] 사용법: .\setup\env.ps1 <Ghidra 설치 경로>"
    Write-Host "예: .\setup\env.ps1 `$env:USERPROFILE\Tools\ghidra_11.4.2_PUBLIC"
    exit
}

$GhidraPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($GhidraPath)

Write-Host "[*] 입력된 GHIDRA_PATH: $GhidraPath"

if (-Not (Test-Path $GhidraPath)) {
    Write-Host "[!] 경고: Ghidra 디렉토리가 존재하지 않습니다: $GhidraPath"
    Write-Host "[!] 설치 후 다시 실행해주세요."
    exit
}

$currentGhidraHome = [Environment]::GetEnvironmentVariable("GHIDRA_HOME", "User")

if ($currentGhidraHome -eq $GhidraPath) {
    Write-Host "[=] GHIDRA_HOME 은 이미 설정되어 있습니다."
} else {
    Write-Host "[+] GHIDRA_HOME 설정 중..."
    [Environment]::SetEnvironmentVariable("GHIDRA_HOME", $GhidraPath, "User")
}

$supportPath = "$GhidraPath\support"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($currentPath -like "*$supportPath*") {
    Write-Host "[=] PATH 에 이미 support 경로가 존재합니다."
} else {
    Write-Host "[+] PATH 에 support 경로 추가..."
    $newPath = "$supportPath;$currentPath"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

$profilePath = "$PROFILE"

if (-Not (Test-Path $profilePath)) {
    Write-Host "[*] PowerShell 프로필이 없어 생성합니다: $profilePath"
    New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

# 기존 alias 중복 검사
if (Select-String -Path $profilePath -Pattern "Set-Alias ghidra" -Quiet) {
    Write-Host "[=] ghidra alias가 이미 존재합니다."
} else {
    Write-Host "[+] ghidra alias 추가..."
    Add-Content -Path $profilePath -Value "`n# Ghidra alias`nSet-Alias ghidra `"$GhidraPath\ghidraRun.bat`""
}

Write-Host "[+] 설정 즉시 적용..."
. $profilePath

Write-Host "[✔] Ghidra 환경 구성 완료! 이제 PowerShell에서 'ghidra' 명령어를 사용할 수 있습니다."
