# 필요한 디렉토리 생성
New-Item -ItemType Directory -Force -Path "./static/project" | Out-Null
New-Item -ItemType Directory -Force -Path "./static/META" | Out-Null
New-Item -ItemType Directory -Force -Path "./reports/hook" | Out-Null
New-Item -ItemType Directory -Force -Path "./frida_scripts" | Out-Null
New-Item -ItemType Directory -Force -Path "./.log" | Out-Null

Write-Host "[+] 디렉토리 구조 생성 완료!"
