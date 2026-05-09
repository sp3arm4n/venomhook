# VenomHook

<p align="center">
  <img src="assets/venomhook.png" alt="VenomHook logo" width="220">
</p>

<p align="center">
  <a href="https://github.com/sp3arm4n/venomhook/actions/workflows/ci.yml"><img src="https://github.com/sp3arm4n/venomhook/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

VenomHook은 네이티브 바이너리와 Android APK를 정적 분석해 후킹 후보 함수를 찾고, offset 기반 HookSpec과 Frida 스크립트를 생성하는 CLI 도구입니다.

```text
Binary/APK -> StaticMeta -> Endpoint scoring -> HookSpec -> Frida script -> Runtime report
```

PE, ELF, Mach-O를 같은 데이터 모델로 다루며, Android APK에서는 native library 추출, manifest 감사, Java native method 추출, JNI bridge 분석, PoC 번들 export까지 제공합니다.

이 도구는 권한이 있는 분석 대상에서 리버스 엔지니어링, 보안 검증, 동적 계측 자동화를 돕기 위한 용도입니다.

## Quick Start

가장 빠른 확인은 포함된 샘플 `StaticMeta`로 HookSpec과 Frida 스크립트를 생성하는 것입니다. Ghidra, Frida 실행 대상, Android 도구가 없어도 동작합니다.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .

venomhook offset-e2e \
  --static-json ./sample/examples/static_meta.sample.json \
  --target sample.exe \
  --out-dir ./out
```

생성되는 파일:

```text
out/
├── venomhook.json      # HookSpec JSON
├── venomhook.db        # HookSpec SQLite
├── venomhook.md        # HookSpec summary
└── venomhook.js        # Generated Frida script
```

생성된 스크립트 확인:

```bash
sed -n '1,120p' ./out/venomhook.js
```

## Install

기본 CLI:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

옵션 기능:

```bash
pip install -e '.[static]'   # lief 기반 PE/ELF/Mach-O metadata helper
pip install -e '.[dynamic]'  # Frida 실행 오케스트레이션
pip install -e '.[llm]'      # opt-in LLM 보조 기능
```

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .
```

## Common Commands

`pip install -e .` 이후에는 `venomhook` 명령을 바로 사용할 수 있습니다.

| 목적 | 명령 |
| --- | --- |
| 샘플 전체 흐름 실행 | `venomhook offset-e2e --static-json ./sample/examples/static_meta.sample.json --target sample.exe --out-dir ./out` |
| HookSpec만 생성 | `venomhook offset-static --static-json ./sample/examples/static_meta.sample.json --out ./out/venomhook.json --out-db ./out/venomhook.db` |
| Frida 스크립트 생성 | `venomhook offset-hook --hookspec ./out/venomhook.json --target sample.exe --out-script ./out/venomhook.js` |
| 실제 바이너리 Ghidra 분석 | `venomhook offset-static --binary ./path/to/target.exe --ghidra-headless analyzeHeadless --ghidra-script ./ghidra_scripts/export_staticmeta.py --out ./reports/hook/venomhook.json` |
| APK manifest 빠른 감사 | `venomhook android-audit --apk ./sample/myapp.apk --no-jadx --out-dir ./out_audit --audit-json ./out_audit/audit.json` |
| 실행 가능한 PoC 번들 생성 | `venomhook android-audit --apk ./sample/myapp.apk --out-dir ./out_audit --poc-bundle-dir ./out_audit/pocs` |
| Frida 로그 요약 | `venomhook offset-report-runtime --log ./logs/frida.log --out-md ./out/summary.md --out-html ./out/summary.html` |

## Requirements

| Tool | Required | Purpose |
| --- | --- | --- |
| Python 3.10+ | yes | CLI 실행 |
| Ghidra 11.x | real binary 분석 시 | Binary -> StaticMeta |
| Java/OpenJDK | Ghidra/apktool 사용 시 | Java 기반 도구 실행 |
| Frida 17.x | 동적 후킹 실행 시 | Generated script 실행 |
| lief | optional `.[static]` | PE/ELF/Mach-O module metadata |
| apktool | Android manifest 분석 시 | Binary AndroidManifest.xml decode |
| jadx | Android Java 분석 시 | DEX -> Java native method extraction |

외부 도구 경로는 환경 변수로 지정할 수 있습니다.

```bash
export VENOMHOOK_APKTOOL=/path/to/apktool
export VENOMHOOK_JADX=/path/to/jadx
```

VenomHook은 `jadx-gui`가 아니라 `jadx`/`jadx-cli` 같은 CLI wrapper를 실행합니다. Windows에서 jadx를 GUI로만 사용 중이라면 Java/JNI 분석은 `--no-jadx`로 건너뛰거나, Wiki의 [Installation](https://github.com/sp3arm4n/venomhook/wiki/Installation) 안내에 따라 `jadx.bat`/`jadx-cli.bat` 경로를 지정하세요.

Ghidra helper:

```bash
chmod +x ./setup/env.sh
./setup/env.sh "$HOME/tools/ghidra_11.4.2_PUBLIC"
```

## Documentation

상세 사용법은 GitHub Wiki로 분리했습니다. README는 처음 보는 사용자가 빠르게 설치하고 첫 결과를 얻는 데 집중합니다.

| 주제 | 링크 |
| --- | --- |
| 전체 문서 홈 | [Wiki Home](https://github.com/sp3arm4n/venomhook/wiki) |
| 첫 사용 전 환경 점검 | [Environment Checklist](https://github.com/sp3arm4n/venomhook/wiki/Environment-Checklist) |
| 설치와 외부 도구 설정 | [Installation](https://github.com/sp3arm4n/venomhook/wiki/Installation) |
| 네이티브 바이너리 분석 흐름 | [Core Workflow](https://github.com/sp3arm4n/venomhook/wiki/Core-Workflow) |
| Android APK 분석 흐름 | [Android Workflow](https://github.com/sp3arm4n/venomhook/wiki/Android-Workflow) |
| Manifest 감사와 PoC export | [Manifest Audit and PoC](https://github.com/sp3arm4n/venomhook/wiki/Manifest-Audit-and-PoC) |
| 선택형 LLM 보조 기능 | [LLM Layer](https://github.com/sp3arm4n/venomhook/wiki/LLM-Layer) |
| Python API 예시 | [Developer API](https://github.com/sp3arm4n/venomhook/wiki/Developer-API) |
| 개발, 구조, 프로젝트 레이아웃 | [Development and Architecture](https://github.com/sp3arm4n/venomhook/wiki/Development-and-Architecture) |

아키텍처 상세도는 [ARCHITECTURE.md](ARCHITECTURE.md)에도 유지합니다.

## Development

테스트:

```bash
python3 -m unittest discover -s ./sample/tests
```

`out/`, `static/META`, `static/project`, `reports`, `frida_scripts`, `.log`, `.venomhook-cache` 같은 생성 산출물은 Git에서 제외됩니다.

## Project Layout

```text
venomhook/
├── ghidra_scripts/
├── sample/
│   ├── examples/
│   └── tests/
├── setup/
├── src/venomhook/
├── ARCHITECTURE.md
├── pyproject.toml
└── README.md
```

대용량 APK나 로컬 바이너리 샘플은 원격 저장소에 올리지 않고, ignored path 아래에서 로컬 테스트 입력으로만 사용합니다.

## Credits

### 🏗️ Architect

<a href="https://github.com/sp3arm4n"><img src="https://img.shields.io/badge/GitHub-sp3arm4n-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - sp3arm4n"></a>

### 🤝 Collaborators

<a href="https://github.com/kilkat"><img src="https://img.shields.io/badge/GitHub-kilkat-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - kilkat"></a>
<a href="https://github.com/leelsey"><img src="https://img.shields.io/badge/GitHub-Leelsey-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - Leelsey"></a>

### 👨‍💻 Development Support

<img src="https://img.shields.io/badge/OpenAI-Codex-0f172a?logo=openai&logoColor=white&style=for-the-badge" alt="OpenAI Codex"> <img src="https://img.shields.io/badge/Anthropic-Claude%20Code-d97757?logo=anthropic&logoColor=white&style=for-the-badge" alt="Anthropic Claude Code badge">

## License

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this project except in compliance with the License. See the [`LICENSE`](LICENSE) file for the full text.

```
Copyright 2026 sp3arm4n

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
