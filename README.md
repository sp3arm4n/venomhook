# VenomHook

<p align="center">
  <img src="assets/venomhook.png" alt="VenomHook logo" width="220">
</p>

<p align="center">
  <a href="https://github.com/sp3arm4n/venomhook/actions/workflows/ci.yml"><img src="https://github.com/sp3arm4n/venomhook/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

VenomHook은 네이티브 바이너리와 Android APK를 정적 분석해 후킹 후보 함수와 보안 결함을 찾고, offset 기반 HookSpec, 실행 가능한 PoC 레시피, 가독성 있는 HTML 보고서를 생성하는 CLI 도구입니다.

```text
Binary/APK -> StaticMeta -> Endpoint scoring -> HookSpec -> Frida script -> Runtime report
```

PE, ELF, Mach-O를 같은 데이터 모델로 다룹니다. Android APK 분석의 단일 진입점은 `venomhook scan-apk`이며 한 명령으로 다음을 모두 수행합니다.

- **Manifest 감사** — 10 룰 (debuggable, cleartext / NSC base-config / user-cert trust, allowBackup, exported 컴포넌트 / provider, grantUriPermissions, 위험 권한, 구버전 SDK)
- **2-tier 코드 레벨 감사**
  - **Java tier** — jadx 디컴파일 결과 위에서 6 룰 (평문 HTTP, WebView setJavaScriptEnabled / addJavascriptInterface, 약한 Cipher / 해시, 평문 자격증명 로그, 외부 저장소 사용, MODE_WORLD_READABLE/WRITEABLE)
  - **Smali tier (NEW)** — jadx가 타임아웃 / 실패해도 apktool이 생성한 smali에서 4 룰(CODE-001/003/005/006)을 매칭. 패킹·난독화 APK에도 코드 결함 산출 보장
- **공격면 추출** — deeplink / 데이터 스킴 / 카테고리, intent-filter 구조, JNI bridge correlation, .so 문자열 카테고리화 (URL / 경로 / 쉘 / crypto / 자격증명 단서 / SQL)
- **PoC 자동 생성 + dedup** — adb 명령, Frida 후킹, mitmproxy 가로채기, logcat grep 레시피를 .sh / .frida.js / .md 번들로 export. 동일 템플릿 PoC는 자동으로 1개 + `applies_to` 컴포넌트 리스트로 압축 (KakaoTalk-급 APK에서 190→17 PoCs로 −91% 압축)
- **결과 정규화** — 같은 클래스 안의 동일 룰 반복 발화는 1개의 finding + `occurrences` 펼침으로 압축. 펜테스트 보고서 가독성↑
- **자체 포함 HTML 보고서** — 심각도 색상 카드, MASVS 카테고리 그룹핑, 코드 단서 인용, occurrence 펼침 + applies_to 칩, on-disk PoC 링크 — 외부 자산 / JS 의존 없음
- **10단계 라이브 진행 출력** — 모든 단계가 stderr에 `[N/10] step ...` 형식으로 진행 표시. `--quiet`로 억제 가능

이 도구는 권한이 있는 분석 대상에서 리버스 엔지니어링, 보안 검증, 펜테스트, 동적 계측 자동화를 돕기 위한 용도입니다.

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

### Android APK 분석 — `scan-apk` 한 명령

APK 펜테스트의 **단일 진입점**입니다. 옵션 없이 호출하면 manifest + 코드 + smali + HTML + PoC 번들 + JNI bridge correlation을 모두 실행합니다. (`android-audit`는 동일한 동작의 호환 별칭으로 유지됩니다.)

| 목적 | 명령 |
| --- | --- |
| **기본 — 전체 감사 + 모든 산출물** | `venomhook scan-apk --apk ./app.apk --out-dir ./out --out-html ./out/audit.html --poc-bundle-dir ./out/pocs` |
| Manifest만 빠르게 (jadx 건너뜀) | `venomhook scan-apk --apk ./app.apk --out-dir ./out --no-jadx` |
| 모든 .so 분석 (multi-lib) | `venomhook scan-apk --apk ./app.apk --out-dir ./out --apk-lib all` |
| 대용량 APK — jadx 타임아웃 + 빠른 모드 | `venomhook scan-apk --apk ./big.apk --out-dir ./out --jadx-timeout 1800 --jadx-threads 8 --jadx-fast` |
| CI 게이트 — high 이상 발견 시 비-0 종료 | `venomhook scan-apk --apk ./app.apk --out-dir ./out --severity-threshold high --quiet` |
| 결과 캐시 (재실행 시 즉시 replay) | `venomhook scan-apk --apk ./app.apk --out-dir ./out --cache-dir ./cache` |
| 특정 산출물만 별도 저장 | `--report-json`, `--audit-json`, `--code-audit-json`, `--poc-json` 플래그 |

### 네이티브 바이너리 분석 (HookSpec / Frida)

| 목적 | 명령 |
| --- | --- |
| 샘플 전체 흐름 실행 | `venomhook offset-e2e --static-json ./sample/examples/static_meta.sample.json --target sample.exe --out-dir ./out` |
| HookSpec만 생성 | `venomhook offset-static --static-json ./sample/examples/static_meta.sample.json --out ./out/venomhook.json --out-db ./out/venomhook.db` |
| Frida 스크립트 생성 | `venomhook offset-hook --hookspec ./out/venomhook.json --target sample.exe --out-script ./out/venomhook.js` |
| 실제 바이너리 Ghidra 분석 | `venomhook offset-static --binary ./path/to/target.exe --ghidra-headless analyzeHeadless --ghidra-script ./ghidra_scripts/export_staticmeta.py --out ./reports/hook/venomhook.json` |
| Frida 로그 요약 | `venomhook offset-report-runtime --log ./logs/frida.log --out-md ./out/summary.md --out-html ./out/summary.html` |

> `offset-static --apk` / `offset-e2e --apk`는 Ghidra-routed 변형이며 deprecation 경고가 표시됩니다. Android 워크플로는 `scan-apk`만 사용해주세요.

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
│   └── tests/                 # 864+ 단위 테스트
├── setup/
├── src/venomhook/
│   ├── apk_decoder.py         # Manifest + apktool.yml + NSC + intent-filter 파싱
│   ├── binary_meta.py         # .so 메타 (lief) + .rodata strings 추출
│   ├── manifest_audit.py      # MANIFEST-001..010 (10 룰)
│   ├── code_audit.py          # CODE-001..006 (.java tier, jadx 위에서)
│   ├── smali_audit.py         # CODE-001/003/005/006 (smali tier, apktool 위에서 — jadx 실패 시 폴백)
│   ├── native_strings.py      # .so 문자열 8 카테고리 분류 + 심볼 attribution
│   ├── rule_taxonomy.py       # MASVS 카테고리 매핑 (HTML 그룹핑)
│   ├── poc_generator.py       # adb / Frida / mitmproxy / logcat PoC 빌더
│   ├── audit_html_report.py   # 자체 포함 HTML 보고서
│   ├── android_pipeline.py    # 10-step 파이프라인 통합 (라이브 진행 출력)
│   └── ...
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
