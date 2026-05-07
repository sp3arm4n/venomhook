# VenomHook

<p align="center">
  <img src="assets/venomhook.png" alt="VenomHook logo" width="220">
</p>

VenomHook은 네이티브 바이너리와 Android APK를 정적 분석해 후킹 후보 함수를 찾고, offset 기반 HookSpec과 Frida 스크립트를 생성하는 CLI 도구입니다.

주요 흐름은 다음과 같습니다.

```text
Binary/APK -> StaticMeta -> Endpoint scoring -> HookSpec -> Frida script -> Runtime report
```

Windows PE, Linux/Android ELF, macOS Mach-O를 같은 데이터 모델로 다루며, Android APK에서는 native library 추출, manifest 감사, jadx 기반 Java native 메서드 추출, JNI symbol bridge 분석까지 제공합니다.

이 도구는 권한이 있는 분석 대상에서 리버스 엔지니어링, 보안 검증, 동적 계측 자동화를 돕기 위한 용도입니다.

## What It Does

- Ghidra headless postScript로 함수 RVA, imports, strings, raw bytes를 `StaticMeta` JSON으로 추출
- `StaticMeta`를 점수화해 네트워크, 파일, 인증, URL, 암호화, JNI 관련 후킹 후보를 선별
- 후킹 후보를 `HookSpec` JSON/SQLite로 저장
- `HookSpec`에서 Frida JavaScript를 생성
- signature fallback, module alias, 문자열/버퍼/return logging 옵션 지원
- APK에서 `lib/<abi>/*.so`를 추출해 기존 native 분석 파이프라인으로 연결
- apktool/jadx가 있으면 AndroidManifest, Java native method, JNI bridge까지 분석
- AndroidManifest 취약점 룰 9종(MANIFEST-001~009)을 자동 감사하고, 결과 finding마다 ADB / Frida / shell PoC 레시피를 자동 생성 (`venomhook android-audit`)
- 생성된 PoC를 실행 가능한 `.sh` / `.frida.js` 번들로 디렉터리 단위 export
- Frida JSON 로그를 Markdown/HTML runtime summary로 변환

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

생성된 스크립트를 확인하려면:

```bash
sed -n '1,120p' ./out/venomhook.js
```

## Install

기본 CLI만 사용할 경우:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

정적 바이너리 메타데이터 추출(`binary_meta`)도 사용할 경우:

```bash
pip install -e '.[static]'
```

Frida 실행까지 CLI에서 처리할 경우:

```bash
pip install -e '.[dynamic]'
```

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .
```

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

환경 변수로 외부 도구 경로를 지정할 수 있습니다.

```bash
export VENOMHOOK_APKTOOL=/path/to/apktool
export VENOMHOOK_JADX=/path/to/jadx
```

Ghidra 경로 설정 helper:

```bash
chmod +x ./setup/env.sh
./setup/env.sh "$HOME/tools/ghidra_11.4.2_PUBLIC"
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\env.ps1 "$env:USERPROFILE\Tools\ghidra_11.4.2_PUBLIC"
```

작업 디렉터리 생성:

```bash
chmod +x ./setup/mkdir.sh
./setup/mkdir.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\mkdir.ps1
```

## Core Workflow

### 1. StaticMeta 생성

이미 `StaticMeta` JSON이 있으면 이 단계는 건너뛰어도 됩니다.

Ghidra headless로 샘플 PE를 분석:

```bash
analyzeHeadless ./static/project venomhook_project \
  -import ./sample/putty.exe \
  -overwrite \
  -scriptPath ./ghidra_scripts \
  -postScript export_staticmeta.py ./static/META/staticmeta.json
```

출력 파일:

```text
static/META/staticmeta.json
```

### 2. StaticMeta -> HookSpec

```bash
venomhook offset-static \
  --static-json ./static/META/staticmeta.json \
  --out ./reports/hook/venomhook.json \
  --out-db ./reports/hook/venomhook.db \
  --report-md ./reports/hook/venomhook.md \
  --top 20
```

바이너리를 직접 넣고 Ghidra 실행까지 맡기려면:

```bash
venomhook offset-static \
  --binary ./sample/putty.exe \
  --ghidra-headless analyzeHeadless \
  --ghidra-script ./ghidra_scripts/export_staticmeta.py \
  --out ./reports/hook/venomhook.json
```

주요 옵션:

| Option | Meaning |
| --- | --- |
| `--top` | 상위 N개 후킹 후보만 출력 |
| `--sig-max-bytes` | signature prefix 최대 byte 수 |
| `--score-network` | network import 가중치 |
| `--score-file` | file import 가중치 |
| `--score-auth` | auth keyword 가중치 |
| `--score-url` | URL/string 가중치 |
| `--score-crypto` | crypto import/string 가중치 |
| `--score-jni` | JNI/Android 가중치 |

### 3. HookSpec -> Frida Script

```bash
venomhook offset-hook \
  --hookspec ./reports/hook/venomhook.json \
  --target putty.exe \
  --out-script ./frida_scripts/venomhook.js \
  --log-format json \
  --hexdump-len 64 \
  --string-arg 0 \
  --string-ret \
  --scan-size 4096 \
  --retry-attach 2
```

SQLite HookSpec을 사용할 수도 있습니다.

```bash
venomhook offset-hook \
  --hookspec-db ./reports/hook/venomhook.db \
  --target putty.exe \
  --out-script ./frida_scripts/venomhook.js
```

모듈 이름이 런타임에서 달라질 수 있으면 alias를 추가합니다.

```bash
venomhook offset-hook \
  --hookspec ./reports/hook/venomhook.json \
  --target libfoo.so \
  --module-alias libfoo.so.1 \
  --module-alias libfoo.so.1.0 \
  --out-script ./frida_scripts/venomhook.js
```

### 4. Frida 실행

Frida CLI를 직접 사용할 경우:

```bash
frida -f ./sample/putty.exe -l ./frida_scripts/venomhook.js --no-pause
```

VenomHook 오케스트레이터를 사용할 경우:

```bash
venomhook offset-run \
  --script ./frida_scripts/venomhook.js \
  --target ./sample/putty.exe \
  --frida-path frida \
  --log-file ./.log/frida.log
```

실행하지 않고 command만 확인:

```bash
venomhook offset-run \
  --script ./frida_scripts/venomhook.js \
  --target ./sample/putty.exe \
  --dry-run
```

### 5. Runtime Report

Frida script를 `--log-format json`으로 생성하고 로그를 저장했다면 runtime summary를 만들 수 있습니다.

```bash
venomhook offset-report-runtime \
  --log ./.log/frida.log \
  --out-md ./reports/runtime_summary.md \
  --out-html ./reports/runtime_summary.html
```

## Android Workflow

### APK에서 native library HookSpec 생성

APK 안의 `lib/<abi>/*.so`를 추출한 뒤 Ghidra 분석으로 넘깁니다.

```bash
venomhook offset-static \
  --apk ./sample/myapp.apk \
  --abi arm64-v8a \
  --ghidra-headless analyzeHeadless \
  --ghidra-script ./ghidra_scripts/export_staticmeta.py \
  --out ./reports/hook/myapp.json
```

옵션:

| Option | Meaning |
| --- | --- |
| `--abi auto` | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` 순서로 자동 선택 |
| `--apk-lib libfoo.so` | 특정 `.so`만 선택 |
| `--apk-extract-dir ./out/lib` | 추출 위치 지정 |

생성된 HookSpec의 target은 디바이스에서 로드되는 실제 모듈 이름입니다. 보통 `libfoo.so` 형태입니다.

```bash
venomhook offset-hook \
  --hookspec ./reports/hook/myapp.json \
  --target libfoo.so \
  --out-script ./frida_scripts/myapp.js
```

Android 디바이스에서 실행:

```bash
frida -U -f com.example.app -l ./frida_scripts/myapp.js --no-pause
```

이미 실행 중인 프로세스에 attach:

```bash
frida -U -n com.example.app -l ./frida_scripts/myapp.js
```

### APK 전체 컨텍스트 분석

`android_pipeline.analyze_apk`는 APK에서 native library, module metadata, AndroidManifest, Java native methods, JNI bridge를 한 번에 수집합니다.

```bash
python -c "
from venomhook.android_pipeline import analyze_apk

r = analyze_apk('./sample/myapp.apk', './out_android', abi='auto')
print('ABI:', r.selected_abi)
print('SO:', r.extracted_so_path)
print('manifest:', r.app_meta.package_name if r.app_meta else 'not decoded')
print('java natives:', len(r.java_natives))
print('matched bridges:', len(r.matched_bridges), '/', len(r.bridges))
print('warnings:', r.warnings)
"
```

`apktool` 또는 `jadx`가 없으면 해당 단계만 warning으로 남기고 계속 진행합니다. 반드시 필요하게 만들려면:

```python
analyze_apk("./sample/myapp.apk", "./out_android", fail_on_missing_tools=True)
```

### AndroidManifest 감사

`apk_decoder`로 디코드한 manifest metadata를 `manifest_audit` 룰 엔진에 넣습니다.

```bash
python -c "
from venomhook.apk_decoder import decode_apk
from venomhook.manifest_audit import audit_manifest, format_audit_summary

_, app = decode_apk('./sample/myapp.apk', './out_audit/apktool')
report = audit_manifest(app)
print(format_audit_summary(report))
"
```

CI gate 예시:

```bash
python -c "
import sys
from venomhook.apk_decoder import decode_apk
from venomhook.manifest_audit import audit_manifest

_, app = decode_apk('./sample/myapp.apk', './out_audit/apktool')
report = audit_manifest(app)
sys.exit(1 if report.has_severity_at_least('high') else 0)
"
```

현재 manifest audit rule:

| Rule ID | Title | Severity | PoC |
| --- | --- | --- | --- |
| `MANIFEST-001` | Debuggable Application | high | adb (jdb + run-as) |
| `MANIFEST-002` | Cleartext Traffic Permitted | high | shell (mitmproxy) |
| `MANIFEST-003` | Allow Backup Enabled | medium | adb backup |
| `MANIFEST-004` | Exported Component without Permission | high | adb am + frida observer |
| `MANIFEST-005` | Exported Content Provider | high | adb content query |
| `MANIFEST-006` | Provider with grantUriPermissions | medium | adb traversal probes |
| `MANIFEST-007` | Dangerous Permission Surface | info | — |
| `MANIFEST-008` | Outdated minSdkVersion | medium | — |
| `MANIFEST-009` | Outdated targetSdkVersion | medium | — |

### `android-audit` CLI — manifest 감사 + PoC 자동 생성 (Phase 3)

Phase 3에서 추가된 `android-audit` 서브커맨드는 APK 한 개에 대해
`apktool decode → manifest_audit → poc_generator`까지를 한 번에 실행하고
운영자가 그대로 실행 가능한 PoC 레시피를 출력합니다.

```bash
venomhook android-audit \
    --apk ./sample/myapp.apk \
    --out-dir ./out_audit \
    --report-json ./out_audit/analysis.json \
    --audit-json  ./out_audit/audit.json \
    --poc-json    ./out_audit/pocs.json \
    --poc-bundle-dir ./out_audit/pocs/ \
    --severity-threshold high
```

출력 채널:

| 옵션 | 내용 |
| --- | --- |
| stdout (`--quiet`로 끔) | `format_audit_summary` + `format_pocs_text` (사람용 요약) |
| `--report-json` | `AndroidAnalysis.to_dict()` — apk_meta·app_meta·bridges·audit_report·pocs 전체 |
| `--audit-json`  | `AndroidAuditReport.to_dict()`만 추출 |
| `--poc-json`    | `PoCArtifact[]` JSON — CI 아카이브·재실행용 |
| `--poc-bundle-dir` | 디렉터리에 `.sh` / `.frida.js` / `.md` + `README.md` 인덱스 (실행 가능한 형태) |

종료 코드:

| 코드 | 의미 |
| --- | --- |
| 0 | 성공, severity gate 통과 |
| 1 | 파이프라인 오류 (no native libs / `--strict-tools`로 apktool 누락 등) |
| 2 | severity gate 발동 — `--severity-threshold` 이상의 finding 존재 |

`--poc-bundle-dir` 출력 예시:

```
out_audit/pocs/
├── README.md
├── MANIFEST-001-1_attach-jdb-to-debuggable-process.sh        (chmod +x)
├── MANIFEST-001-2_read-app-private-files-via-run-as.sh       (chmod +x)
├── MANIFEST-004-3_invoke-exported-activity-com-x-publicact.sh (chmod +x)
├── MANIFEST-004-4_observe-intents-to-com-x-publicact.frida.js
└── ...
```

각 `.sh` 파일은 shebang + 헤더 코멘트(rule, severity, package, description,
expected evidence, references) + 실제 명령어로 구성되어 있어 별도 가공 없이
`bash pocs/MANIFEST-004-3_*.sh`로 바로 실행 가능합니다. Frida 스크립트는
`frida -U -f <pkg> -l <file>.frida.js --no-pause` 패턴으로 사용합니다.

CI gate 예시 (직접 Python 호출 대신 CLI):

```bash
venomhook android-audit \
    --apk ./sample/myapp.apk \
    --out-dir /tmp/audit_$$ \
    --quiet \
    --severity-threshold high
echo "exit=$?"   # 2 if gate fired, 0 otherwise
```

`--no-jadx`로 jadx를 건너뛰면 audit-only 모드로 동작 (Java decompile + JNI
bridge 생략). `--strict-tools`는 apktool/jadx 누락 시 즉시 비0 종료를 강제합니다.

### Phase 3 — PoC artifact 형태

`PoCArtifact`는 다음 형태입니다 (`venomhook.models`):

```python
@dataclass
class PoCArtifact:
    rule_id: str             # 예: "MANIFEST-004"
    title: str
    severity: str            # critical | high | medium | low | info
    kind: str                # "adb" | "frida" | "shell" | "info"
    package_name: str
    component: Optional[str] = None
    description: str = ""
    commands: list[str] = []
    expected_evidence: str = ""
    notes: str = ""
    references: list[str] = []
```

`AndroidComponent.authorities` 필드(Phase 3에서 신규 추가됨)는 provider의
`android:authorities` 속성을 추출해 MANIFEST-005/006 PoC의 `content://`
URI에 실제 authority를 박아넣는 데 사용됩니다. 다중 authority가 선언된
경우 첫 번째를 URI에 사용하고 나머지는 PoC notes에 노출됩니다.

## Binary Metadata Helper

Ghidra 함수 분석 없이 module-level metadata만 빠르게 확인할 수 있습니다. `lief`가 필요합니다.

```bash
pip install -e '.[static]'

python -c "
from venomhook.binary_meta import extract_binary_meta

m = extract_binary_meta('./sample/putty.exe')
print(m.format, m.arch, m.os_hint, hex(m.image_base), 'aslr=', m.aslr)
print('libraries:', m.libraries[:5])
print('imports:', m.imports[:10])
print('exports:', m.exports[:10])
"
```

## Profile Defaults

반복 실행 옵션은 JSON profile로 관리할 수 있습니다.

```json
{
  "static": {
    "sig_max_bytes": 14,
    "score": {
      "network_weight": 30,
      "file_weight": 20,
      "auth_weight": 15,
      "url_weight": 10,
      "crypto_weight": 10,
      "jni_weight": 30
    }
  },
  "dynamic": {
    "hexdump_len": 64,
    "string_arg": [0],
    "string_ret": true,
    "string_len": 128,
    "scan_size": 4096,
    "retry_attach": 2
  }
}
```

사용:

```bash
venomhook offset-static \
  --static-json ./sample/examples/static_meta.sample.json \
  --profile ./profile.json \
  --out ./out/venomhook.json

venomhook offset-hook \
  --hookspec ./out/venomhook.json \
  --target sample.exe \
  --profile ./profile.json \
  --out-script ./out/venomhook.js
```

## Project Layout

```text
venomhook/
├── ghidra_scripts/
│   └── export_staticmeta.py
├── sample/
│   ├── examples/
│   │   └── static_meta.sample.json
│   ├── tests/
│   └── putty.exe
├── setup/
│   ├── env.ps1
│   ├── env.sh
│   ├── mkdir.ps1
│   └── mkdir.sh
├── src/
│   └── venomhook/
│       ├── android_pipeline.py
│       ├── apk_decoder.py
│       ├── apk_extractor.py
│       ├── binary_meta.py
│       ├── cli.py
│       ├── dynamic_pipeline.py
│       ├── ghidra_runner.py
│       ├── hookspec_builder.py
│       ├── jadx_runner.py
│       ├── jni_bridge.py
│       ├── manifest_audit.py
│       ├── models.py
│       ├── orchestrator.py
│       ├── poc_export.py
│       ├── poc_generator.py
│       ├── report.py
│       ├── runtime_report.py
│       ├── scoring.py
│       ├── static_pipeline.py
│       └── store.py
├── architecture.md
├── pyproject.toml
└── README.md
```

Generated output directories such as `static/META`, `static/project`, `reports`, `frida_scripts`, and `.log` are ignored by git.

## 개발/테스트
```bash
python3 -m unittest discover -s ./sample/tests
```

## Architect

### 👾 Reverse Engineering & White Hat Hacker

<a href="https://github.com/sp3arm4n"><img src="https://img.shields.io/badge/GitHub-sp3arm4n-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - sp3arm4n"></a>

### 🤝 Collaborators

<a href="https://github.com/kilkat"><img src="https://img.shields.io/badge/GitHub-kilkat-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - kilkat"></a>
<a href="https://github.com/leelsey"><img src="https://img.shields.io/badge/GitHub-Leelsey-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - Leelsey"></a>

## Developer

### 👨‍💻 AI Pair Programming

<img src="https://img.shields.io/badge/OpenAI-Codex-0f172a?logo=openai&logoColor=white&style=for-the-badge" alt="OpenAI Codex"> <img src="https://img.shields.io/badge/Anthropic-Claude%20Code-d97757?logo=anthropic&logoColor=white&style=for-the-badge" alt="Anthropic Claude Code badge">

## Support

### 🤖 AI Research Assistance

<img src="https://img.shields.io/badge/OpenAI-ChatGPT-0f172a?logo=openai&logoColor=white&style=for-the-badge" alt="OpenAI ChatGPT"> <img src="https://img.shields.io/badge/Anthropic-Claude-d97757?logo=anthropic&logoColor=white&style=for-the-badge" alt="Anthropic Claude">

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
