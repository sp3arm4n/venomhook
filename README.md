# VenomHook: Offset-based Native Hook Automation Platform

<p align="center">
  <img src="assets/venomhook.png" alt="VenomHook logo" width="240">
</p>

`venomhook`은 정적 분석 결과(StaticMeta)로부터 offset 기반 HookSpec을 자동 생성하고, Frida 스크립트로 변환해 주는 CLI 도구입니다. `offset_architecture.md`에 정의된 흐름(StaticMeta → EndpointMeta → HookSpec → Frida)을 최소 실행 가능한 형태로 구현했습니다.

## 주요 기능
- Ghidra 헤드리스 + postScript로 StaticMeta 자동 추출(해시/함수 필터 포함)
- StaticMeta(JSON) → HookSpec(JSON/SQLite) 생성, 마크다운 리포트 출력 (E2E 모드 `offset-e2e` 제공)
- HookSpec → Frida 스크립트 자동 생성 (텍스트/JSON 로그, 시나리오, 문자열/버퍼 로깅, 스캔 범위·리트라이 옵션)
- Frida 실행 오케스트레이션(`offset-run`) 및 런타임 로그 요약(MD/HTML, 문자열 샘플 포함)
- 프로파일(JSON)로 점수/시그니처/Frida 옵션 기본값 일괄 적용
- 예제 StaticMeta 포함(`examples/static_meta.sample.json`)

## Requirements
| 구분 | 환경 |
| --- | --- |
| OS | Windows & Linux |
| Java | OpenJDK 21 |
| Ghidra | Ghidra 11.4.x |
| Python | 3.10+ (venv 사용) |
| frida | 17.x |

## Install
```bash
python -m venv venv
source venv/bin/activate  # Linux
.\venv\Scripts\Activate.ps1   # Windows PowerShell

# 개발 모드로 해당 프로젝트를 패키징하여 설치
pip install -e .
```

## Set Up

### Linux
```bash
# 1) Ghidra 환경 변수 자동 설정
chmod +x ./setup/env.sh && ./setup/env.sh <Ghidra 설치 경로>

# 예시
# chmod +x ./setup/env.sh && ./setup/env.sh "$HOME/tools/ghidra_11.4.2_PUBLIC"

# 2) 프로젝트용 필수 디렉토리 자동 생성
chmod +x ./setup/mkdir.sh && ./setup/mkdir.sh
```

### Windows (PowerShell)
```powershell
# 1) Ghidra 환경 변수 자동 설정
powershell -ExecutionPolicy Bypass -File .\setup\env.ps1 <Ghidra 설치 경로>

# 예시
# powershell -ExecutionPolicy Bypass -File .\setup\env.ps1 "$env:USERPROFILE\Tools\ghidra_11.4.2_PUBLIC"

# 2) 프로젝트용 필수 디렉토리 자동 생성
powershell -ExecutionPolicy Bypass -File .\setup\mkdir.ps1
```

## Usage

### Step 1. Create StaticMeta JSON File from Ghidra headless
```bash
# Linux
analyzeHeadless ./static/project venomhook_project -import ./sample/putty.exe -overwrite -scriptPath $HOME/Tools/venomhook/ghidra_scripts -postScript export_staticmeta.py ./static/META/staticmeta.json

# Windows
analyzeHeadless .\static\project venomhook_project -import .\sample\putty.exe -overwrite -scriptPath $HOME\Tools\venomhook\ghidra_scripts -postScript export_staticmeta.py .\static\META\staticmeta.json
```
- 결과물: `/static/META/staticmeta.json` (StaticMeta). 다음 단계 입력으로 사용.
- Ghidra 옵션: `--ghidra-headless`, `--ghidra-script`, `--ghidra-project-dir`, `--ghidra-project-name`
  - 샘플 postScript(`export_staticmeta.py`)가 리포지토리에 포함됨. 마지막 인자 경로에 StaticMeta JSON을 써야 함.

### Step 2. StaticMeta → HookSpec / Report
```bash
venomhook offset-static --static-json ./static/META/staticmeta.json --out ./reports/hook/venomhook.json --out-db ./reports/hook/venomhook.db --report-md ./reports/hook/venomhook.md --top 20 --sig-max-bytes 12 --score-network 30 --score-file 20 --score-auth 15 --score-url 10 --score-crypto 10

# 바이너리를 직접 넣을 경우(Ghidra 실행 포함)
venomhook offset-static --binary ./sample/putty.exe --ghidra-headless analyzeHeadless --ghidra-script ghidra_scripts/export_staticmeta.py --out ./reports/hook/venomhook.json

# 프로파일(JSON)로 점수/시그니처 기본값 적용
venomhook offset-static --static-json ./static/META/staticmeta.json --profile profile.json --out ./reports/hook/venomhook.json
```
- 결과물: `venomhook.json`(필수), `venomhook.db`(선택), `venomhook.md`(요약).
- 주요 옵션: 시그니처 길이(`--sig-max-bytes`), 점수 가중치(`--score-*`), 출력(`--out`, `--out-db`, `--report-md`), 입력(`--static-json` 또는 `--binary`+Ghidra 설정).
- 프로파일: `--profile`로 `{ "static": { "sig_max_bytes": 14, "score": { ... } } }` 형태 JSON을 넣으면 기본값을 덮어씁니다 (동일 값인 경우에만 적용, CLI 명시 값 우선).

### Step 3. HookSpec → Frida Script
```bash
# Create from JSON file
venomhook offset-hook --hookspec ./reports/hook/venomhook.json --target putty.exe --out-script ./frida_scripts/venomhook.frida.js --log-format json --log-prefix "[venomhook]" --scenario-message "start" --auto-start-scenario --hexdump-len 64 --string-arg 0 --string-ret --string-len 128 --scan-size 4096 --retry-attach 2 --print-script

# Create from DB file
venomhook offset-hook --hookspec-db ./reports/hook/venomhook.db --target putty.exe --out-script ./frida_scripts/venomhook.frida.js --log-format json --log-prefix "[venomhook]" --scenario-message "start" --auto-start-scenario --hexdump-len 64 --string-arg 0 --string-ret --string-len 128 --scan-size 4096 --retry-attach 2 --print-script

# 프로파일(JSON)로 동적 옵션 기본값 적용
venomhook offset-hook --hookspec ./reports/hook/venomhook.json --target putty.exe --profile profile.json
```
- 결과물: `venomhook.js` (자동 생성된 Frida 후킹 스크립트).
- 주요 옵션: 입력(`--hookspec`/`--hookspec-db` 둘 중 하나), 로그 포맷(`--log-format text|json`), 접두사(`--log-prefix`), 시나리오 알림(`--scenario-message`, `--auto-start-scenario`), 출력 경로(`--out-script`).
- hexdump 길이(`--hexdump-len`), 호출 카운트 로그 포함.
- 문자열 로깅: `--string-arg <idx>` 반복 지정 시 해당 인자를 C-string으로 읽어 로그, `--string-ret`는 반환값을 C-string으로 로그, 길이는 `--string-len`으로 제어.
- 안정성 옵션: 시그니처 스캔 범위(`--scan-size`), attach 실패 리트라이(`--retry-attach`).
- 프로파일: `--profile`로 `{ "dynamic": { "hexdump_len": 32, "string_arg": [0], ... } }` 형태 JSON을 넣으면 기본값을 덮어씁니다 (동일 값인 경우에만 적용, CLI 명시 값 우선).

### Step 4. Frida Hooking Execute
```bash
# frida 직접 실행
frida -f ./sample/putty.exe -l ./frida_scripts/venomhook.js --no-pause

# 또는 CLI 오케스트레이터 사용 (사용 시 --dry-run 옵션 제거)
venomhook offset-run --script ./frida_scripts/venomhook.js --target ./sample/putty.exe --frida-path frida --log-file ./.log/frida.log --dry-run
```
- 결과물: 콘솔 로그(텍스트/JSON), 필요 시 `send()` 이벤트 소비. 실행/입력 시나리오는 별도 조작.

### Step 5. Runtime Log Summary (선택)
Frida JSON 로그를 Markdown 요약으로 변환합니다.
```bash
venomhook offset-report-runtime --log ./.log/frida.log --out-md ./reports/runtime_summary.md --out-html ./reports/runtime_summary.html
```
- 결과물: `runtime_summary.md` / `runtime_summary.html` (hook별 enter/leave/hexdump/error 카운트 + 문자열/args/ret 샘플)

### Step 6. One-shot E2E (옵션)
StaticMeta→HookSpec→Frida 스크립트 생성까지 한 번에 수행하고(기본 frida 실행은 생략, `--run-frida`로 실행 가능), 산출물을 한 디렉터리에 모읍니다.
```bash
venomhook offset-e2e \
  --static-json ./static/META/staticmeta.json \   # 또는 --binary ... (Ghidra 필요)
  --target putty.exe \
  --out-dir out \
  --profile profile.json \   # 선택: 기본값 덮어쓰기
  --run-frida --frida-log ./.log/frida.log --summarize-log   # 실제 frida 실행 시
```
- 산출물: `reports/hook/venomhook.json` `reports/hook/venomhook.db` `reports/hook/venomhook.md` `frida_scripts/venomhook.js` (+옵션: frida.log, runtime_summary)

## 주요 스크립트
```
venomhook/
│
├── .log/                                 # Frida 로그
│
├── setup/                                # 환경 설정
│   ├── env.ps1
│   ├── env.sh
│   ├── mkdir.ps1
│   └── mkdir.sh
│
├── ghidra_scripts/
│   └── export_staticmeta.py              # StaticMeta JSON을 내보내는 Ghidra postScript
│
├── src/
│   └── venomhook/
│       ├── models.py                     # StaticMeta/EndpointMeta/HookSpec 데이터 모델
│       ├── scoring.py                    # 엔드포인트 점수 규칙
│       ├── hookspec_builder.py           # HookSpec 생성기
│       ├── static_pipeline.py            # StaticMeta -> HookSpec 파이프라인
│       ├── dynamic_pipeline.py           # HookSpec -> Frida 스크립트 생성
│       ├── ghidra_runner.py              # Ghidra headless 래퍼
│       ├── orchestrator.py               # Frida 실행 오케스트레이터
│       ├── report.py                     # HookSpec 마크다운 리포트
│       ├── runtime_report.py             # Frida 로그(MD/HTML) 요약기 (문자열 샘플 포함)
│       ├── config.py                     # 프로파일 로더
│       ├── store.py                      # JSON/SQLite 로드·세이브 유틸
│       └── cli.py                        # venomhook offset-static / offset-hook 엔트리포인트
│
├── static/
│   ├── frida_manager.py
│   ├── META/
│   │   └── staticmeta.json               # StaticMeta JSON 파일
│   └── project/                          # ghidra 정적 분석 파일
│
├── frida_scripts/
│   └── venomhook.js                      # Frida Hooking 스크립트
│
├── reports/
│   ├── hook/                             # HookSpec
│   │   ├── venomhook.json
│   │   ├── venomhook.db
│   │   └── venomhook.md
│   ├── runtime_summary.md
│   └── runtime_summary.html
│
└── sample/
    ├── examples/
    │   └── static_meta.sample.json       # 샘플 StaticMeta
    ├── tests/                            # 간단한 파이프라인 테스트
    └── putty.exe                         # 테스트용 EXE 파일
```

## 개발/테스트
```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Architect

### 👾 Reverse Engineering & White Hat Hacker

<a href="https://github.com/sp3arm4n"><img src="https://img.shields.io/badge/GitHub-sp3arm4n-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - sp3arm4n"></a>

### 🤝 Collaborators

<a href="https://github.com/kilkat"><img src="https://img.shields.io/badge/GitHub-kilkat-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - kilkat"></a>
<a href="https://github.com/leelsey"><img src="https://img.shields.io/badge/GitHub-Leelsey-181717?logo=github&logoColor=white&style=for-the-badge" alt="GitHub - Leelsey"></a>

## Developer

### 👨‍💻 AI Pair Programming

<img src="https://img.shields.io/badge/OpenAI-Codex-0f172a?logo=openai&logoColor=white&style=for-the-badge" alt="OpenAI Codex badge">

## Support

### 🤖 AI Research Assistance

<img src="https://img.shields.io/badge/OpenAI-ChatGPT-7c3aed?logo=openai&logoColor=white&style=for-the-badge" alt="OpenAI ChatGPT badge">
