# Architecture

## 0. 개발 환경
| 구분 | 환경 |
| --- | --- |
| OS | Windows & Linux 혼용 (CLI 환경) |
| Java | JDK 21 |
| Ghidra | Ghidra 11.4.x |
| Python | 3.10+ (venv 사용) |
| frida | 17.x |

개인이 직접 빌드하여 사용하는 도구가 아닌 이미 릴리즈된 파일로 사용하며 옵션 명령어로 각 기능들을 이용.

## 1. 전체 구조도 (Offset-based Native Hook Automation Platform)

```text
─────────────────────────────────────────────────────────────
         Offset-based Native Hook Automation Platform
─────────────────────────────────────────────────────────────
                STATIC OFFSET ENGINE
              (Ghidra Headless + PE/ELF)
─────────────────────────────────────────────────────────────
    • Function Discovery
    • RVA/Offset Extractor      ┐
    • Xref / Strings Analyzer   ├→ StaticMeta
    • Import/API Ref Analyzer   ┘
─────────────────────────────────────────────────────────────
            ENDPOINT & HOOKSPEC ENGINE
─────────────────────────────────────────────────────────────
    • Endpoint Scoring (Rule-based)
    • Offset-based HookSpec Builder
    • Signature (byte pattern) Generator
    • HookSpec Repository (JSON/SQLite)
─────────────────────────────────────────────────────────────
                DYNAMIC OFFSET HOOK ENGINE
                   (Frida + Python)
─────────────────────────────────────────────────────────────
    • Offset Hook Loader (base + RVA)
    • Signature Fallback Scanner
    • Auto Generated Frida Scripts
    • Runtime Logger (Args/Ret/Buffers)
─────────────────────────────────────────────────────────────
                 ORCHESTRATION & REPORT
─────────────────────────────────────────────────────────────
    • Pipeline Orchestrator (CLI)
    • Run Profile (scenario) Manager
    • Report & Export (JSON/HTML/MD)
─────────────────────────────────────────────────────────────
```

## 2. 아키텍처 구성도

```text
                                        ┌───────────────────────────────────┐
                                        │ Offset-based Hook Automation Core │
                                        └─────────────────┬─────────────────┘
                                                          │
                           ┌──────────────────────────────┴──────────────────────────────┐
                           │                                                             │
                 [Static Offset Engine]                                        [Dynamic Hook Engine]
               (Ghidra Headless + PE/ELF)                                         (Frida + Python)
                           │                                                             │
          ┌────────────────┼────────────────┐                               ┌────────────┴────────────┐
          │                │                │                               │                         │
    [Function Map]    [RVA/Offset]   [Xref/Strings]                [Offset Hook Loader]       [Runtime Logger]
    [Import/API]      [Byte Patterns]                              [Sig Fallback Scanner]     [Scenario Runner]
          │                │                │                               │                         │
          └────────────────┼────────────────┘                               └────────────┬────────────┘
                           │                                                             │
        ┌──────────────────▼──────────────────┐                          ┌───────────────▼─────────────────┐
        │ Endpoint Scoring & HookSpec Builder │                          │ Frida Script Gen(from HookSpec) │
        └──────────────────┬──────────────────┘                          └───────────────┬─────────────────┘
                           │                                                             │
                           └──────────────────────────────┬──────────────────────────────┘
                                                          │
                                           ┌──────────────▼──────────────┐
                                           │ HookSpec DB (JSON / SQLite) │
                                           └──────────────┬──────────────┘
                                                          │
                                         ┌────────────────┴────────────────┐
                                         │                                 │
                                [Orchestration Layer]            [Report/Export Engine]
                                 - CLI / Pipeline Manager         - JSON / HTML / MD
                                 - Static→Dynamic Flow            - Hook/Runtime Summary
```

## 3. 계층 구조 (Layered Architecture)
```text
─────────────────────────────────────────────────────────────
0. OS / RUNTIME Layer
   - OS : Windows / Linux
   - Runtime : Python 3.10+, Java (Ghidra)
─────────────────────────────────────────────────────────────
1. Engine Layer
   - Ghidra Headless (정적 분석)
   - PE/ELF Parser (pefile/lief 등)
   - Frida (동적 후킹)
   - Capstone (옵션: 시그니처용)
─────────────────────────────────────────────────────────────
2. Analysis Layer
   [Static Offset Layer]
     • Function & RVA Extractor
     • Xref / Strings Analyzer
     • Import/API Reference Analyzer
     • Byte Pattern / Signature Generator

   [Dynamic Offset Hook Layer]
     • Offset Hook Loader (base + RVA)
     • Signature-based Fallback Scanner
     • Auto Hook Script Engine (Frida)
     • Runtime Data Collector (args/ret/buffer)
─────────────────────────────────────────────────────────────
3. Data Layer
   - StaticMeta (정적 분석 결과)
   - EndpointMeta (점수, 태그 포함)
   - HookSpec (offset 기반 후킹 명세)
   - DynamicLog (runtime 로그/덤프)
─────────────────────────────────────────────────────────────
4. Orchestration Layer
   - Pipeline Orchestrator
   - Ghidra Runner / Static Pipeline
   - Endpoint Scoring Runner
   - Frida Runner / Dynamic Pipeline
─────────────────────────────────────────────────────────────
5. Interface Layer
   - CLI (예: `vh offset-static`, `vh offset-hook`)
   - Report Exporter (JSON/HTML/Markdown)
─────────────────────────────────────────────────────────────
```

## 4. 정적 파이프라인 (Offset 중심)
```text
[1] 대상 바이너리(EXE/SO) 입력
    │
    ▼
[2] PE/ELF Parser
    - ImageBase
    - Section Info
    - ASLR/PIE 여부
    - Import Table / Export Table
    │
    ▼
[3] Ghidra Headless 분석
    - 함수 목록(Function)
    - 각 함수 VA / Basic Block 수
    - Xref (caller/callee)
    - 문자열 참조 (URL, token, login, etc.)
    - Import/API 호출 xref
    - 함수 시작 Raw bytes
    │
    ▼
[4] RVA/Offset 계산
    - RVA = VA - ImageBase
    - 각 함수별 offset(m) 계산
    - { module, RVA, size, bytes, xref, strings, imports } 구조화
    │
    ▼
[5] Endpoint Scoring
    - 네트워크/파일/암호화/인증 API 포함 여부
    - 의미있는 문자열(“auth”, “token”, URL 등) 포함 여부
    - caller 수/ callee 특성
    - 스코어 + 태그 부여 (예: network, auth, crypto)
    │
    ▼
[6] HookSpec Builder
    - 상위 N개 endpoint 선택
    - 각 endpoint에 대해:
      • module
      • arch
      • offset (RVA)
      • optional: 첫 N바이트 signature
      • tags / description
      • onEnter/onLeave 기본 정책
    │
    ▼
[7] HookSpec DB 저장
    - JSON/SQLite에 write
    - 나중에 동적 파이프라인에서 그대로 재사용
```

## 5. 동적 파이프라인 (Offset 기반 자동 후킹)
```text
[1] HookSpec 로딩 (JSON/SQLite)
    - 대상 module명, arch, offset, sig, tags
    │
    ▼
[2] 프로세스 실행/attach
    - CLI: vh offset-hook --target sample.exe --hookspec venomhook.json
    │
    ▼
[3] Offset Hook Loader
    - Module.findBaseAddress("sample.exe")
    - target = base + offset
    - 주소 유효성 검사 (read test)
    │
    ├── [성공] → target 주소 확정
    │
    └── [실패] → Signature Fallback
          - module 전체 혹은 섹션 범위 Memory.scan(sig)
          - 첫 매칭 주소를 target으로 사용
    ▼
[4] Frida Script Generator
    - HookSpec 기준으로 JS 코드 자동 생성
    - onEnter:
        · args dump / hexdump
        · 특정 인자만 문자열/버퍼 처리
      onLeave:
        · return 값 로깅
    │
    ▼
[5] Hook Attach & Scenario Runner
    - Interceptor.attach(target, {...})
    - 필요 시 Python에서 입력/트리거 시나리오 실행
    │
    ▼
[6] Runtime Logger
    - send()로 전달된 이벤트 수집
    - 함수별 호출 카운트, args, ret, 버퍼 덤프 축적
    │
    ▼
[7] Report Generator
    - 어떤 offset 엔드포인트가 실제 많이 호출됐는지
    - 어떤 문자열/버퍼 패턴이 관찰됐는지
    - 후킹 효과(성공/실패, 에러)를 리포트로 출력
```

## 6. HookSpec / StaticMeta 데이터 모델 (정규화 관점)
### 6.1. StaticMeta (정적 분석 결과)
```json
{
  "binary": {
    "name": "sample.exe",
    "hash": "sha256:...",
    "arch": "x64",
    "image_base": "0x140000000"
  },
  "functions": [
    {
      "va": "0x1400123A0",
      "rva": "0x000123A0",
      "name": "FUN_1400123A0",
      "size": 128,
      "basic_blocks": 5,
      "callers": ["0x140010100"],
      "callees": [
        {"type": "import", "name": "connect"},
        {"type": "local", "rva": "0x00012000"}
      ],
      "strings": ["https://api.example.com/login", "User-Agent"],
      "imports": ["connect", "send", "recv"],
      "raw_bytes": "48 89 5C 24 08 57 48 83 EC 20 ..."
    }
  ]
}
```
### 6.2. EndpointMeta (스코어링 결과)
```json
{
  "endpoint": {
    "module": "sample.exe",
    "arch": "x64",
    "rva": "0x000123A0",
    "score": 85,
    "tags": ["network", "auth"],
    "reason": [
      "import: connect, send",
      "string: /login",
      "callers: 3"
    ]
  }
}
```
### 6.3. HookSpec (동적 후킹 명세 – offset 기반)
```json
{
  "module": "sample.exe",
  "arch": "x64",
  "offset": "0x000123A0",
  "sig": "48 89 5C 24 ?? 57 48 83 EC ??",
  "name": "login_handler_candidate",
  "tags": ["network", "auth"],
  "proto": {
    "ret": "int",
    "args": ["void *", "char *", "int"]
  },
  "hook": {
    "onEnter": {
      "log_args": [1, 2],
      "hexdump_args": [1],
      "log_stack": false
    },
    "onLeave": {
      "log_ret": true,
      "hexdump_ret": false
    }
  }
}
```
위 HookSpec 구조가 offset 중심 정규화된 핵심 스키마.
StaticMeta → EndpointMeta → HookSpec 으로 단계별 정제/축소되면서, 최종적으로 Frida가 이해할 수 있는 “offset + 보조 정보” 형태까지 내려오는 흐름.

## 7. 오케스트레이션 & CLI 플로우
```text
         ┌─────────────────────────────────────┐
         │                 CLI                 │
         │ vh offset-static  /  vh offset-hook │
         └──────────────────┬──────────────────┘
                            │
                  ┌─────────▼─────────┐
                  │ Pipeline  Manager │
                  └─────────┬─────────┘
                            │
             ┌──────────────┴───────────────┐
             │                              │
    ┌────────▼────────┐           ┌─────────▼─────────┐
    │ Static Pipeline │           │ Dynamic  Pipeline │ 
    └────────┬────────┘           └─────────┬─────────┘
             │                              │
  ┌──────────▼──────────┐         ┌─────────▼─────────┐
  │ StaticMeta Endpoint │  ◀─┬─▶  │ HookSpec  Runtime │ 
  └─────────────────────┘    │    └───────────────────┘
                     ┌───────▼───────┐
                     │ Report Engine │
                     └───────────────┘
```
