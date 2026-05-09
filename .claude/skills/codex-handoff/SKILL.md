---
name: codex-handoff
description: |
  Claude로 venomhook 코드를 수정하거나 보고서를 작성한 뒤, Codex에게 검증을 맡기기 직전에 사용한다.
  Codex가 읽어야 할 최소 컨텍스트만 골라 단일 번들 파일로 패키징하여 토큰 사용량을 크게 줄이는 것이 목적이다.
  사용 트리거: "Codex로 검증", "Codex에 넘기기 전에", "검증 번들 만들어", "리뷰용 패키지", "이 변경 점검 좀",
  "Codex 핸드오프", "리포트 사실관계 확인", "보고서 검증", "이 보고서 Codex로 cross-check".
  코드 변경 검증과 보고서/문서 사실관계 검증 두 모드를 지원한다.
  주의: 사용자가 "Codex"를 명시하지 않더라도 venomhook 작업 직후 외부 LLM/리뷰어에 핸드오프하는 맥락이면
  본 스킬을 적극적으로 호출해야 한다 — 매번 전체 파일을 다시 보내는 비효율이 이 프로젝트의 큰 통증점이다.
---

# codex-handoff — Claude→Codex 검증 핸드오프 번들러

이 스킬은 venomhook 프로젝트 전용이다. Claude가 코드 수정·보고서 작성을 마친 뒤,
Codex(또는 외부 리뷰어 LLM)에게 검증을 맡기기 위해 다시 컨텍스트를 구성할 때 호출된다.

핵심 문제의식: venomhook의 `cli.py`는 1,200여 줄이고 `models.py`·`poc_generator.py`도 600줄 이상이다.
검증을 받을 때 매번 파일 전체를 보내면 Codex가 정작 봐야 할 변경 부위를 찾는 데 토큰이 낭비되고,
Claude가 어떤 의도로 무엇을 바꿨는지 맥락이 누락돼 재설명이 필요해진다.

본 스킬은 다음을 자동으로 한다.

- 변경된 코드만 함수/클래스 단위로 슬라이스 (Python AST 기반)
- `git diff`로 정확한 라인 변화를 함께 첨부
- import 그래프 1-hop으로 영향 받을 수 있는 인접 파일 식별 (코드 본문은 옵트인)
- Claude가 수행한 작업 의도, 리스크 가설, 검증 체크리스트를 구조화된 헤더로 첨부
- 단일 마크다운 번들로 패키징하여 Codex 입력에 그대로 붙여넣을 수 있게 한다

## 두 가지 모드

이 스킬은 두 모드를 지원하며, 사용자 발화의 의도에 따라 한쪽을 선택한다.

| 모드 | 트리거 발화 예시 | 진입점 |
|------|-----------------|--------|
| code (기본) | "이 변경 Codex로 검증", "PR 리뷰 받기 전에 번들 만들어" | `scripts/bundle.py` |
| doc | "이 보고서 사실관계 Codex로 cross-check", "audit 결과랑 README 일치하는지" | `scripts/doc_verify.py` |

모드 판단이 모호하면 사용자에게 한 번 물어본다. 둘 다 필요하면 두 번 호출한다.

## 모드 1: code 검증 번들

### 사용 흐름

1. 작업 의도 수집. 사용자가 "Codex로 검증해줘"라고만 말한 경우, **번들을 생성하기 전에**
   Claude가 직접 다음 세 가지를 1~3문장씩 정리한다 (사용자에게 다시 묻지 않는다 — Claude 자신이
   방금 수행한 작업이기 때문에 본인이 가장 잘 안다):

   - **변경 의도** (intent): 무엇을 왜 바꿨는가
   - **리스크 가설** (risk): 어디서 깨질 수 있다고 의심하는가, 어떤 부작용이 가능한가
   - **검증 포인트** (focus): Codex가 특히 확인해줬으면 하는 항목 (체크리스트)

   이 세 항목을 마크다운 한 파일로 작성해 `outputs/intent-<timestamp>.md`에 둔다.
   템플릿은 `references/prompt_templates.md`의 `intent-skeleton` 참조.

2. `scripts/bundle.py` 호출. 기본은 `HEAD`와 워킹 트리의 차이.

   ```bash
   python .claude/skills/codex-handoff/scripts/bundle.py \
     --intent-file outputs/intent-<timestamp>.md \
     --out outputs/codex-bundle-<timestamp>.md
   ```

   주요 플래그:

   - `--ref <git-ref>` : diff 기준 (기본 `HEAD`). PR 리뷰면 `origin/main` 등 베이스 브랜치 사용.
   - `--staged` : staged 변경만
   - `--files a.py,b.py` : git diff 무시하고 명시한 파일만 포함 (의존성 1-hop은 그대로 따라감)
   - `--include-related` : import 그래프 1-hop 본문까지 포함 (기본은 파일 경로만)
   - `--related-depth N` : 1-hop 이상 확장 (드물게만. N=2면 토큰이 다시 폭증)
   - `--no-funcs-only` : 변경된 파일을 함수 단위로 자르지 않고 전체 포함 (긴 파일에 비추천)
   - `--max-bytes <int>` : 번들 사이즈 상한. 초과 시 잘라내고 경고 헤더 삽입
   - `--intent-file <path>` : 위 1번에서 작성한 의도/리스크/검증 포인트 마크다운

3. 산출 마크다운을 `outputs/`에 저장하고 사용자에게 `computer://` 링크로 제시한다.

4. 산출물 마지막 줄에 "예상 입력 토큰: ~N" 추정치를 출력한다.

### 산출 번들 구조

`scripts/bundle.py`가 만드는 마크다운은 다음 섹션을 가진다. Codex가 빠르게 스캔해
"진짜로 봐야 할 것"을 찾도록 설계됐다.

```
# Codex Verification Bundle — venomhook
## 1. 작업 맥락 (Claude가 채움)
   1.1 변경 의도
   1.2 리스크 가설
   1.3 검증 포인트 체크리스트
## 2. 변경된 파일 (함수 단위 슬라이스)
   - src/venomhook/foo.py
     - changed: parse_manifest(), _ensure_abi()
     - context (unchanged but referenced): MANIFEST_RULES
## 3. Unified diff (라인 단위)
## 4. 영향 가능성 있는 인접 파일 (import 1-hop)
## 5. 사실 확인용 메타데이터 (현재 브랜치, HEAD sha, 모듈 경로)
## 6. Codex 검증 프롬프트 (그대로 복사해 사용)
```

`references/prompt_templates.md`의 `code-review` 템플릿이 6번 섹션 본문이 된다.

## 모드 2: doc 검증 번들

### 사용 흐름

이 모드는 venomhook이 다루는 두 종류의 문서를 위해 최적화돼 있다.

- 사용자가 작성한 외부 보고서/공유 문서 (모의 침투 결과 보고서를 마크다운으로 옮긴 것 등)
- venomhook이 생성한 산출물 (`audit_html_report.py`가 만든 HTML, README의 CLI 사용 예시 등)

`scripts/doc_verify.py`는 입력 문서에서 **검증 가능한 주장(verifiable claim)**을 추출하고,
각 주장의 출처라고 추정되는 코드/스펙 파일을 매핑한다.

추출 대상:

- 파일 경로 (`src/venomhook/...`, `lib/<abi>/*.so` 등)
- 함수/클래스명 (PascalCase, snake_case 함수 호출 패턴)
- CLI 명령 (`venomhook android-audit ...`)
- 룰 ID (`MANIFEST-001`~`MANIFEST-009` 등)
- 수치/카운트 ("9종", "RVA", 버전, hash 길이 등)
- CVE/CWE 번호

```bash
python .claude/skills/codex-handoff/scripts/doc_verify.py \
  --doc <보고서.md|README.md> \
  --out outputs/codex-doc-verify-<timestamp>.md
```

### 산출 번들 구조

```
# Codex Document Verification Bundle
## 1. 검증 대상 문서 (전체 또는 발췌)
## 2. 추출된 주장 목록
   주장 #1: "MANIFEST-001~009 9종 룰을 자동 감사한다"
     - 추정 출처: src/venomhook/manifest_audit.py
     - 코드 발췌 (해당 상수/함수)
   주장 #2: ...
## 3. 출처를 찾지 못한 주장 (사람이 판단해야 함)
## 4. Codex 검증 프롬프트 (`doc-verify` 템플릿)
```

## 세부 동작 원칙

### 함수 단위 슬라이스 (가장 중요)

- 변경된 라인이 함수/클래스/메서드 본문 안에 있으면 해당 정의 전체를 추출한다.
- 모듈 최상단 import, 상수, dataclass 정의는 항상 포함한다 (참조 해석에 필요).
- 변경되지 않은 다른 함수는 포함하지 않는다.
- 함수가 너무 길면(>300줄) 그대로 두되, 진단 헤더에 길이를 적어 둔다.
- Python 외 파일(`.md`, `.json`, `.toml`, `.yaml`, `.sh`, `.ps1`, `.js`)은 통째로 포함한다 — 자르기 어렵고 보통 짧다.

### import 그래프

- 1-hop이 기본. `from venomhook.X import Y` / `import venomhook.X` 형태만 추적한다.
- 외부 라이브러리(`frida`, `ghidra`, `lief` 등)는 무시한다.
- 1-hop 결과는 **파일 경로만** 보여주고 본문은 `--include-related` 플래그에서만 펼친다.

### 토큰 추정

- 정확한 tokenizer가 없을 가능성이 높으므로 `len(text)/4` 휴리스틱을 기본값으로 사용한다.
- `tiktoken`이 venv에 있으면 그것을 쓴다.
- 추정치는 ±20% 오차로 안내한다.

### 비밀 정보 차단

이 도구는 보안 컨설팅 결과물을 다룬다. 다음 패턴을 발견하면 **자동으로 ◼◼◼로 마스킹**하고
번들 헤더에 "REDACTED: N" 카운트를 적어 둔다.

- API 키 / 토큰처럼 보이는 긴 영숫자 리터럴 (`[A-Za-z0-9_\-]{32,}`)
- `password = "..."`, `api_key = "..."` 형태 할당
- `Authorization: Bearer ...` HTTP 헤더
- AWS access key 패턴 (`AKIA[0-9A-Z]{16}`)

마스킹은 보수적으로 동작한다. false positive 시 `--no-mask`로 비활성화 가능.

### gitignore 존중

- `.gitignore`에 들어 있는 경로는 절대 번들에 넣지 않는다 (특히 `sample/apk/`, `venv/`, `build/`).
- `.git/`, `__pycache__/`, `.pytest_cache/`도 항상 제외.

## 호출 시 점검할 것

- venv가 활성화돼 있어야 `tiktoken` 등 선택적 의존성을 발견할 수 있다. 없으면 graceful fallback.
- `git`이 PATH에 있어야 한다. 없으면 `--files`로만 동작.
- 출력 경로는 항상 `outputs/`(워크스페이스) 또는 사용자가 명시한 경로. 프로젝트 루트에 직접 쓰지 않는다.

## 응답 톤

산출물을 사용자에게 전달할 때는:

- 번들 파일을 `computer://` 링크로 한 줄에 보여준다
- 추정 토큰 수 1줄
- 마스킹된 항목 수 1줄 (있을 때만)
- "Codex에 넘길 때 [모델 이름]에 그대로 붙여넣으면 됩니다" 한 줄
- 그 외 장황한 설명은 피한다 — 사용자는 이미 무엇을 만들었는지 안다

## 참고 파일

- `scripts/bundle.py` — 코드 검증 번들 생성기 (메인 진입점)
- `scripts/doc_verify.py` — 문서 검증 번들 생성기
- `scripts/_common.py` — 공통 유틸리티 (AST 슬라이서, 토큰 추정, 마스킹)
- `references/prompt_templates.md` — Codex 검증용 프롬프트 템플릿 (`code-review`, `doc-verify`, `intent-skeleton`)
- `references/venomhook-map.md` — venomhook 모듈 분류 — 영향 분석 시 참고
