# codex-handoff

Claude로 venomhook 수정 → Codex 검증 워크플로 전용 핸드오프 번들러.

매번 cli.py(1,200줄)·models.py(660줄) 같은 큰 파일 전체를 Codex에 보내는 대신, 변경된 함수만
잘라 단일 마크다운 번들로 패키징한다. Claude의 작업 의도·리스크 가설·검증 체크리스트를 헤더에
박아 두므로 Codex는 "왜 이런 변경이 들어왔는지" 다시 물을 필요가 없다.

## 빠른 사용법

### 1) 코드 변경 검증 (가장 자주 쓰는 모드)

```bash
# (선택) 작업 의도 메모를 남기면 Codex 응답 품질이 크게 올라간다.
cat > outputs/intent.md <<'EOF'
### 변경 의도
- ...

### 리스크 가설
- ...

### 검증 포인트
- [ ] ...
EOF

python3 .claude/skills/codex-handoff/scripts/bundle.py \
  --ref HEAD~1 \
  --intent-file outputs/intent.md \
  --out outputs/codex-bundle.md
```

옵션 정리:

| 옵션 | 의미 |
|------|------|
| `--ref <ref>` | diff 기준 git ref (기본 `HEAD`). PR 리뷰면 `origin/main` 권장. |
| `--staged` | staged 변경만 비교 |
| `--files a.py,b.py` | git 무시하고 명시 파일만 |
| `--include-related` | import 1-hop 인접 파일 *본문*까지 포함 (기본은 경로만 표시) |
| `--related-depth N` | import 그래프 확장 깊이 (기본 1; 2 이상은 토큰 폭증 주의) |
| `--no-funcs-only` | 변경된 파일을 함수 단위로 자르지 않고 통째로 |
| `--max-bytes N` | 번들 본문 최대 바이트 (초과 시 잘라내고 경고 헤더 삽입) |
| `--no-mask` | 비밀 패턴 마스킹 끔 |

### 2) 보고서 사실관계 검증

```bash
python3 .claude/skills/codex-handoff/scripts/doc_verify.py \
  --doc <보고서.md|README.md|ARCHITECTURE.md> \
  --out outputs/codex-doc-verify.md
```

문서에서 검증 가능한 주장(파일 경로, 함수명, CLI 명령, MANIFEST 룰 ID, CVE 등)을 자동 추출해
각 주장의 추정 출처 코드를 함께 묶는다. Codex는 "출처를 봐 가며 사실인지 확인"만 하면 된다.

## 산출 번들 구조 (코드 모드)

```
1. 작업 맥락 (Claude가 채움)
2. 변경된 파일 (함수/클래스 단위 슬라이스)
3. Unified diff (라인 단위)
4. 영향 가능성 있는 인접 파일 (import 1-hop)
5. 메타데이터 (브랜치, HEAD sha)
6. Codex 검증 프롬프트 (그대로 복사 가능)
```

## 토큰 절감 효과 (실측)

최근 venomhook 커밋(`50c85af`) 기준 — `audit_html_report.py`, `poc_export.py`, `test_poc_export.py`
3개 파일 변경:

| 방식 | 크기 | 추정 토큰 |
|------|------|----------|
| 전체 파일 통째 전송 | 46KB | ~11,574 |
| 본 도구 번들 | 28KB | ~7,033 |
| **절감률** | | **~39%** |

함수 단위 슬라이스 + module-head 압축이 효과를 낸다. 변경 파일이 많고 클수록 절감률이 더 커진다.
실제 사용에서는 "Claude의 작업 맥락 재설명"을 매번 하지 않아도 되므로 추가로 ~1,000 토큰 절감된다.

## 비밀 정보 마스킹

기본으로 다음 패턴을 자동으로 `◼◼◼REDACTED◼◼◼`로 치환한다 (보수적 — false positive 최소화):

- AWS access key (`AKIA[A-Z0-9]{16}`)
- Bearer 토큰 (`Authorization: Bearer ...`)
- key=value 형태 비밀 (`api_key`, `secret`, `password`, `private_key` 등)
- GitHub PAT (`ghp_...`, `ghs_...`)
- Slack 토큰 (`xoxb-...` 등)
- 따옴표 안의 hex hash 40자 이상

함수명·식별자처럼 보이는 긴 영숫자는 마스킹하지 않는다 — 코드 검증을 망가뜨릴 수 있기 때문.
보고서에 진짜 토큰이 있는지는 사후 grep으로 확인하길 권장한다.

## 디렉터리

```
.claude/skills/codex-handoff/
├── README.md             ← 이 파일
├── SKILL.md              ← Claude가 이 스킬을 호출할 때 읽는 명세
├── scripts/
│   ├── bundle.py         ← 코드 검증 번들러
│   ├── doc_verify.py     ← 문서 검증 번들러
│   └── _common.py        ← 공통 유틸 (AST 슬라이서, 마스킹, 토큰 추정)
└── references/
    ├── prompt_templates.md
    └── venomhook-map.md  ← 도메인 모듈 분류 (변경 영향 분석 시 참고)
```

## 알려진 한계

- Python 외 언어(JS, Java, C/C++)는 함수 단위 슬라이스 미지원 — 통째로 포함된다.
- `git rename` 처리는 단순화돼 있다. 큰 리네임 + 수정이 섞이면 diff 청크가 분리될 수 있다.
- `tiktoken`이 없으면 `len/4` 휴리스틱이라 토큰 추정에 ±20% 오차가 있다. 정확히 보려면
  `pip install tiktoken` 권장.
- doc_verify는 정규식 기반이라 false positive가 있을 수 있다. "출처를 찾지 못한 주장" 섹션은
  사람이 한번 훑어보는 걸 권장.
