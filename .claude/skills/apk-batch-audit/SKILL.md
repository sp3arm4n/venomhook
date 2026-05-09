---
name: apk-batch-audit
description: |
  sample/apk/ (또는 임의 디렉터리) 하위의 모든 APK를 venomhook android-audit로 일괄 분석하고,
  SHA-256 기반 중복 제거, 캐시 공유, 룰 발화/심각도 분포 비교표 생성을 자동화한다.
  Phase 2 manifest 룰 / Phase 3 PoC 빌더에 변경이 있을 때 회귀 검증용으로 호출한다.
  사용 트리거: "모든 APK 다시 돌려", "샘플 APK 전체 회귀", "batch audit", "apk 전부 검사",
  "5개 APK 비교", "테스트 APK 일괄 실행", "전체 APK 회귀 비교".
  반복 가능한 단일 진입점이 없으면 매번 bash 루프를 즉흥적으로 짜게 되어 출력 형식이 흔들리고
  diff 비교가 어려워진다. 본 스킬이 그 통증을 제거한다.
---

# apk-batch-audit — APK 디렉터리 일괄 감사 + 비교

본 스킬은 venomhook 프로젝트 전용이다. manifest 파서, 룰 엔진, PoC 빌더,
HTML/번들 export 어느 한 곳이라도 변경했다면 호출해 회귀를 본다.

## 핵심 동작

1. 입력 디렉터리(default `sample/apk/`)의 모든 `.apk`를 SHA-256으로 해싱
2. 중복 해시는 한 번만 분석하고 alias 목록에 기록 (예: `KOReader.apk == OsmAnd~.apk == VCL.apk`)
3. 단일 cache-dir을 공유하여 두 번째 실행부터 0.x초로 replay
4. 각 APK별 `report.json` / `audit.json` / `pocs/` / `audit.html` 생성
5. 비교표 출력:
   - 헤더 라인: package, min/target SDK, 컴포넌트 수, 네이티브 .so 수, 경고 유무
   - 룰 발화 매트릭스: 행=APK, 열=MANIFEST-001~009 (개수)
   - 심각도 분포: critical/high/medium/low/info 누적
   - 변동 검출 (옵트인): 이전 실행 결과(`prev.json`)와 비교해 신규/소멸 발화 표시

## 출력 위치

기본은 워크스페이스 외부 임시 경로 `out_audit_runs/`이며 `.gitignore`로 차단되어 있다.
`--out-dir <path>`로 override 가능. 영구 보관이 필요한 경우만 사용자가 명시적으로 지정한다.

## 사용

```bash
# 기본 — sample/apk/ 전부, out_audit_runs/에 출력
python3 .claude/skills/apk-batch-audit/scripts/batch_audit.py

# 결과만 출력 (캐시 hit 강제, 재분석 안함)
python3 .claude/skills/apk-batch-audit/scripts/batch_audit.py --replay-only

# 임의 디렉터리 + JSON 비교 결과
python3 .claude/skills/apk-batch-audit/scripts/batch_audit.py \
  --apk-dir /path/to/apks \
  --json-out outputs/batch_summary.json

# 이전 결과와 비교 (회귀 게이트)
python3 .claude/skills/apk-batch-audit/scripts/batch_audit.py \
  --baseline outputs/batch_summary.json
```

## 호출 시점 가이드

- ✅ manifest 룰 추가/수정 직후 (e.g. NSC XML 파싱, 데이터 스킴 룰)
- ✅ PoC 빌더 변경 직후 (PoC 카운트 변동 확인)
- ✅ apk_decoder.py 파서 손볼 때 (이번 SDK 폴백 같은 케이스)
- ✅ Phase 6/7/8 각 Unit 완료 시 회귀
- ❌ 단순 텍스트/주석 변경 — 호출 가치 없음

## 인접 자원

- 런타임 의존: `venomhook` CLI (이 리포의 venv에서 `pip install -e .`로 설치된 상태 가정)
- 외부 도구: `apktool`, `jadx` (선택)
- 입력 APK: `.gitignore`로 차단된 `sample/apk/` 또는 사용자 지정 경로
