# venomhook — Claude 작업 가이드

이 파일은 Claude가 venomhook 리포에서 작업할 때 항상 참고할 짧은 메모다.

## 검증 워크플로 (Claude → Codex 핸드오프)

이 프로젝트는 Claude로 코드 수정·보고서 작성을 끝낸 뒤 Codex로 검증하는 흐름을 사용한다.
**Codex에 컨텍스트를 던지기 전에 반드시 `.claude/skills/codex-handoff` 스킬을 사용한다.**

스킬 전체 명세: `.claude/skills/codex-handoff/SKILL.md`

요약:

```bash
# 코드 변경 검증
python3 .claude/skills/codex-handoff/scripts/bundle.py \
  --ref HEAD~1 \
  --intent-file outputs/intent.md \
  --out outputs/codex-bundle.md

# 보고서/문서 사실관계 검증
python3 .claude/skills/codex-handoff/scripts/doc_verify.py \
  --doc <doc.md> \
  --out outputs/codex-doc-verify.md
```

intent 파일은 Claude 자신이 작성한다 (변경 의도 / 리스크 가설 / 검증 체크리스트).
사용자에게 다시 묻지 말 것 — 방금 본인이 한 작업이므로 본인이 가장 잘 안다.

## 산출물 위치

- 작업 결과 파일: `outputs/` (워크스페이스 임시 폴더)
- 영구 보관: 사용자가 명시적으로 지정한 위치만

## 도메인 맵

`.claude/skills/codex-handoff/references/venomhook-map.md` — 모듈 분류와 "변경 시 함께 봐야 할 곳"
휴리스틱이 있다. 영향 분석할 때 참고.
