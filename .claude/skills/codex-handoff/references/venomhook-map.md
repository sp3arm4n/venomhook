# venomhook 모듈 분류 (영향 분석용)

이 파일은 codex-handoff가 변경의 영향 범위를 추정할 때 참고하는 도메인 맵이다.
번들 자동화에는 직접 쓰이지 않지만, Claude가 'intent skeleton'을 채울 때 이 분류를 참조하면
정확한 리스크 가설을 세우기 좋다.

## 도메인별 모듈

| 도메인 | 핵심 모듈 | 책임 |
|--------|----------|------|
| Static engine | `binary_meta.py`, `ghidra_runner.py` | Ghidra headless 결과 → StaticMeta |
| APK 처리 | `apk_decoder.py`, `apk_extractor.py`, `jadx_runner.py` | APK 풀기, Java 디컴파일, lib/* 추출 |
| JNI/Manifest | `jni_bridge.py`, `manifest_audit.py` | JNI symbol 매핑, Manifest 룰 9종 |
| HookSpec | `hookspec_builder.py`, `scoring.py` | 후킹 후보 점수 + HookSpec 생성 |
| 동적 분석 | `dynamic_pipeline.py`, `runtime_report.py` | Frida 스크립트 생성, 런타임 로그 처리 |
| 파이프라인 | `static_pipeline.py`, `android_pipeline.py`, `orchestrator.py` | 각 단계 오케스트레이션 |
| 산출물 | `report.py`, `audit_html_report.py`, `poc_export.py`, `poc_generator.py` | 보고서/PoC export |
| 캐시·diff | `analysis_cache.py`, `analysis_diff.py`, `store.py` | SQLite 캐시, 분석 diff |
| LLM 보조 | `llm/provider.py`, `llm/budget.py`, `llm/cache.py`, `llm/sig_recovery.py`, `llm/proto_inference.py`, `llm/flow_description.py`, `llm/runtime_summary.py`, `llm/tagging.py` | LLM 호출 추상화, 비용 budget, 프롬프트별 모듈 |
| 모델/CLI/설정 | `models.py`, `cli.py`, `config.py` | dataclass, CLI 진입점, 환경 |

## 변경 시 자주 함께 봐야 할 묶음

| 변경 위치 | 함께 봐야 할 곳 |
|-----------|-----------------|
| `cli.py` argparse 변경 | `README.md`, `ARCHITECTURE.md` 4·5장의 CLI 예시 |
| `manifest_audit.py` 룰 추가/수정 | `poc_generator.py`(룰별 PoC), `audit_html_report.py`(렌더), README 룰 카운트 |
| `models.py` dataclass 변경 | `store.py`, `analysis_cache.py`(직렬화), 산출물 모듈들 |
| `llm/*` 변경 | `llm/budget.py`(토큰 회계), `llm/cache.py`(캐시 키), 호출자 |
| `apk_decoder.py` / `apk_extractor.py` | `android_pipeline.py`(호출), sample/apk/ 테스트 입력 |
| `poc_generator.py` 변경 | `poc_export.py`(번들 export), 보고서 PoC 섹션, sample 출력 |

## 변경별 리스크 휴리스틱

- **CLI 변경**: argparse 옵션 명/디폴트 변경은 사용자 워크플로 회귀 위험. README/ARCHITECTURE.md 동기화 필요.
- **dataclass 필드 변경**: 캐시(`analysis_cache.py`)에 직렬화돼 있으므로 호환성 깨질 수 있음.
  마이그레이션 함수 또는 캐시 버전 bump 필요.
- **PoC 생성**: 명령 인젝션 위험. `subprocess`/`shell=True` 또는 사용자 입력의 셸 이스케이프 확인.
- **Frida 스크립트 생성**: 결과 JS는 그대로 디스크에 쓰여 실행되므로, hookspec 입력에서 파일 경로 traversal,
  큰따옴표 이스케이프 등 점검.
- **manifest 룰**: 룰 카운트가 README/`audit_html_report.py` 헤더와 일치하는지 확인.
